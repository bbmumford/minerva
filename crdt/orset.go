package crdt

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// orsetTag represents a single add-tag in the OR-Set.
type orsetTag struct {
	TagID  string `json:"tagId"`
	HLC    uint64 `json:"hlc"`
	NodeID string `json:"nodeId"`
}

// orsetDeltaOp is a single operation in an OR-Set delta.
type orsetDeltaOp struct {
	Value      string   `json:"value"`
	IsRemove   bool     `json:"isRemove,omitempty"`
	AddTag     orsetTag `json:"addTag,omitempty"`
	RemoveTags []string `json:"removeTags,omitempty"` // tagIDs to remove
	HLC        uint64   `json:"hlc"`
}

// orsetDelta is the wire format for OR-Set delta synchronization.
type orsetDelta struct {
	Ops []orsetDeltaOp `json:"ops"`
}

// ORSet is an observed-remove set. Each Add() generates a globally unique
// add-tag. Remove() targets specific add-tags. An element is present if it
// has at least one live (non-removed) add-tag. "Add wins" over concurrent
// "remove" for different tags.
type ORSet struct {
	mu       sync.RWMutex
	name     string
	elements map[string]map[string]orsetTag // value -> {tagID -> tag}
	removed  map[string]uint64             // tombstoned tagIDs -> HLC when removed
	nodeID   string
	hlc      *HLC
	tagSeq   atomic.Uint64 // monotonic counter for unique tag generation
}

// NewORSet creates a new OR-Set with the given name.
func NewORSet(name string, nodeID string, hlc *HLC) *ORSet {
	return &ORSet{
		name:     name,
		elements: make(map[string]map[string]orsetTag),
		removed:  make(map[string]uint64),
		nodeID:   nodeID,
		hlc:      hlc,
	}
}

// Type returns TypeORSet.
func (s *ORSet) Type() CRDTType { return TypeORSet }

// Name returns the collection name.
func (s *ORSet) Name() string { return s.name }

// Add adds a value to the set, generating a globally unique add-tag.
func (s *ORSet) Add(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := s.hlc.Now()
	seq := s.tagSeq.Add(1)
	tagID := fmt.Sprintf("%s:%d:%d", s.nodeID, ts, seq)

	tag := orsetTag{
		TagID:  tagID,
		HLC:    ts,
		NodeID: s.nodeID,
	}

	if s.elements[value] == nil {
		s.elements[value] = make(map[string]orsetTag)
	}
	s.elements[value][tagID] = tag
}

// Remove removes all add-tags for the given value from this node's perspective.
// The tags are moved to the tombstone set.
func (s *ORSet) Remove(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tags, ok := s.elements[value]
	if !ok {
		return
	}

	ts := s.hlc.Now()
	for tagID := range tags {
		s.removed[tagID] = ts
	}
	delete(s.elements, value)
}

// Contains returns true if the value has at least one live add-tag.
func (s *ORSet) Contains(value string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tags, ok := s.elements[value]
	return ok && len(tags) > 0
}

// Elements returns all values currently in the set (sorted for determinism).
func (s *ORSet) Elements() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]string, 0, len(s.elements))
	for val, tags := range s.elements {
		if len(tags) > 0 {
			result = append(result, val)
		}
	}
	sort.Strings(result)
	return result
}

// MarshalDelta returns a JSON-encoded delta containing all operations with HLC > since.
func (s *ORSet) MarshalDelta(since uint64) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ops []orsetDeltaOp

	// Emit add operations.
	for value, tags := range s.elements {
		for _, tag := range tags {
			if tag.HLC > since {
				ops = append(ops, orsetDeltaOp{
					Value:  value,
					AddTag: tag,
					HLC:    tag.HLC,
				})
			}
		}
	}

	// Emit remove operations.
	for tagID, hlc := range s.removed {
		if hlc > since {
			ops = append(ops, orsetDeltaOp{
				IsRemove:   true,
				RemoveTags: []string{tagID},
				HLC:        hlc,
			})
		}
	}

	delta := orsetDelta{Ops: ops}
	return json.Marshal(delta)
}

// ApplyDelta merges a JSON-encoded remote delta into local state.
func (s *ORSet) ApplyDelta(data []byte) error {
	var delta orsetDelta
	if err := json.Unmarshal(data, &delta); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, op := range delta.Ops {
		// Update local HLC.
		if _, err := s.hlc.Update(op.HLC); err != nil {
			continue // skip ops with excessive clock drift
		}

		if op.IsRemove {
			// Remove specific tags.
			for _, tagID := range op.RemoveTags {
				s.removed[tagID] = op.HLC
				// Remove the tag from all elements.
				for value, tags := range s.elements {
					delete(tags, tagID)
					if len(tags) == 0 {
						delete(s.elements, value)
					}
				}
			}
		} else {
			// Add operation: add the tag if not already removed.
			if _, tombstoned := s.removed[op.AddTag.TagID]; tombstoned {
				continue // tag was already removed
			}
			if s.elements[op.Value] == nil {
				s.elements[op.Value] = make(map[string]orsetTag)
			}
			s.elements[op.Value][op.AddTag.TagID] = op.AddTag
		}
	}
	return nil
}

// RemovedTags returns the tombstone map for garbage collection.
func (s *ORSet) RemovedTags() map[string]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]uint64, len(s.removed))
	for k, v := range s.removed {
		result[k] = v
	}
	return result
}

// PurgeTombstone removes a specific tombstoned tag during garbage collection.
func (s *ORSet) PurgeTombstone(tagID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.removed, tagID)
}

// SweepTombstones removes all tombstoned tags older than the given duration
// and returns the number removed. Implements GCTarget.
func (s *ORSet) SweepTombstones(olderThan time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoffWall := uint64(time.Now().UnixMilli()) - uint64(olderThan.Milliseconds())
	cutoff := cutoffWall << 16

	removed := 0
	for tagID, hlc := range s.removed {
		if hlc < cutoff {
			delete(s.removed, tagID)
			removed++
		}
	}
	return removed
}
