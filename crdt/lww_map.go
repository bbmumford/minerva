package crdt

import (
	"encoding/json"
	"sync"
	"time"
)

// lwwMapEntry is a single entry in an LWW map, holding a value, its HLC
// timestamp, the authoring node, and a tombstone flag for deletions.
type lwwMapEntry struct {
	Value     []byte `json:"value,omitempty"`
	HLC       uint64 `json:"hlc"`
	NodeID    string `json:"nodeId"`
	Tombstone bool   `json:"tombstone,omitempty"`
}

// lwwMapDelta is the wire format for delta synchronization.
type lwwMapDelta struct {
	Entries map[string]*lwwMapEntry `json:"entries"`
}

// LWWMap is a last-write-wins map. Each key is an independent LWW register.
// Supports per-key granularity: two nodes can update different keys without conflict.
type LWWMap struct {
	mu      sync.RWMutex
	name    string
	entries map[string]*lwwMapEntry
	nodeID  string
	hlc     *HLC
}

// NewLWWMap creates a new LWW map with the given name.
func NewLWWMap(name string, nodeID string, hlc *HLC) *LWWMap {
	return &LWWMap{
		name:    name,
		entries: make(map[string]*lwwMapEntry),
		nodeID:  nodeID,
		hlc:     hlc,
	}
}

// Type returns TypeLWWMap.
func (m *LWWMap) Type() CRDTType { return TypeLWWMap }

// Name returns the collection name.
func (m *LWWMap) Name() string { return m.name }

// Set stores a value for the given key, advancing the HLC.
func (m *LWWMap) Set(key string, value []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ts := m.hlc.Now()
	m.entries[key] = &lwwMapEntry{
		Value:  value,
		HLC:    ts,
		NodeID: m.nodeID,
	}
}

// Get returns the value for the given key and whether it exists (non-tombstoned).
func (m *LWWMap) Get(key string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.entries[key]
	if !ok || entry.Tombstone {
		return nil, false
	}
	return entry.Value, true
}

// Delete marks the key as tombstoned, advancing the HLC.
func (m *LWWMap) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ts := m.hlc.Now()
	m.entries[key] = &lwwMapEntry{
		HLC:       ts,
		NodeID:    m.nodeID,
		Tombstone: true,
	}
}

// All returns all non-tombstoned key-value pairs.
func (m *LWWMap) All() map[string][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]byte, len(m.entries))
	for k, e := range m.entries {
		if !e.Tombstone {
			result[k] = e.Value
		}
	}
	return result
}

// MarshalDelta returns a JSON-encoded delta containing all entries with HLC > since.
func (m *LWWMap) MarshalDelta(since uint64) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	delta := lwwMapDelta{
		Entries: make(map[string]*lwwMapEntry),
	}
	for k, e := range m.entries {
		if e.HLC > since {
			delta.Entries[k] = e
		}
	}
	return json.Marshal(delta)
}

// ApplyDelta merges a JSON-encoded remote delta into local state.
// Each key is merged independently: higher HLC wins, ties broken by NodeID.
func (m *LWWMap) ApplyDelta(data []byte) error {
	var delta lwwMapDelta
	if err := json.Unmarshal(data, &delta); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for k, remote := range delta.Entries {
		// Update local HLC to maintain causal ordering.
		if _, err := m.hlc.Update(remote.HLC); err != nil {
			continue // skip entries with excessive clock drift
		}

		local, exists := m.entries[k]
		if !exists {
			m.entries[k] = remote
			continue
		}
		// LWW merge: higher HLC wins, then lexicographic NodeID tiebreak.
		if remote.HLC > local.HLC {
			m.entries[k] = remote
		} else if remote.HLC == local.HLC && remote.NodeID > local.NodeID {
			m.entries[k] = remote
		}
	}
	return nil
}

// Entries returns the raw entries map for garbage collection.
// The caller must not modify the returned map without holding appropriate locks.
func (m *LWWMap) Entries() map[string]*lwwMapEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a shallow copy for safety.
	result := make(map[string]*lwwMapEntry, len(m.entries))
	for k, v := range m.entries {
		result[k] = v
	}
	return result
}

// RemoveTombstone removes a specific tombstoned entry during garbage collection.
func (m *LWWMap) RemoveTombstone(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if e, ok := m.entries[key]; ok && e.Tombstone {
		delete(m.entries, key)
	}
}

// SweepTombstones removes all tombstoned entries older than the given duration
// and returns the number removed. Implements GCTarget.
func (m *LWWMap) SweepTombstones(olderThan time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoffWall := uint64(time.Now().UnixMilli()) - uint64(olderThan.Milliseconds())
	cutoff := cutoffWall << 16

	removed := 0
	for key, entry := range m.entries {
		if entry.Tombstone && entry.HLC < cutoff {
			delete(m.entries, key)
			removed++
		}
	}
	return removed
}
