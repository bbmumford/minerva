package crdt

import (
	"encoding/json"
	"sync"
)

// lwwRegisterDelta is the wire format for LWW-Register delta synchronization.
type lwwRegisterDelta struct {
	Value  []byte `json:"value,omitempty"`
	HLC    uint64 `json:"hlc"`
	NodeID string `json:"nodeId"`
}

// LWWRegister is a last-write-wins register. It stores a single value
// with an associated HLC timestamp. Conflict resolution: highest HLC
// timestamp wins. Ties are broken by NodeID (lexicographic comparison).
type LWWRegister struct {
	mu     sync.RWMutex
	name   string
	value  []byte
	hlc    uint64
	nodeID string
}

// NewLWWRegister creates a new LWW register for the given node.
func NewLWWRegister(name string, nodeID string) *LWWRegister {
	return &LWWRegister{
		name:   name,
		nodeID: nodeID,
	}
}

// Type returns TypeLWWRegister.
func (r *LWWRegister) Type() CRDTType { return TypeLWWRegister }

// Name returns the collection name.
func (r *LWWRegister) Name() string { return r.name }

// MarshalDelta returns a JSON-encoded delta if the register's HLC > since.
// Returns an empty JSON object if there is no newer state.
func (r *LWWRegister) MarshalDelta(since uint64) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.hlc <= since {
		return json.Marshal(lwwRegisterDelta{})
	}
	return json.Marshal(lwwRegisterDelta{
		Value:  r.value,
		HLC:    r.hlc,
		NodeID: r.nodeID,
	})
}

// ApplyDelta merges a JSON-encoded remote delta into this register.
func (r *LWWRegister) ApplyDelta(data []byte) error {
	var delta lwwRegisterDelta
	if err := json.Unmarshal(data, &delta); err != nil {
		return err
	}
	if delta.HLC == 0 {
		return nil // empty delta, nothing to apply
	}
	r.Merge(delta.Value, delta.HLC, delta.NodeID)
	return nil
}

// Set updates the register value with the given HLC timestamp.
func (r *LWWRegister) Set(value []byte, hlc uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.value = value
	r.hlc = hlc
}

// Get returns the current value and its HLC timestamp.
func (r *LWWRegister) Get() ([]byte, uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.value, r.hlc
}

// Merge attempts to merge a remote value into this register.
// Returns true if the remote value wins (was applied), false if local wins.
//
// Merge rules:
//  1. Higher HLC wins.
//  2. If HLC is equal, higher NodeID (lexicographic) wins.
func (r *LWWRegister) Merge(remoteValue []byte, remoteHLC uint64, remoteNodeID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if remoteHLC > r.hlc {
		r.value = remoteValue
		r.hlc = remoteHLC
		return true
	}
	if remoteHLC == r.hlc && remoteNodeID > r.nodeID {
		r.value = remoteValue
		r.hlc = remoteHLC
		return true
	}
	return false
}
