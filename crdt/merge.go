package crdt

import (
	"encoding/json"
	"fmt"
	"sync"

	ledger "github.com/bbmumford/ledger"
)

// MergeRegistry provides internal merge dispatch for Minerva CRDTs,
// independent of the Ledger layer. Each CRDTType can register a merge
// function that operates on raw byte deltas.
type MergeRegistry struct {
	mu    sync.RWMutex
	funcs map[CRDTType]func(existing, incoming []byte) ([]byte, error)
}

// NewMergeRegistry creates an empty merge registry.
func NewMergeRegistry() *MergeRegistry {
	return &MergeRegistry{
		funcs: make(map[CRDTType]func(existing, incoming []byte) ([]byte, error)),
	}
}

// Register adds a merge function for the given CRDT type.
func (r *MergeRegistry) Register(t CRDTType, fn func(existing, incoming []byte) ([]byte, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.funcs[t] = fn
}

// Merge dispatches to the registered merge function for the given CRDT type.
func (r *MergeRegistry) Merge(t CRDTType, existing, incoming []byte) ([]byte, error) {
	r.mu.RLock()
	fn, ok := r.funcs[t]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("crdt: no merge function registered for type %d", t)
	}
	return fn(existing, incoming)
}

// crdtBody is the CRDT metadata embedded in a ledger record's Body.
type crdtBody struct {
	CRDTType  CRDTType        `json:"crdtType"`
	Key       string          `json:"key"`
	Value     json.RawMessage `json:"value,omitempty"`
	HLC       uint64          `json:"hlc"`
	NodeID    string          `json:"nodeId"`
	Tombstone bool            `json:"tombstone,omitempty"`
}

// LWWMapMerge implements ledger.MergeFunc for LWW-Map and LWW-Register records.
// The record with the higher HLC wins. Ties are broken by NodeID (lexicographic).
func LWWMapMerge(existing, incoming ledger.Record) (ledger.Record, error) {
	var existBody, incBody crdtBody
	if err := json.Unmarshal(existing.Body, &existBody); err != nil {
		return incoming, nil // can't parse existing; accept incoming
	}
	if err := json.Unmarshal(incoming.Body, &incBody); err != nil {
		return existing, fmt.Errorf("crdt: cannot unmarshal incoming body: %w", err)
	}

	if incBody.HLC > existBody.HLC {
		return incoming, nil
	}
	if incBody.HLC == existBody.HLC && incBody.NodeID > existBody.NodeID {
		return incoming, nil
	}
	return existing, nil
}

// ORSetMerge implements ledger.MergeFunc for OR-Set records.
// OR-Set deltas are additive: the merge concatenates add-tag operations
// and applies remove-tag operations. Since ledger records carry the full
// delta payload, the incoming record always replaces the existing one
// (the CRDT layer handles actual merge via ApplyDelta).
func ORSetMerge(existing, incoming ledger.Record) (ledger.Record, error) {
	// OR-Set records in the ledger carry delta payloads.
	// The CRDT layer's ApplyDelta handles the actual set merge.
	// At the ledger level, accept the incoming record if it has a newer HLC.
	var existBody, incBody crdtBody
	if err := json.Unmarshal(existing.Body, &existBody); err != nil {
		return incoming, nil
	}
	if err := json.Unmarshal(incoming.Body, &incBody); err != nil {
		return existing, fmt.Errorf("crdt: cannot unmarshal incoming body: %w", err)
	}

	if incBody.HLC >= existBody.HLC {
		return incoming, nil
	}
	return existing, nil
}

// CounterMerge implements ledger.MergeFunc for G-Counter and PN-Counter records.
// Counter merges take the max of each node's count. Since the ledger record
// carries the full counter state, we decode both, merge, and return the result.
func CounterMerge(existing, incoming ledger.Record) (ledger.Record, error) {
	var existCounts, incCounts map[string]uint64
	if err := json.Unmarshal(existing.Body, &existCounts); err != nil {
		return incoming, nil
	}
	if err := json.Unmarshal(incoming.Body, &incCounts); err != nil {
		return existing, fmt.Errorf("crdt: cannot unmarshal incoming counter: %w", err)
	}

	// Merge: take max per nodeID.
	merged := make(map[string]uint64, len(existCounts))
	for k, v := range existCounts {
		merged[k] = v
	}
	for k, v := range incCounts {
		if v > merged[k] {
			merged[k] = v
		}
	}

	body, err := json.Marshal(merged)
	if err != nil {
		return existing, fmt.Errorf("crdt: cannot marshal merged counter: %w", err)
	}

	result := incoming
	result.Body = body
	return result, nil
}
