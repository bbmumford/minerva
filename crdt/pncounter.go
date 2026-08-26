package crdt

import (
	"encoding/json"
	"sync"
)

// pnCounterDelta is the wire format for PN-Counter delta synchronization.
type pnCounterDelta struct {
	P map[string]uint64 `json:"p"` // positive counts per nodeID
	N map[string]uint64 `json:"n"` // negative counts per nodeID
}

// PNCounter supports both increment and decrement via two internal G-Counters.
// Value = sum(P) - sum(N).
type PNCounter struct {
	mu   sync.RWMutex
	name string
	pos  *GCounter
	neg  *GCounter
}

// NewPNCounter creates a new positive-negative counter for the given node.
func NewPNCounter(name string, nodeID string) *PNCounter {
	return &PNCounter{
		name: name,
		pos:  NewGCounter(name+"/pos", nodeID),
		neg:  NewGCounter(name+"/neg", nodeID),
	}
}

// Type returns TypePNCounter.
func (c *PNCounter) Type() CRDTType { return TypePNCounter }

// Name returns the collection name.
func (c *PNCounter) Name() string { return c.name }

// Increment adds n to the positive counter.
func (c *PNCounter) Increment(n uint64) {
	c.pos.Increment(n)
}

// Decrement adds n to the negative counter.
func (c *PNCounter) Decrement(n uint64) {
	c.neg.Increment(n)
}

// Value returns the current counter value: sum(pos) - sum(neg).
func (c *PNCounter) Value() int64 {
	return int64(c.pos.Value()) - int64(c.neg.Value())
}

// MarshalDelta returns a JSON-encoded delta containing both P and N counts
// for this node.
func (c *PNCounter) MarshalDelta(since uint64) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	delta := pnCounterDelta{
		P: c.pos.Counts(),
		N: c.neg.Counts(),
	}
	return json.Marshal(delta)
}

// ApplyDelta merges a JSON-encoded remote delta into local state.
// For each nodeID, local counts are set to max(local, remote) for both P and N.
func (c *PNCounter) ApplyDelta(data []byte) error {
	var delta pnCounterDelta
	if err := json.Unmarshal(data, &delta); err != nil {
		return err
	}

	// Marshal sub-deltas and apply to internal G-Counters.
	if len(delta.P) > 0 {
		pData, err := json.Marshal(gCounterDelta{Counts: delta.P})
		if err != nil {
			return err
		}
		if err := c.pos.ApplyDelta(pData); err != nil {
			return err
		}
	}
	if len(delta.N) > 0 {
		nData, err := json.Marshal(gCounterDelta{Counts: delta.N})
		if err != nil {
			return err
		}
		if err := c.neg.ApplyDelta(nData); err != nil {
			return err
		}
	}
	return nil
}
