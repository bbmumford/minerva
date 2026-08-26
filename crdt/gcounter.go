package crdt

import (
	"encoding/json"
	"sync"
)

// gCounterDelta is the wire format for G-Counter delta synchronization.
type gCounterDelta struct {
	Counts map[string]uint64 `json:"counts"`
}

// GCounter is a grow-only counter. Each node has its own monotonically
// increasing count. The global value is the sum of all per-node counts.
type GCounter struct {
	mu     sync.RWMutex
	name   string
	counts map[string]uint64 // nodeID -> count
	nodeID string
}

// NewGCounter creates a new grow-only counter for the given node.
func NewGCounter(name string, nodeID string) *GCounter {
	return &GCounter{
		name:   name,
		counts: make(map[string]uint64),
		nodeID: nodeID,
	}
}

// Type returns TypeGCounter.
func (c *GCounter) Type() CRDTType { return TypeGCounter }

// Name returns the collection name.
func (c *GCounter) Name() string { return c.name }

// Increment adds n to this node's counter.
func (c *GCounter) Increment(n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.counts[c.nodeID] += n
}

// Value returns the sum of all per-node counts.
func (c *GCounter) Value() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var sum uint64
	for _, v := range c.counts {
		sum += v
	}
	return sum
}

// MarshalDelta returns a JSON-encoded delta containing this node's current count.
// The since parameter is ignored for counters (always send current state).
func (c *GCounter) MarshalDelta(_ uint64) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	delta := gCounterDelta{
		Counts: map[string]uint64{
			c.nodeID: c.counts[c.nodeID],
		},
	}
	return json.Marshal(delta)
}

// ApplyDelta merges a JSON-encoded remote delta into local state.
// For each nodeID, the local count is set to max(local, remote).
func (c *GCounter) ApplyDelta(data []byte) error {
	var delta gCounterDelta
	if err := json.Unmarshal(data, &delta); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for nodeID, count := range delta.Counts {
		if count > c.counts[nodeID] {
			c.counts[nodeID] = count
		}
	}
	return nil
}

// Counts returns a copy of the per-node counts map.
func (c *GCounter) Counts() map[string]uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]uint64, len(c.counts))
	for k, v := range c.counts {
		result[k] = v
	}
	return result
}
