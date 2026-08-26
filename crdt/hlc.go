package crdt

import (
	"errors"
	"sync"
	"time"
)

// MaxDrift is the maximum allowed clock drift between nodes (60 seconds).
const MaxDrift = 60 * time.Second

// ErrClockDrift is returned when a remote timestamp exceeds MaxDrift.
var ErrClockDrift = errors.New("crdt: remote clock drift exceeds maximum")

// HLC is a Hybrid Logical Clock that combines physical wall-clock time
// with a logical counter and a node identifier to produce monotonically
// increasing, causally ordered timestamps without clock synchronization.
//
// Packed format: upper 48 bits = wall time (unix millis), lower 16 bits = logical counter.
// NodeID is used as a deterministic tiebreaker when packed values are equal.
type HLC struct {
	mu      sync.Mutex
	wall    uint64 // physical wall clock (unix millis)
	logical uint16 // logical counter
	nodeID  string // tiebreaker for total ordering
}

// NewHLC creates a new Hybrid Logical Clock for the given node.
func NewHLC(nodeID string) *HLC {
	return &HLC{
		wall:   uint64(time.Now().UnixMilli()),
		nodeID: nodeID,
	}
}

// Now returns the next HLC timestamp as a packed uint64: wall<<16 | logical.
// The physical clock is sampled; if it has not advanced since the last call,
// the logical counter is incremented instead.
func (h *HLC) Now() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()

	phys := uint64(time.Now().UnixMilli())
	if phys > h.wall {
		h.wall = phys
		h.logical = 0
	} else {
		h.logical++
	}
	return h.pack()
}

// Update merges a remote HLC timestamp into the local clock and returns
// the new local packed timestamp. This ensures causal ordering: the
// returned timestamp is strictly greater than both the previous local
// timestamp and the remote timestamp.
//
// Returns ErrClockDrift if the remote wall time is too far in the future.
func (h *HLC) Update(remote uint64) (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	remoteWall := remote >> 16
	remoteLogical := uint16(remote & 0xFFFF)

	phys := uint64(time.Now().UnixMilli())

	// Drift check: reject if remote wall is more than MaxDrift ahead of physical clock.
	maxWall := phys + uint64(MaxDrift.Milliseconds())
	if remoteWall > maxWall {
		return 0, ErrClockDrift
	}

	if phys > h.wall && phys > remoteWall {
		// Physical clock advanced past both local and remote.
		h.wall = phys
		h.logical = 0
	} else if h.wall == remoteWall {
		// Local and remote wall times are equal; advance logical.
		if remoteLogical > h.logical {
			h.logical = remoteLogical + 1
		} else {
			h.logical++
		}
	} else if remoteWall > h.wall {
		// Remote wall is ahead; adopt it and advance logical.
		h.wall = remoteWall
		h.logical = remoteLogical + 1
	} else {
		// Local wall is ahead; just advance local logical.
		h.logical++
	}

	return h.pack(), nil
}

// Compare returns -1 if a < b, 0 if a == b, 1 if a > b.
// When packed values are equal, the caller should use NodeID for tiebreaking.
func (h *HLC) Compare(a, b uint64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// NodeID returns the node identifier for this clock.
func (h *HLC) NodeID() string {
	return h.nodeID
}

// pack returns the current state as wall<<16 | logical.
func (h *HLC) pack() uint64 {
	return (h.wall << 16) | uint64(h.logical)
}
