package crdt

import (
	"errors"
	"time"

	"github.com/bbmumford/swarm"
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
//
// The stamps come from a swarm.HLC, whose packed format is this one, so a
// stamp already stored (an LWW register or map entry, a sequence operation,
// a delta watermark) reads back with the same wall and counter and orders
// against new stamps unchanged. A counter that is full within one
// millisecond carries into the next millisecond.
type HLC struct {
	clock  *swarm.HLC
	nodeID string
}

// NewHLC creates a new Hybrid Logical Clock for the given node.
func NewHLC(nodeID string) *HLC {
	return &HLC{
		clock:  swarm.NewHLC(),
		nodeID: nodeID,
	}
}

// Now returns the next HLC timestamp as a packed uint64: wall<<16 | logical.
// The physical clock is sampled; if it has not advanced since the last call,
// the logical counter is incremented instead.
func (h *HLC) Now() uint64 {
	return h.clock.Now()
}

// Update merges a remote HLC timestamp into the local clock and returns
// the new local packed timestamp. This ensures causal ordering: the
// returned timestamp is strictly greater than both the previous local
// timestamp and the remote timestamp.
//
// Returns ErrClockDrift if the remote wall time is too far in the future,
// and then leaves the clock as it was. MaxDrift is inside swarm's own
// forward-skew budget (10 minutes), so every remote Update accepts is folded
// into the clock before the new stamp is taken.
func (h *HLC) Update(remote uint64) (uint64, error) {
	remoteWall, _ := swarm.Decompose(remote)
	maxWall := uint64(time.Now().UnixMilli()) + uint64(MaxDrift.Milliseconds())
	if remoteWall > maxWall {
		return 0, ErrClockDrift
	}
	h.clock.Observe(remote)
	return h.clock.Now(), nil
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
