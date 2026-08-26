package crdt

// CRDTType identifies the kind of CRDT collection.
type CRDTType int

const (
	TypeLWWRegister CRDTType = iota
	TypeLWWMap
	TypeORSet
	TypeGCounter
	TypePNCounter
)

// Delta represents a single state change to be gossiped.
type Delta struct {
	Type      CRDTType `json:"type"`
	Key       string   `json:"key"`
	Value     []byte   `json:"value,omitempty"`
	HLC       uint64   `json:"hlc"`
	NodeID    string   `json:"nodeId"`
	Tombstone bool     `json:"tombstone,omitempty"`
}

// Collection is the interface all CRDT types implement.
type Collection interface {
	Type() CRDTType
	Name() string
	// MarshalDelta returns the delta since the given HLC.
	MarshalDelta(since uint64) ([]byte, error)
	// ApplyDelta merges a remote delta into local state.
	ApplyDelta(data []byte) error
}

// Compile-time interface checks.
var (
	_ Collection = (*LWWRegister)(nil)
	_ Collection = (*LWWMap)(nil)
	_ Collection = (*ORSet)(nil)
	_ Collection = (*GCounter)(nil)
	_ Collection = (*PNCounter)(nil)
)
