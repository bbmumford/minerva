package persistence

import (
	"github.com/bbmumford/minerva/crdt"
	"github.com/bbmumford/minerva/identity"
)

// Store is the persistence interface shared by all backends (memory, file, IndexedDB).
type Store interface {
	SaveKeypair(keypair *identity.Keypair, passphrase []byte) error
	LoadKeypair(passphrase []byte) (*identity.Keypair, error)
	HasKeypair() (bool, error)

	SaveCollection(name string, crdtType crdt.CRDTType, entries map[string][]byte, tombstones map[string]uint64) error
	LoadCollection(name string) (crdtType crdt.CRDTType, entries map[string][]byte, tombstones map[string]uint64, err error)
	ListCollections() ([]string, error)

	SavePeer(peer PeerRecord) error
	LoadPeers() ([]PeerRecord, error)
	DeletePeer(peerID []byte) error

	SaveHLC(hlc uint64) error
	LoadHLC() (uint64, error)

	SaveWatermark(peerID []byte, hlc uint64) error
	LoadWatermarks() (map[string]uint64, error)

	Close() error
}

// PeerRecord holds persisted state about a known peer.
type PeerRecord struct {
	PeerID     []byte
	Pubkey     []byte
	Petname    string
	Addresses  []string
	LastSeen   int64
	TrustScore float64
}
