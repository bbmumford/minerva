package memory

import (
	"encoding/hex"
	"errors"
	"sort"
	"sync"

	"github.com/bbmumford/minerva/crdt"
	"github.com/bbmumford/minerva/identity"
	"github.com/bbmumford/minerva/persistence"
)

// Store is an in-memory persistence.Store for testing.
type Store struct {
	mu sync.RWMutex

	keypairData []byte // encrypted keypair blob
	hlc         uint64

	collections map[string]*collectionRecord
	peers       map[string]persistence.PeerRecord // hex(peerID) -> record
	watermarks  map[string]uint64                 // hex(peerID) -> hlc

	closed bool
}

type collectionRecord struct {
	crdtType   crdt.CRDTType
	entries    map[string][]byte
	tombstones map[string]uint64
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		collections: make(map[string]*collectionRecord),
		peers:       make(map[string]persistence.PeerRecord),
		watermarks:  make(map[string]uint64),
	}
}

var errClosed = errors.New("memory store: closed")

func (s *Store) SaveKeypair(keypair *identity.Keypair, passphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}

	encrypted, err := identity.EncryptKeypair(keypair, string(passphrase))
	if err != nil {
		return err
	}
	s.keypairData = encrypted
	return nil
}

func (s *Store) LoadKeypair(passphrase []byte) (*identity.Keypair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errClosed
	}
	if s.keypairData == nil {
		return nil, errors.New("memory store: no keypair saved")
	}
	return identity.DecryptKeypair(s.keypairData, string(passphrase))
}

func (s *Store) HasKeypair() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return false, errClosed
	}
	return s.keypairData != nil, nil
}

func (s *Store) SaveCollection(name string, crdtType crdt.CRDTType, entries map[string][]byte, tombstones map[string]uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}

	// Deep copy entries.
	ec := make(map[string][]byte, len(entries))
	for k, v := range entries {
		vc := make([]byte, len(v))
		copy(vc, v)
		ec[k] = vc
	}

	// Deep copy tombstones.
	tc := make(map[string]uint64, len(tombstones))
	for k, v := range tombstones {
		tc[k] = v
	}

	s.collections[name] = &collectionRecord{
		crdtType:   crdtType,
		entries:    ec,
		tombstones: tc,
	}
	return nil
}

func (s *Store) LoadCollection(name string) (crdt.CRDTType, map[string][]byte, map[string]uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, nil, nil, errClosed
	}

	rec, ok := s.collections[name]
	if !ok {
		return 0, nil, nil, errors.New("memory store: collection not found: " + name)
	}

	// Deep copy on read.
	ec := make(map[string][]byte, len(rec.entries))
	for k, v := range rec.entries {
		vc := make([]byte, len(v))
		copy(vc, v)
		ec[k] = vc
	}
	tc := make(map[string]uint64, len(rec.tombstones))
	for k, v := range rec.tombstones {
		tc[k] = v
	}

	return rec.crdtType, ec, tc, nil
}

func (s *Store) ListCollections() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errClosed
	}

	names := make([]string, 0, len(s.collections))
	for name := range s.collections {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (s *Store) SavePeer(peer persistence.PeerRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}

	key := hex.EncodeToString(peer.PeerID)
	// Deep copy addresses.
	addrs := make([]string, len(peer.Addresses))
	copy(addrs, peer.Addresses)

	pid := make([]byte, len(peer.PeerID))
	copy(pid, peer.PeerID)
	pub := make([]byte, len(peer.Pubkey))
	copy(pub, peer.Pubkey)

	s.peers[key] = persistence.PeerRecord{
		PeerID:     pid,
		Pubkey:     pub,
		Petname:    peer.Petname,
		Addresses:  addrs,
		LastSeen:   peer.LastSeen,
		TrustScore: peer.TrustScore,
	}
	return nil
}

func (s *Store) LoadPeers() ([]persistence.PeerRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errClosed
	}

	peers := make([]persistence.PeerRecord, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	return peers, nil
}

func (s *Store) DeletePeer(peerID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}

	key := hex.EncodeToString(peerID)
	delete(s.peers, key)
	return nil
}

func (s *Store) SaveHLC(hlc uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}
	s.hlc = hlc
	return nil
}

func (s *Store) LoadHLC() (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, errClosed
	}
	return s.hlc, nil
}

func (s *Store) SaveWatermark(peerID []byte, hlc uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}

	key := hex.EncodeToString(peerID)
	s.watermarks[key] = hlc
	return nil
}

func (s *Store) LoadWatermarks() (map[string]uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errClosed
	}

	wm := make(map[string]uint64, len(s.watermarks))
	for k, v := range s.watermarks {
		wm[k] = v
	}
	return wm, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
