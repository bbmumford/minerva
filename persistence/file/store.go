//go:build !js

// Package file provides a persistence.Store backed by JSON files on disk.
// This avoids requiring cgo (needed for go-sqlite3) while providing a
// functional native store. A proper SQLite backend can be added later.
//
// Directory layout:
//
//	{dir}/keypair.json          — encrypted keypair (base64 blob)
//	{dir}/collections/{name}.json — per-collection CRDT state
//	{dir}/peers.json            — peer records
//	{dir}/hlc.json              — HLC counter
//	{dir}/watermarks.json       — gossip watermarks
package file

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/bbmumford/minerva/crdt"
	"github.com/bbmumford/minerva/identity"
	"github.com/bbmumford/minerva/persistence"
)

// Store is a JSON-file-backed persistence.Store.
type Store struct {
	mu  sync.RWMutex
	dir string
}

// New creates a file store rooted at dir, creating the directory tree if needed.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "collections"), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// --- keypair ----------------------------------------------------------------

type keypairFile struct {
	Encrypted string `json:"encrypted"` // base64 of encrypted blob
}

func (s *Store) keypairPath() string {
	return filepath.Join(s.dir, "keypair.json")
}

func (s *Store) SaveKeypair(keypair *identity.Keypair, passphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	encrypted, err := identity.EncryptKeypair(keypair, string(passphrase))
	if err != nil {
		return err
	}

	data := keypairFile{Encrypted: base64.StdEncoding.EncodeToString(encrypted)}
	return writeJSON(s.keypairPath(), data)
}

func (s *Store) LoadKeypair(passphrase []byte) (*identity.Keypair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var data keypairFile
	if err := readJSON(s.keypairPath(), &data); err != nil {
		return nil, err
	}

	encrypted, err := base64.StdEncoding.DecodeString(data.Encrypted)
	if err != nil {
		return nil, err
	}
	return identity.DecryptKeypair(encrypted, string(passphrase))
}

func (s *Store) HasKeypair() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, err := os.Stat(s.keypairPath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// --- collections ------------------------------------------------------------

type collectionFile struct {
	CRDTType   crdt.CRDTType     `json:"crdtType"`
	Entries    map[string]string  `json:"entries"`    // key -> base64(value)
	Tombstones map[string]uint64 `json:"tombstones"`
}

func (s *Store) collectionPath(name string) string {
	return filepath.Join(s.dir, "collections", name+".json")
}

func (s *Store) SaveCollection(name string, crdtType crdt.CRDTType, entries map[string][]byte, tombstones map[string]uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	enc := make(map[string]string, len(entries))
	for k, v := range entries {
		enc[k] = base64.StdEncoding.EncodeToString(v)
	}

	tc := make(map[string]uint64, len(tombstones))
	for k, v := range tombstones {
		tc[k] = v
	}

	data := collectionFile{
		CRDTType:   crdtType,
		Entries:    enc,
		Tombstones: tc,
	}
	return writeJSON(s.collectionPath(name), data)
}

func (s *Store) LoadCollection(name string) (crdt.CRDTType, map[string][]byte, map[string]uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var data collectionFile
	if err := readJSON(s.collectionPath(name), &data); err != nil {
		return 0, nil, nil, err
	}

	entries := make(map[string][]byte, len(data.Entries))
	for k, v := range data.Entries {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return 0, nil, nil, err
		}
		entries[k] = b
	}

	return data.CRDTType, entries, data.Tombstones, nil
}

func (s *Store) ListCollections() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := filepath.Join(s.dir, "collections")
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var names []string
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if ext := filepath.Ext(name); ext == ".json" {
			names = append(names, name[:len(name)-len(ext)])
		}
	}
	sort.Strings(names)
	return names, nil
}

// --- peers ------------------------------------------------------------------

type peerFile struct {
	PeerID     string   `json:"peerId"`     // hex
	Pubkey     string   `json:"pubkey"`     // hex
	Petname    string   `json:"petname"`
	Addresses  []string `json:"addresses"`
	LastSeen   int64    `json:"lastSeen"`
	TrustScore float64  `json:"trustScore"`
}

func (s *Store) peersPath() string {
	return filepath.Join(s.dir, "peers.json")
}

func (s *Store) SavePeer(peer persistence.PeerRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	peers, _ := s.loadPeersLocked()

	key := hex.EncodeToString(peer.PeerID)
	peers[key] = peerFile{
		PeerID:     key,
		Pubkey:     hex.EncodeToString(peer.Pubkey),
		Petname:    peer.Petname,
		Addresses:  peer.Addresses,
		LastSeen:   peer.LastSeen,
		TrustScore: peer.TrustScore,
	}

	return writeJSON(s.peersPath(), peers)
}

func (s *Store) LoadPeers() ([]persistence.PeerRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peers, err := s.loadPeersLocked()
	if err != nil {
		return nil, err
	}

	result := make([]persistence.PeerRecord, 0, len(peers))
	for _, p := range peers {
		pid, _ := hex.DecodeString(p.PeerID)
		pub, _ := hex.DecodeString(p.Pubkey)
		result = append(result, persistence.PeerRecord{
			PeerID:     pid,
			Pubkey:     pub,
			Petname:    p.Petname,
			Addresses:  p.Addresses,
			LastSeen:   p.LastSeen,
			TrustScore: p.TrustScore,
		})
	}
	return result, nil
}

func (s *Store) DeletePeer(peerID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	peers, _ := s.loadPeersLocked()
	key := hex.EncodeToString(peerID)
	delete(peers, key)
	return writeJSON(s.peersPath(), peers)
}

// loadPeersLocked reads the peers file. Caller must hold at least s.mu.RLock().
func (s *Store) loadPeersLocked() (map[string]peerFile, error) {
	peers := make(map[string]peerFile)
	err := readJSON(s.peersPath(), &peers)
	if errors.Is(err, os.ErrNotExist) {
		return peers, nil
	}
	return peers, err
}

// --- HLC --------------------------------------------------------------------

type hlcFile struct {
	HLC uint64 `json:"hlc"`
}

func (s *Store) hlcPath() string {
	return filepath.Join(s.dir, "hlc.json")
}

func (s *Store) SaveHLC(hlc uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSON(s.hlcPath(), hlcFile{HLC: hlc})
}

func (s *Store) LoadHLC() (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var data hlcFile
	if err := readJSON(s.hlcPath(), &data); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	return data.HLC, nil
}

// --- watermarks -------------------------------------------------------------

func (s *Store) watermarksPath() string {
	return filepath.Join(s.dir, "watermarks.json")
}

func (s *Store) SaveWatermark(peerID []byte, hlc uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	wm := make(map[string]uint64)
	_ = readJSON(s.watermarksPath(), &wm) // ignore not-found
	wm[hex.EncodeToString(peerID)] = hlc
	return writeJSON(s.watermarksPath(), wm)
}

func (s *Store) LoadWatermarks() (map[string]uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	wm := make(map[string]uint64)
	if err := readJSON(s.watermarksPath(), &wm); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return wm, nil
		}
		return nil, err
	}
	return wm, nil
}

// --- Close ------------------------------------------------------------------

func (s *Store) Close() error {
	return nil
}

// --- helpers ----------------------------------------------------------------

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
