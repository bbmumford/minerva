//go:build js && wasm

// Package indexeddb provides a persistence.Store backed by browser IndexedDB.
// It uses syscall/js to interact with the IndexedDB API, converting async
// callbacks into synchronous Go operations via channels.
package indexeddb

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"syscall/js"

	"github.com/bbmumford/minerva/crdt"
	"github.com/bbmumford/minerva/identity"
	"github.com/bbmumford/minerva/persistence"
)

var errClosed = errors.New("indexeddb: store closed")

// Store satisfies persistence.Store using browser IndexedDB via syscall/js.
type Store struct {
	mu     sync.RWMutex
	db     js.Value
	closed bool
}

// New opens (or creates) an IndexedDB database with the given name.
func New(dbName string) (*Store, error) {
	type openResult struct {
		db  js.Value
		err error
	}
	done := make(chan openResult, 1)

	openReq := js.Global().Get("indexedDB").Call("open", dbName, 1)

	var onUpgrade, onSuccess, onError js.Func

	onUpgrade = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onUpgrade.Release()
		db := args[0].Get("target").Get("result")
		stores := []string{"keypair", "collections", "peers", "hlc", "watermarks"}
		for _, name := range stores {
			if !db.Call("objectStoreNames", nil).Call("contains", name).Bool() {
				db.Call("createObjectStore", name)
			}
		}
		return nil
	})

	onSuccess = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onSuccess.Release()
		done <- openResult{db: args[0].Get("target").Get("result")}
		return nil
	})

	onError = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onError.Release()
		done <- openResult{err: fmt.Errorf("indexeddb: open failed: %s", args[0].Get("target").Get("error").String())}
		return nil
	})

	openReq.Set("onupgradeneeded", onUpgrade)
	openReq.Set("onsuccess", onSuccess)
	openReq.Set("onerror", onError)

	res := <-done
	if res.err != nil {
		return nil, res.err
	}
	return &Store{db: res.db}, nil
}

// --- internal helpers --------------------------------------------------------

// idbPut stores a JS value in the given object store under the given key.
func (s *Store) idbPut(storeName string, key string, value js.Value) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}

	done := make(chan error, 1)
	tx := s.db.Call("transaction", storeName, "readwrite")
	store := tx.Call("objectStore", storeName)
	putReq := store.Call("put", value, key)

	var onSuccess, onError js.Func
	onSuccess = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onSuccess.Release()
		done <- nil
		return nil
	})
	onError = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onError.Release()
		done <- fmt.Errorf("indexeddb: put %s/%s: %s", storeName, key, args[0].Get("target").Get("error").String())
		return nil
	})
	putReq.Set("onsuccess", onSuccess)
	putReq.Set("onerror", onError)

	return <-done
}

// idbGet retrieves a value from the given object store. Returns (result, found, error).
// The result is js.Undefined() when not found.
func (s *Store) idbGet(storeName string, key string) (js.Value, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return js.Undefined(), false, errClosed
	}

	type getResult struct {
		val   js.Value
		found bool
		err   error
	}
	done := make(chan getResult, 1)
	tx := s.db.Call("transaction", storeName, "readonly")
	store := tx.Call("objectStore", storeName)
	getReq := store.Call("get", key)

	var onSuccess, onError js.Func
	onSuccess = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onSuccess.Release()
		result := args[0].Get("target").Get("result")
		done <- getResult{val: result, found: !result.IsUndefined()}
		return nil
	})
	onError = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onError.Release()
		done <- getResult{err: fmt.Errorf("indexeddb: get %s/%s: %s", storeName, key, args[0].Get("target").Get("error").String())}
		return nil
	})
	getReq.Set("onsuccess", onSuccess)
	getReq.Set("onerror", onError)

	res := <-done
	return res.val, res.found, res.err
}

// idbDelete removes a key from the given object store.
func (s *Store) idbDelete(storeName string, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}

	done := make(chan error, 1)
	tx := s.db.Call("transaction", storeName, "readwrite")
	store := tx.Call("objectStore", storeName)
	delReq := store.Call("delete", key)

	var onSuccess, onError js.Func
	onSuccess = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onSuccess.Release()
		done <- nil
		return nil
	})
	onError = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onError.Release()
		done <- fmt.Errorf("indexeddb: delete %s/%s: %s", storeName, key, args[0].Get("target").Get("error").String())
		return nil
	})
	delReq.Set("onsuccess", onSuccess)
	delReq.Set("onerror", onError)

	return <-done
}

// idbGetAllKeys returns all keys in the given object store as strings.
func (s *Store) idbGetAllKeys(storeName string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errClosed
	}

	type keysResult struct {
		keys []string
		err  error
	}
	done := make(chan keysResult, 1)
	tx := s.db.Call("transaction", storeName, "readonly")
	store := tx.Call("objectStore", storeName)
	req := store.Call("getAllKeys")

	var onSuccess, onError js.Func
	onSuccess = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onSuccess.Release()
		result := args[0].Get("target").Get("result")
		length := result.Length()
		keys := make([]string, length)
		for i := 0; i < length; i++ {
			keys[i] = result.Index(i).String()
		}
		done <- keysResult{keys: keys}
		return nil
	})
	onError = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onError.Release()
		done <- keysResult{err: fmt.Errorf("indexeddb: getAllKeys %s: %s", storeName, args[0].Get("target").Get("error").String())}
		return nil
	})
	req.Set("onsuccess", onSuccess)
	req.Set("onerror", onError)

	res := <-done
	return res.keys, res.err
}

// idbGetAll returns all values in the given object store as a JS array.
func (s *Store) idbGetAll(storeName string) (js.Value, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return js.Undefined(), errClosed
	}

	type allResult struct {
		val js.Value
		err error
	}
	done := make(chan allResult, 1)
	tx := s.db.Call("transaction", storeName, "readonly")
	store := tx.Call("objectStore", storeName)
	req := store.Call("getAll")

	var onSuccess, onError js.Func
	onSuccess = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onSuccess.Release()
		done <- allResult{val: args[0].Get("target").Get("result")}
		return nil
	})
	onError = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onError.Release()
		done <- allResult{err: fmt.Errorf("indexeddb: getAll %s: %s", storeName, args[0].Get("target").Get("error").String())}
		return nil
	})
	req.Set("onsuccess", onSuccess)
	req.Set("onerror", onError)

	res := <-done
	return res.val, res.err
}

// jsString stores a Go string as a JS string value.
func jsString(s string) js.Value {
	return js.ValueOf(s)
}

// --- Keypair -----------------------------------------------------------------

func (s *Store) SaveKeypair(keypair *identity.Keypair, passphrase []byte) error {
	encrypted, err := identity.EncryptKeypair(keypair, string(passphrase))
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(encrypted)
	return s.idbPut("keypair", "default", jsString(encoded))
}

func (s *Store) LoadKeypair(passphrase []byte) (*identity.Keypair, error) {
	val, found, err := s.idbGet("keypair", "default")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("indexeddb: no keypair saved")
	}

	encrypted, err := base64.StdEncoding.DecodeString(val.String())
	if err != nil {
		return nil, fmt.Errorf("indexeddb: decode keypair: %w", err)
	}
	return identity.DecryptKeypair(encrypted, string(passphrase))
}

func (s *Store) HasKeypair() (bool, error) {
	_, found, err := s.idbGet("keypair", "default")
	return found, err
}

// --- Collections -------------------------------------------------------------

type collectionRecord struct {
	CRDTType   crdt.CRDTType     `json:"crdtType"`
	Entries    map[string]string `json:"entries"` // key -> base64(value)
	Tombstones map[string]uint64 `json:"tombstones"`
}

func (s *Store) SaveCollection(name string, crdtType crdt.CRDTType, entries map[string][]byte, tombstones map[string]uint64) error {
	enc := make(map[string]string, len(entries))
	for k, v := range entries {
		enc[k] = base64.StdEncoding.EncodeToString(v)
	}
	tc := make(map[string]uint64, len(tombstones))
	for k, v := range tombstones {
		tc[k] = v
	}

	rec := collectionRecord{
		CRDTType:   crdtType,
		Entries:    enc,
		Tombstones: tc,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("indexeddb: marshal collection %s: %w", name, err)
	}
	return s.idbPut("collections", name, jsString(string(data)))
}

func (s *Store) LoadCollection(name string) (crdt.CRDTType, map[string][]byte, map[string]uint64, error) {
	val, found, err := s.idbGet("collections", name)
	if err != nil {
		return 0, nil, nil, err
	}
	if !found {
		return 0, nil, nil, fmt.Errorf("indexeddb: collection not found: %s", name)
	}

	var rec collectionRecord
	if err := json.Unmarshal([]byte(val.String()), &rec); err != nil {
		return 0, nil, nil, fmt.Errorf("indexeddb: unmarshal collection %s: %w", name, err)
	}

	entries := make(map[string][]byte, len(rec.Entries))
	for k, v := range rec.Entries {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("indexeddb: decode entry %s/%s: %w", name, k, err)
		}
		entries[k] = b
	}
	return rec.CRDTType, entries, rec.Tombstones, nil
}

func (s *Store) ListCollections() ([]string, error) {
	return s.idbGetAllKeys("collections")
}

// --- Peers -------------------------------------------------------------------

type peerRecord struct {
	PeerID     string   `json:"peerId"`
	Pubkey     string   `json:"pubkey"`
	Petname    string   `json:"petname"`
	Addresses  []string `json:"addresses"`
	LastSeen   int64    `json:"lastSeen"`
	TrustScore float64  `json:"trustScore"`
}

func (s *Store) SavePeer(peer persistence.PeerRecord) error {
	key := hex.EncodeToString(peer.PeerID)
	rec := peerRecord{
		PeerID:     key,
		Pubkey:     hex.EncodeToString(peer.Pubkey),
		Petname:    peer.Petname,
		Addresses:  peer.Addresses,
		LastSeen:   peer.LastSeen,
		TrustScore: peer.TrustScore,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("indexeddb: marshal peer %s: %w", key, err)
	}
	return s.idbPut("peers", key, jsString(string(data)))
}

func (s *Store) LoadPeers() ([]persistence.PeerRecord, error) {
	keys, err := s.idbGetAllKeys("peers")
	if err != nil {
		return nil, err
	}

	peers := make([]persistence.PeerRecord, 0, len(keys))
	for _, key := range keys {
		val, found, err := s.idbGet("peers", key)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}

		var rec peerRecord
		if err := json.Unmarshal([]byte(val.String()), &rec); err != nil {
			return nil, fmt.Errorf("indexeddb: unmarshal peer %s: %w", key, err)
		}

		pid, _ := hex.DecodeString(rec.PeerID)
		pub, _ := hex.DecodeString(rec.Pubkey)
		peers = append(peers, persistence.PeerRecord{
			PeerID:     pid,
			Pubkey:     pub,
			Petname:    rec.Petname,
			Addresses:  rec.Addresses,
			LastSeen:   rec.LastSeen,
			TrustScore: rec.TrustScore,
		})
	}
	return peers, nil
}

func (s *Store) DeletePeer(peerID []byte) error {
	key := hex.EncodeToString(peerID)
	return s.idbDelete("peers", key)
}

// --- HLC ---------------------------------------------------------------------

func (s *Store) SaveHLC(hlc uint64) error {
	// Store as float64 since JS numbers are IEEE 754 doubles.
	// Safe for values up to 2^53.
	return s.idbPut("hlc", "current", js.ValueOf(float64(hlc)))
}

func (s *Store) LoadHLC() (uint64, error) {
	val, found, err := s.idbGet("hlc", "current")
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, nil
	}
	return uint64(math.Round(val.Float())), nil
}

// --- Watermarks --------------------------------------------------------------

func (s *Store) SaveWatermark(peerID []byte, hlc uint64) error {
	key := hex.EncodeToString(peerID)
	return s.idbPut("watermarks", key, js.ValueOf(float64(hlc)))
}

func (s *Store) LoadWatermarks() (map[string]uint64, error) {
	keys, err := s.idbGetAllKeys("watermarks")
	if err != nil {
		return nil, err
	}

	wm := make(map[string]uint64, len(keys))
	for _, key := range keys {
		val, found, err := s.idbGet("watermarks", key)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		wm[key] = uint64(math.Round(val.Float()))
	}
	return wm, nil
}

// --- Close -------------------------------------------------------------------

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}
	s.closed = true
	// IndexedDB connections are garbage collected; explicit close is optional
	// but we call it for cleanliness.
	s.db.Call("close")
	return nil
}
