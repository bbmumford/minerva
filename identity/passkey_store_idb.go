//go:build js && wasm

package identity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"syscall/js"
	"time"
)

// IndexedDBPasskeyStore persists passkey credential metadata in browser
// IndexedDB. Uses the same async-to-sync channel pattern as the persistence
// package's IndexedDB store.
type IndexedDBPasskeyStore struct {
	mu     sync.RWMutex
	db     js.Value
	dbName string
	opened bool
}

// idbCredentialRecord is the JSON-serialisable form stored in IndexedDB.
type idbCredentialRecord struct {
	CredentialID  string `json:"credentialId"`
	RPEntityID    string `json:"rpEntityId"`
	UserHandle    string `json:"userHandle"`
	CreatedAt     int64  `json:"createdAt"`
	LastUsedAt    int64  `json:"lastUsedAt"`
	DisplayName   string `json:"displayName"`
	EncryptedSeed string `json:"encryptedSeed"`
}

// NewIndexedDBPasskeyStore creates a new IndexedDB-backed passkey store.
// The database is named "passkey-{appID}" to avoid collisions.
func NewIndexedDBPasskeyStore(appID string) *IndexedDBPasskeyStore {
	return &IndexedDBPasskeyStore{
		dbName: "passkey-" + appID,
	}
}

// ensureOpen opens the IndexedDB database if not already open.
func (s *IndexedDBPasskeyStore) ensureOpen() error {
	if s.opened {
		return nil
	}

	type openResult struct {
		db  js.Value
		err error
	}
	done := make(chan openResult, 1)

	openReq := js.Global().Get("indexedDB").Call("open", s.dbName, 1)

	var onUpgrade, onSuccess, onError js.Func

	onUpgrade = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onUpgrade.Release()
		db := args[0].Get("target").Get("result")
		if !db.Get("objectStoreNames").Call("contains", "credential").Bool() {
			db.Call("createObjectStore", "credential")
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
		done <- openResult{err: fmt.Errorf("passkey-idb: open failed: %s", args[0].Get("target").Get("error").String())}
		return nil
	})

	openReq.Set("onupgradeneeded", onUpgrade)
	openReq.Set("onsuccess", onSuccess)
	openReq.Set("onerror", onError)

	res := <-done
	if res.err != nil {
		return res.err
	}

	s.db = res.db
	s.opened = true
	return nil
}

// idbPut stores a value in the credential object store.
func (s *IndexedDBPasskeyStore) idbPut(key string, value js.Value) error {
	done := make(chan error, 1)
	tx := s.db.Call("transaction", "credential", "readwrite")
	store := tx.Call("objectStore", "credential")
	putReq := store.Call("put", value, key)

	var onSuccess, onError js.Func
	onSuccess = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onSuccess.Release()
		done <- nil
		return nil
	})
	onError = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onError.Release()
		done <- fmt.Errorf("passkey-idb: put %s: %s", key, args[0].Get("target").Get("error").String())
		return nil
	})
	putReq.Set("onsuccess", onSuccess)
	putReq.Set("onerror", onError)

	return <-done
}

// idbGet retrieves a value from the credential object store.
func (s *IndexedDBPasskeyStore) idbGet(key string) (js.Value, bool, error) {
	type getResult struct {
		val   js.Value
		found bool
		err   error
	}
	done := make(chan getResult, 1)
	tx := s.db.Call("transaction", "credential", "readonly")
	store := tx.Call("objectStore", "credential")
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
		done <- getResult{err: fmt.Errorf("passkey-idb: get %s: %s", key, args[0].Get("target").Get("error").String())}
		return nil
	})
	getReq.Set("onsuccess", onSuccess)
	getReq.Set("onerror", onError)

	res := <-done
	return res.val, res.found, res.err
}

// idbDelete removes a key from the credential object store.
func (s *IndexedDBPasskeyStore) idbDelete(key string) error {
	done := make(chan error, 1)
	tx := s.db.Call("transaction", "credential", "readwrite")
	store := tx.Call("objectStore", "credential")
	delReq := store.Call("delete", key)

	var onSuccess, onError js.Func
	onSuccess = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onSuccess.Release()
		done <- nil
		return nil
	})
	onError = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer onError.Release()
		done <- fmt.Errorf("passkey-idb: delete %s: %s", key, args[0].Get("target").Get("error").String())
		return nil
	})
	delReq.Set("onsuccess", onSuccess)
	delReq.Set("onerror", onError)

	return <-done
}

// SaveCredential persists a PasskeyCredential to IndexedDB.
func (s *IndexedDBPasskeyStore) SaveCredential(cred PasskeyCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureOpen(); err != nil {
		return err
	}

	rec := idbCredentialRecord{
		CredentialID:  base64.StdEncoding.EncodeToString(cred.CredentialID),
		RPEntityID:    cred.RPEntityID,
		UserHandle:    base64.StdEncoding.EncodeToString(cred.UserHandle),
		CreatedAt:     cred.CreatedAt.UnixMilli(),
		LastUsedAt:    cred.LastUsedAt.UnixMilli(),
		DisplayName:   cred.DisplayName,
		EncryptedSeed: base64.StdEncoding.EncodeToString(cred.EncryptedSeed),
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("passkey-idb: marshal credential: %w", err)
	}

	return s.idbPut("default", js.ValueOf(string(data)))
}

// LoadCredential loads the stored PasskeyCredential from IndexedDB.
func (s *IndexedDBPasskeyStore) LoadCredential() (*PasskeyCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureOpen(); err != nil {
		return nil, err
	}

	val, found, err := s.idbGet("default")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	var rec idbCredentialRecord
	if err := json.Unmarshal([]byte(val.String()), &rec); err != nil {
		return nil, fmt.Errorf("passkey-idb: unmarshal credential: %w", err)
	}

	credentialID, err := base64.StdEncoding.DecodeString(rec.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("passkey-idb: decode credential ID: %w", err)
	}

	userHandle, err := base64.StdEncoding.DecodeString(rec.UserHandle)
	if err != nil {
		return nil, fmt.Errorf("passkey-idb: decode user handle: %w", err)
	}

	encryptedSeed, err := base64.StdEncoding.DecodeString(rec.EncryptedSeed)
	if err != nil {
		return nil, fmt.Errorf("passkey-idb: decode encrypted seed: %w", err)
	}

	return &PasskeyCredential{
		CredentialID:  credentialID,
		RPEntityID:    rec.RPEntityID,
		UserHandle:    userHandle,
		CreatedAt:     time.UnixMilli(rec.CreatedAt),
		LastUsedAt:    time.UnixMilli(rec.LastUsedAt),
		DisplayName:   rec.DisplayName,
		EncryptedSeed: encryptedSeed,
	}, nil
}

// HasCredential returns true if a passkey credential is stored.
func (s *IndexedDBPasskeyStore) HasCredential() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureOpen(); err != nil {
		return false
	}

	_, found, err := s.idbGet("default")
	return found && err == nil
}

// DeleteCredential removes the stored passkey credential.
func (s *IndexedDBPasskeyStore) DeleteCredential() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureOpen(); err != nil {
		return err
	}

	return s.idbDelete("default")
}
