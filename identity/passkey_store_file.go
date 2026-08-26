//go:build !js

package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FilePasskeyStore persists passkey credential metadata as a JSON file on disk.
// Used on native platforms (macOS, Windows, Linux) for credential metadata
// storage. The actual passkey secret never touches disk — only the credential
// ID, display name, and encrypted seed are persisted.
type FilePasskeyStore struct {
	path string // full path to passkey.json
}

// fileCredentialRecord is the JSON-serialisable form stored on disk.
type fileCredentialRecord struct {
	CredentialID  []byte `json:"credentialId"`
	RPEntityID    string `json:"rpEntityId"`
	UserHandle    []byte `json:"userHandle"`
	CreatedAt     int64  `json:"createdAt"`
	LastUsedAt    int64  `json:"lastUsedAt"`
	DisplayName   string `json:"displayName"`
	EncryptedSeed []byte `json:"encryptedSeed"`
}

// NewFilePasskeyStore creates a new file-based passkey store.
// Credential metadata is stored at {dir}/passkey.json.
func NewFilePasskeyStore(dir string) *FilePasskeyStore {
	return &FilePasskeyStore{
		path: filepath.Join(dir, "passkey.json"),
	}
}

// SaveCredential persists a PasskeyCredential to disk as JSON.
func (s *FilePasskeyStore) SaveCredential(cred PasskeyCredential) error {
	rec := fileCredentialRecord{
		CredentialID:  cred.CredentialID,
		RPEntityID:    cred.RPEntityID,
		UserHandle:    cred.UserHandle,
		CreatedAt:     cred.CreatedAt.UnixMilli(),
		LastUsedAt:    cred.LastUsedAt.UnixMilli(),
		DisplayName:   cred.DisplayName,
		EncryptedSeed: cred.EncryptedSeed,
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("passkey-file: marshal credential: %w", err)
	}

	// Ensure parent directory exists.
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("passkey-file: create directory: %w", err)
	}

	// Write atomically: write to temp file then rename.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("passkey-file: write temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp) // clean up on rename failure
		return fmt.Errorf("passkey-file: rename: %w", err)
	}

	return nil
}

// LoadCredential loads the stored PasskeyCredential from disk.
// Returns nil, nil if no credential file exists.
func (s *FilePasskeyStore) LoadCredential() (*PasskeyCredential, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("passkey-file: read credential: %w", err)
	}

	var rec fileCredentialRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("passkey-file: unmarshal credential: %w", err)
	}

	return &PasskeyCredential{
		CredentialID:  rec.CredentialID,
		RPEntityID:    rec.RPEntityID,
		UserHandle:    rec.UserHandle,
		CreatedAt:     time.UnixMilli(rec.CreatedAt),
		LastUsedAt:    time.UnixMilli(rec.LastUsedAt),
		DisplayName:   rec.DisplayName,
		EncryptedSeed: rec.EncryptedSeed,
	}, nil
}

// HasCredential returns true if a passkey credential file exists.
func (s *FilePasskeyStore) HasCredential() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// DeleteCredential removes the stored passkey credential file.
func (s *FilePasskeyStore) DeleteCredential() error {
	err := os.Remove(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // already deleted
	}
	return err
}
