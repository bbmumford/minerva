package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrPasskeyNotAvailable is returned when the platform does not support passkeys.
	ErrPasskeyNotAvailable = errors.New("identity: passkey authentication not available on this platform")

	// ErrNoPasskeyRegistered is returned when no passkey credential is stored.
	ErrNoPasskeyRegistered = errors.New("identity: no passkey registered")

	// ErrPasskeyDecryptFailed is returned when the PRF-derived key cannot decrypt the seed.
	ErrPasskeyDecryptFailed = errors.New("identity: passkey decrypt failed (credential may have changed)")
)

// PasskeyCredential represents a registered WebAuthn passkey.
type PasskeyCredential struct {
	CredentialID  []byte    `json:"credentialId"`  // unique credential identifier
	RPEntityID    string    `json:"rpEntityId"`    // relying party (e.g., "minerva.local")
	UserHandle    []byte    `json:"userHandle"`    // opaque user handle (derived from pubkey)
	CreatedAt     time.Time `json:"createdAt"`
	LastUsedAt    time.Time `json:"lastUsedAt"`
	DisplayName   string    `json:"displayName"`   // e.g., "MacBook Touch ID", "iPhone Face ID"
	EncryptedSeed []byte    `json:"encryptedSeed"` // seed encrypted with PRF-derived key
}

// PasskeyProvider abstracts platform-specific passkey operations.
// Browser WASM uses navigator.credentials API.
// Native uses OS passkey APIs (Windows Hello, macOS Touch ID).
type PasskeyProvider interface {
	// Register creates a new passkey credential with the authenticator.
	// Returns the credential and the PRF-derived 32-byte encryption key.
	Register(ctx context.Context, rpID string, userHandle []byte, displayName string) (*PasskeyCredential, []byte, error)

	// Authenticate uses an existing credential to derive the encryption key.
	// User is prompted for biometric verification (fingerprint, Face ID, etc.)
	// The rpID must match the RP ID used during registration for consistent
	// PRF salt derivation.
	Authenticate(ctx context.Context, credentialID []byte, rpID string) ([]byte, error)

	// IsAvailable returns true if passkey authentication is supported.
	IsAvailable() bool
}

// PasskeyStore persists passkey credential metadata (not the keys themselves).
type PasskeyStore interface {
	SaveCredential(cred PasskeyCredential) error
	LoadCredential() (*PasskeyCredential, error)
	HasCredential() bool
	DeleteCredential() error
}

// PasskeyManager manages passkey-protected wallet access.
type PasskeyManager struct {
	provider PasskeyProvider
	store    PasskeyStore
}

// NewPasskeyManager creates a new PasskeyManager with the given provider and store.
func NewPasskeyManager(provider PasskeyProvider, store PasskeyStore) *PasskeyManager {
	return &PasskeyManager{
		provider: provider,
		store:    store,
	}
}

// RegisterPasskey creates a new passkey and encrypts the wallet seed with
// the PRF-derived key. The encrypted seed is stored alongside the credential
// metadata. Returns the encrypted seed for external storage if needed.
func (pm *PasskeyManager) RegisterPasskey(ctx context.Context, seed []byte, displayName string) ([]byte, error) {
	if !pm.provider.IsAvailable() {
		return nil, ErrPasskeyNotAvailable
	}

	// Derive a user handle from the seed (SHA-256 of the public key derived from seed).
	kp, err := FromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("identity: passkey register: %w", err)
	}
	userHandle := kp.PublicKey[:16] // first 16 bytes of pubkey as user handle

	cred, prfKey, err := pm.provider.Register(ctx, "minerva.local", userHandle, displayName)
	if err != nil {
		return nil, fmt.Errorf("identity: passkey register: %w", err)
	}

	if len(prfKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("identity: PRF key must be %d bytes, got %d", chacha20poly1305.KeySize, len(prfKey))
	}

	// Encrypt the seed with ChaCha20-Poly1305 using the PRF-derived key.
	encryptedSeed, err := encryptWithKey(seed, prfKey)
	if err != nil {
		return nil, fmt.Errorf("identity: passkey encrypt seed: %w", err)
	}

	// Store the encrypted seed with the credential.
	cred.EncryptedSeed = encryptedSeed

	if err := pm.store.SaveCredential(*cred); err != nil {
		return nil, fmt.Errorf("identity: passkey save credential: %w", err)
	}

	return encryptedSeed, nil
}

// UnlockWithPasskey authenticates via passkey and decrypts the wallet seed.
func (pm *PasskeyManager) UnlockWithPasskey(ctx context.Context) ([]byte, error) {
	if !pm.provider.IsAvailable() {
		return nil, ErrPasskeyNotAvailable
	}

	cred, err := pm.store.LoadCredential()
	if err != nil {
		return nil, fmt.Errorf("identity: passkey load credential: %w", err)
	}
	if cred == nil {
		return nil, ErrNoPasskeyRegistered
	}

	prfKey, err := pm.provider.Authenticate(ctx, cred.CredentialID, cred.RPEntityID)
	if err != nil {
		return nil, fmt.Errorf("identity: passkey authenticate: %w", err)
	}

	if len(prfKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("identity: PRF key must be %d bytes, got %d", chacha20poly1305.KeySize, len(prfKey))
	}

	seed, err := decryptWithKey(cred.EncryptedSeed, prfKey)
	if err != nil {
		return nil, ErrPasskeyDecryptFailed
	}

	// Update last used time.
	cred.LastUsedAt = time.Now()
	_ = pm.store.SaveCredential(*cred) // best-effort update

	return seed, nil
}

// HasPasskey returns true if a passkey is registered.
func (pm *PasskeyManager) HasPasskey() bool {
	return pm.store.HasCredential()
}

// RemovePasskey deletes the registered passkey credential.
func (pm *PasskeyManager) RemovePasskey() error {
	return pm.store.DeleteCredential()
}

// encryptWithKey encrypts plaintext using XChaCha20-Poly1305 with a raw 32-byte key.
// Format: nonce (24 bytes) || ciphertext (plaintext + 16 byte tag).
func encryptWithKey(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// nonce || ciphertext
	result := make([]byte, 0, len(nonce)+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result, nil
}

// decryptWithKey decrypts data encrypted by encryptWithKey using a raw 32-byte key.
func decryptWithKey(encrypted, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(encrypted) < nonceSize+aead.Overhead() {
		return nil, errors.New("encrypted data too short")
	}

	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

