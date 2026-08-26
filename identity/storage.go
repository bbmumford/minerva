package identity

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Argon2id parameters for native builds.
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = chacha20poly1305.KeySize // 32 bytes

	saltSize = 32
)

// Storage format: salt (32 bytes) || nonce (24 bytes) || ciphertext (private key + 16 byte tag)

// EncryptKeypair encrypts the private key using XChaCha20-Poly1305 with a
// passphrase-derived key (Argon2id KDF).
func EncryptKeypair(kp *Keypair, passphrase string) ([]byte, error) {
	if kp == nil {
		return nil, errors.New("identity: keypair is nil")
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("identity: generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("identity: create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("identity: generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, []byte(kp.PrivateKey), nil)

	// salt || nonce || ciphertext
	result := make([]byte, 0, saltSize+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// DecryptKeypair reverses EncryptKeypair, recovering the keypair from
// encrypted storage using the passphrase.
func DecryptKeypair(encrypted []byte, passphrase string) (*Keypair, error) {
	nonceSize := chacha20poly1305.NonceSizeX
	minSize := saltSize + nonceSize + chacha20poly1305.Overhead
	if len(encrypted) < minSize {
		return nil, errors.New("identity: encrypted data too short")
	}

	salt := encrypted[:saltSize]
	nonce := encrypted[saltSize : saltSize+nonceSize]
	ciphertext := encrypted[saltSize+nonceSize:]

	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("identity: create cipher: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("identity: decrypt failed (wrong passphrase?): %w", err)
	}

	if len(plaintext) < 32 {
		return nil, fmt.Errorf("identity: decrypted data is %d bytes, expected at least 32", len(plaintext))
	}

	return FromSeed(plaintext[:32])
}

// DecryptKeypairWithKey decrypts a keypair using a raw 32-byte key instead of
// a passphrase. Used by the passkey flow where the PRF output is already the
// encryption key — no Argon2id KDF needed.
//
// The encrypted format is: nonce (24 bytes) || ciphertext (private key + 16 byte tag).
// This differs from the passphrase format which includes a salt prefix.
func DecryptKeypairWithKey(encrypted []byte, key []byte) (*Keypair, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("identity: key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}

	plaintext, err := decryptWithKey(encrypted, key)
	if err != nil {
		return nil, fmt.Errorf("identity: decrypt with key failed: %w", err)
	}

	if len(plaintext) < 32 {
		return nil, fmt.Errorf("identity: decrypted data is %d bytes, expected at least 32", len(plaintext))
	}

	return FromSeed(plaintext[:32])
}
