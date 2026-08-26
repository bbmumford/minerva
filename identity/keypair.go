package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// Keypair holds an Ed25519 signing keypair.
type Keypair struct {
	PublicKey  ed25519.PublicKey  // 32 bytes
	PrivateKey ed25519.PrivateKey // 64 bytes (seed + public)
}

// Generate creates a new random Ed25519 keypair.
// Uses crypto/rand for entropy.
func Generate() (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate keypair: %w", err)
	}
	return &Keypair{PublicKey: pub, PrivateKey: priv}, nil
}

// Sign produces an Ed25519 signature over the message.
func (kp *Keypair) Sign(data []byte) []byte {
	return ed25519.Sign(kp.PrivateKey, data)
}

// Verify checks an Ed25519 signature against a public key.
func Verify(pubkey ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(pubkey, data, sig)
}

// Seed returns the 32-byte private key seed.
func (kp *Keypair) Seed() []byte {
	return kp.PrivateKey.Seed()
}

// FromSeed reconstructs a keypair from a 32-byte seed.
func FromSeed(seed []byte) (*Keypair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity: seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Keypair{PublicKey: pub, PrivateKey: priv}, nil
}
