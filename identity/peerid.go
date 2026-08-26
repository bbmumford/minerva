package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
)

// PeerID is a hex-encoded identity derived from an Ed25519 public key.
// It is the first 20 bytes of SHA-256(publicKey), hex encoded (40 chars).
type PeerID string

// PeerIDFromPublicKey derives the PeerID from an Ed25519 public key.
// Uses SHA-256 truncated to 20 bytes, hex encoded.
func PeerIDFromPublicKey(pub ed25519.PublicKey) PeerID {
	hash := sha256.Sum256(pub)
	return PeerID(hex.EncodeToString(hash[:20]))
}

// Short returns the first 12 characters of the PeerID for display.
func (id PeerID) Short() string {
	if len(id) < 12 {
		return string(id)
	}
	return string(id[:12])
}

// String returns the full hex-encoded PeerID.
func (id PeerID) String() string {
	return string(id)
}
