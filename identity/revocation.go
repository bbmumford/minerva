package identity

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// RevocationRecord represents the revocation of a device key by a master key.
type RevocationRecord struct {
	RevokedPublicKey ed25519.PublicKey `json:"revokedPublicKey"`
	RevokerPublicKey ed25519.PublicKey `json:"revokerPublicKey"`
	Reason           string           `json:"reason"`
	RevokedAt        time.Time        `json:"revokedAt"`
	Signature        []byte           `json:"signature"`
}

// revocationSigningPayload builds the canonical byte payload for signing:
// revokedPubKey || reason || revokedAt (unix nanos, big-endian)
func revocationSigningPayload(revokedPubKey ed25519.PublicKey, reason string, revokedAt time.Time) []byte {
	buf := make([]byte, 0, len(revokedPubKey)+len(reason)+8)
	buf = append(buf, revokedPubKey...)
	buf = append(buf, []byte(reason)...)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(revokedAt.UnixNano()))
	buf = append(buf, ts[:]...)

	return buf
}

// RevokeDevice creates a signed revocation record for a device public key.
// The masterKeypair must be the authority that originally delegated the device key.
func RevokeDevice(masterKeypair *Keypair, devicePubKey ed25519.PublicKey, reason string) (*RevocationRecord, error) {
	if masterKeypair == nil {
		return nil, fmt.Errorf("identity/revocation: master keypair is nil")
	}
	if len(devicePubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity/revocation: invalid device public key length: %d", len(devicePubKey))
	}

	now := time.Now()
	payload := revocationSigningPayload(devicePubKey, reason, now)
	sig := masterKeypair.Sign(payload)

	return &RevocationRecord{
		RevokedPublicKey: devicePubKey,
		RevokerPublicKey: masterKeypair.PublicKey,
		Reason:           reason,
		RevokedAt:        now,
		Signature:        sig,
	}, nil
}

// VerifyRevocation checks that the revocation record signature is valid
// against the revoker public key and the canonical payload.
func VerifyRevocation(rec *RevocationRecord) bool {
	if rec == nil {
		return false
	}
	if len(rec.RevokerPublicKey) != ed25519.PublicKeySize || len(rec.RevokedPublicKey) != ed25519.PublicKeySize {
		return false
	}
	payload := revocationSigningPayload(rec.RevokedPublicKey, rec.Reason, rec.RevokedAt)
	return ed25519.Verify(rec.RevokerPublicKey, payload, rec.Signature)
}

// RevocationRegistry is a thread-safe in-memory store of revocation records.
type RevocationRegistry struct {
	mu      sync.RWMutex
	revoked map[string]*RevocationRecord // hex pubkey -> record
}

// NewRevocationRegistry creates an empty revocation registry.
func NewRevocationRegistry() *RevocationRegistry {
	return &RevocationRegistry{
		revoked: make(map[string]*RevocationRecord),
	}
}

// Add inserts a verified revocation record into the registry.
// Returns an error if the record's signature is invalid.
func (r *RevocationRegistry) Add(rec *RevocationRecord) error {
	if !VerifyRevocation(rec) {
		return fmt.Errorf("identity/revocation: invalid revocation signature")
	}
	key := hex.EncodeToString(rec.RevokedPublicKey)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[key] = rec
	return nil
}

// IsRevoked returns true if the given public key has been revoked.
func (r *RevocationRegistry) IsRevoked(pubkey ed25519.PublicKey) bool {
	key := hex.EncodeToString(pubkey)

	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.revoked[key]
	return ok
}

// All returns a snapshot of all revocation records in the registry.
func (r *RevocationRegistry) All() []*RevocationRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*RevocationRecord, 0, len(r.revoked))
	for _, rec := range r.revoked {
		out = append(out, rec)
	}
	return out
}
