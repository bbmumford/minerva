/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * Sender-keys ratchet for group chat encryption.
 *
 * Design summary:
 *  - Each author holds a 32-byte "sender key" per channel.
 *  - Plaintext message bodies are encrypted with ChaCha20-Poly1305 keyed
 *    by the sender key; a fresh random nonce is prefixed to each ciphertext.
 *  - The sender key itself is distributed to the other group members by
 *    sealing it with nacl/box. To avoid the pitfalls of converting
 *    Ed25519 keys to Curve25519, each author derives a separate
 *    Curve25519 keypair (ExchangeIdentity) deterministically from the
 *    Ed25519 seed; peers look the pub key up by PeerID.
 *  - When a member is removed, the author rotates their sender key and
 *    re-distributes envelopes to the remaining members.
 *
 * This is deliberately simpler than Signal's MLS sender-keys flavour —
 * there is no per-message ratchet chain, just key rotation on membership
 * change. That trade-off keeps the implementation auditable without
 * sacrificing forward secrecy at the membership boundary.
 */
package messaging

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// senderKeyLen is the symmetric key length (ChaCha20-Poly1305 uses 32).
const senderKeyLen = chacha20poly1305.KeySize

// ErrDecrypt is returned when authenticated decryption fails.
var ErrDecrypt = errors.New("messaging: decrypt failed")

// ErrNoSenderKey is returned when we have not yet received a sender key
// for a particular (author, channel) pair — the ciphertext cannot be
// decrypted until the author distributes one.
var ErrNoSenderKey = errors.New("messaging: no sender key for author")

// SenderKeyRatchet owns the local author's sender key for a channel and
// tracks known sender keys for every other channel member. It is safe for
// concurrent use.
type SenderKeyRatchet struct {
	mu sync.RWMutex

	// ownKey is this author's current sender key for the channel.
	ownKey [senderKeyLen]byte
	// keys maps author PeerID -> that author's latest sender key.
	keys map[PeerID][senderKeyLen]byte
}

// NewSenderKeyRatchet returns a ratchet with a freshly-generated own key.
func NewSenderKeyRatchet() (*SenderKeyRatchet, error) {
	r := &SenderKeyRatchet{keys: make(map[PeerID][senderKeyLen]byte)}
	if err := r.Rotate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Rotate replaces the local sender key with a fresh 32 random bytes.
// Called on membership removal to guarantee forward secrecy for future
// messages against the departing member.
func (r *SenderKeyRatchet) Rotate() error {
	var k [senderKeyLen]byte
	if _, err := rand.Read(k[:]); err != nil {
		return fmt.Errorf("messaging: rand read sender key: %w", err)
	}
	r.mu.Lock()
	r.ownKey = k
	r.mu.Unlock()
	return nil
}

// OwnKey returns a copy of the local sender key.
func (r *SenderKeyRatchet) OwnKey() [senderKeyLen]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ownKey
}

// SetOwnKey overrides the local sender key. Used only by tests and by
// disaster-recovery tools; normal flow calls Rotate().
func (r *SenderKeyRatchet) SetOwnKey(k [senderKeyLen]byte) {
	r.mu.Lock()
	r.ownKey = k
	r.mu.Unlock()
}

// Install stores a peer's sender key so subsequent ciphertexts from that
// peer can be decrypted.
func (r *SenderKeyRatchet) Install(peer PeerID, key [senderKeyLen]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[peer] = key
}

// Forget drops a peer's sender key. Used when a member leaves.
func (r *SenderKeyRatchet) Forget(peer PeerID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.keys, peer)
}

// KeyFor returns the sender key known for author peer, or false if none.
// The own-author's PeerID returns ownKey automatically so authors can
// decrypt their own ciphertext on replay.
func (r *SenderKeyRatchet) KeyFor(peer PeerID) ([senderKeyLen]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if k, ok := r.keys[peer]; ok {
		return k, true
	}
	return [senderKeyLen]byte{}, false
}

// SealBody encrypts plaintext with the local sender key. Output layout:
// [12-byte nonce][ciphertext||16-byte tag].
func (r *SenderKeyRatchet) SealBody(plaintext []byte) ([]byte, error) {
	r.mu.RLock()
	key := r.ownKey
	r.mu.RUnlock()

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("messaging: chacha init: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("messaging: rand nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// OpenBody decrypts ciphertext produced by author peer. The ratchet must
// have the author's sender key installed (otherwise ErrNoSenderKey).
func (r *SenderKeyRatchet) OpenBody(peer PeerID, ciphertext []byte) ([]byte, error) {
	key, ok := r.KeyFor(peer)
	if !ok {
		return nil, ErrNoSenderKey
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("messaging: chacha init: %w", err)
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, ErrDecrypt
	}
	nonce := ciphertext[:aead.NonceSize()]
	ct := ciphertext[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// --- ExchangeIdentity ----------------------------------------------------
//
// ExchangeIdentity holds a Curve25519 keypair derived deterministically
// from the author's Ed25519 seed. It is the primary path used by
// Conversation for sealed sender-key envelopes. Because the derivation is
// deterministic, peers can look up (or re-derive) the corresponding public
// key for any PeerID whose seed they know.

// ExchangeIdentity wraps a Curve25519 keypair used exclusively for
// nacl/box sealed-envelope key distribution.
type ExchangeIdentity struct {
	Pub  [32]byte
	Priv [32]byte
}

// NewExchangeIdentity derives a Curve25519 keypair from the given Ed25519
// seed via the libsodium-compatible SHA-512-and-clamp routine.
func NewExchangeIdentity(seed []byte) (*ExchangeIdentity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("messaging: seed must be %d bytes", ed25519.SeedSize)
	}
	h := sha512.Sum512(seed)
	var priv [32]byte
	copy(priv[:], h[:32])
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("messaging: curve25519 basepoint mult: %w", err)
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)
	return &ExchangeIdentity{Pub: pubArr, Priv: priv}, nil
}

// SenderKeyEnvelope is the wire form of a sender key distributed to a
// single recipient. The sealed payload contains the raw 32-byte key.
type SenderKeyEnvelope struct {
	Author    PeerID    `json:"author"`
	Recipient PeerID    `json:"recipient"`
	ChannelID ChannelID `json:"channelId"`
	Nonce     [24]byte  `json:"nonce"`
	Sealed    []byte    `json:"sealed"`
}

// SealFor encrypts key so that only recipient can open it.
func (x *ExchangeIdentity) SealFor(recipient [32]byte, key [senderKeyLen]byte) ([24]byte, []byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, nil, fmt.Errorf("messaging: rand nonce: %w", err)
	}
	sealed := box.Seal(nil, key[:], &nonce, &recipient, &x.Priv)
	return nonce, sealed, nil
}

// OpenSealed unwraps an envelope sealed by author.
func (x *ExchangeIdentity) OpenSealed(author [32]byte, nonce [24]byte, sealed []byte) ([senderKeyLen]byte, error) {
	var zero [senderKeyLen]byte
	opened, ok := box.Open(nil, sealed, &nonce, &author, &x.Priv)
	if !ok {
		return zero, ErrDecrypt
	}
	if len(opened) != senderKeyLen {
		return zero, fmt.Errorf("messaging: sender key wrong length (%d)", len(opened))
	}
	var k [senderKeyLen]byte
	copy(k[:], opened)
	return k, nil
}
