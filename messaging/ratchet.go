/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package messaging

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Double-ratchet protocol version. Wire-compatible peers advertise this
// value in their signed profile; mismatched peers fall back to Version 0
// (NaCl box).
const (
	ratchetVersion byte = 1

	// maxSkippedKeys caps skipped message keys cached per receiving chain
	// to prevent memory blowup from hostile peers or gap storms.
	maxSkippedKeys = 100

	// kdfInfoRootChain / kdfInfoChainKey are HKDF "info" tags separating
	// the root-ratchet KDF from the per-message symmetric ratchet.
	// The "mercury/ratchet/*" byte strings are preserved verbatim so this
	// package remains wire-compatible with Mercury during Session A -> C.
	kdfInfoRootChain = "mercury/ratchet/root"
	kdfInfoChainKey  = "mercury/ratchet/chain"
	kdfInfoMsgKey    = "mercury/ratchet/msg"
)

// Sentinel errors exposed to callers.
var (
	ErrRatchetSessionMissing = errors.New("messaging: no ratchet session for peer")
	ErrRatchetDecryptFailed  = errors.New("messaging: ratchet decrypt failed")
	ErrRatchetDowngrade      = errors.New("messaging: peer does not support ratchet (Version 0 fallback)")
)

// RatchetSession is per-peer state for the double ratchet protocol.
//
// State machine (high level):
//
//  1. Root key RK is seeded from the initial DH shared secret (identity key
//     ECDH) when the session is first established.
//  2. Each "turn" of the conversation triggers a DH ratchet: the sending
//     party rotates its X25519 keypair, performs DH with the latest peer
//     public key, and feeds the result into HKDF(RK) to derive a new RK
//     and a new sending chain key CKs.
//  3. Each message within a turn advances the symmetric ratchet: the
//     sending chain key is stepped via HMAC-SHA256 to produce the next
//     message key and the next chain key.
//
// The ratchet provides forward secrecy: deriving a single message key does
// not reveal prior message keys, because chain advance is one-way
// (HMAC-SHA256 is a PRF).
type RatchetSession struct {
	mu sync.Mutex

	// selfPriv / selfPub is our current X25519 ratchet keypair. It is
	// rotated every time we start a new sending turn (i.e. we send a
	// message after receiving one from the peer).
	selfPriv [32]byte
	selfPub  [32]byte

	// remotePub is the peer's most recent X25519 ratchet public key.
	remotePub    [32]byte
	remotePubSet bool

	// rootKey is the current root-chain key.
	rootKey [32]byte

	// sendChain / recvChain are the sending and receiving symmetric
	// ratchet chain keys derived from the root chain.
	sendChain    [32]byte
	sendChainSet bool
	recvChain    [32]byte
	recvChainSet bool

	// sendN / recvN are message counters within the current turn.
	sendN uint32
	recvN uint32

	// prevSendN records how many messages we sent in the previous
	// sending chain. Transmitted in each message header so that the
	// receiver can compute how many skipped keys to cache when it sees
	// a new remote ratchet public key.
	prevSendN uint32

	// skipped caches decryption keys for messages that arrived out of
	// order. Key is "remoteRatchetPub:msgIndex" -> message key. Bounded
	// to maxSkippedKeys.
	skipped     map[skippedKey][32]byte
	skippedFIFO []skippedKey
}

// skippedKey identifies a skipped message key by remote ratchet public key
// and message counter.
type skippedKey struct {
	pub [32]byte
	n   uint32
}

// ratchetHeader is prepended to every ciphertext so the receiver can
// identify which ratchet key to use and whether a DH ratchet step is due.
type ratchetHeader struct {
	// Pub is the sender's current ratchet X25519 public key.
	Pub [32]byte
	// PrevN is the number of messages the sender transmitted in the
	// previous sending chain (used for skipped-key reconstruction).
	PrevN uint32
	// N is the counter of this message within the current sending chain.
	N uint32
}

const ratchetHeaderLen = 32 + 4 + 4 // 40 bytes

func (h *ratchetHeader) marshal() []byte {
	out := make([]byte, ratchetHeaderLen)
	copy(out[0:32], h.Pub[:])
	binary.BigEndian.PutUint32(out[32:36], h.PrevN)
	binary.BigEndian.PutUint32(out[36:40], h.N)
	return out
}

func parseRatchetHeader(buf []byte) (*ratchetHeader, error) {
	if len(buf) < ratchetHeaderLen {
		return nil, fmt.Errorf("messaging: ratchet header too short: %d bytes", len(buf))
	}
	h := &ratchetHeader{}
	copy(h.Pub[:], buf[0:32])
	h.PrevN = binary.BigEndian.Uint32(buf[32:36])
	h.N = binary.BigEndian.Uint32(buf[36:40])
	return h, nil
}

// NewRatchetSessionInitiator creates a new ratchet session for the party
// that sends the first message. seed is the initial root-key seed derived
// from the long-term identity key ECDH (typically via sharedSecret in
// ecdh.go). remoteIdentityPub is the peer's Ed25519 identity public key,
// converted internally to X25519 so we have a valid "remote public" before
// our peer has rotated keys.
func NewRatchetSessionInitiator(seed []byte, remoteIdentityPub ed25519.PublicKey) (*RatchetSession, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("messaging: ratchet requires non-empty shared secret")
	}
	remoteX, err := ed25519PublicToX25519(remoteIdentityPub)
	if err != nil {
		return nil, fmt.Errorf("messaging: ratchet init convert remote key: %w", err)
	}

	s := &RatchetSession{
		skipped: make(map[skippedKey][32]byte),
	}
	copy(s.remotePub[:], remoteX[:])
	s.remotePubSet = true

	// Seed root key from the shared secret.
	rk := sha256.Sum256(append([]byte("mercury/ratchet/seed"), seed...))
	s.rootKey = rk

	// Generate our first ratchet keypair.
	if err := s.rotateSelfKeys(); err != nil {
		return nil, err
	}

	// Perform the first DH ratchet step to derive our initial sendChain.
	if err := s.dhRatchetSend(); err != nil {
		return nil, err
	}

	return s, nil
}

// NewRatchetSessionResponder creates a new ratchet session for the party
// that receives the first message. seed must match the initiator's.
// ownIdentityPriv is the responder's Ed25519 long-term private key — its
// X25519 form becomes the responder's initial ratchet keypair so the
// initiator's first send-DH (which used the responder's identity public
// key as the peer pub) will yield a matching value when the responder
// computes the receive-DH.
func NewRatchetSessionResponder(seed []byte, ownIdentityPriv ed25519.PrivateKey) (*RatchetSession, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("messaging: ratchet requires non-empty shared secret")
	}
	s := &RatchetSession{
		skipped: make(map[skippedKey][32]byte),
	}
	rk := sha256.Sum256(append([]byte("mercury/ratchet/seed"), seed...))
	s.rootKey = rk

	// Seed selfPriv/selfPub from our identity key so the initiator's
	// first DH (against our identity X25519 pub) matches what we'll
	// compute in dhRatchetRecv.
	xpriv, err := ed25519PrivateToX25519(ownIdentityPriv)
	if err != nil {
		return nil, fmt.Errorf("messaging: ratchet responder key: %w", err)
	}
	copy(s.selfPriv[:], xpriv[:])
	pub, err := curve25519.X25519(s.selfPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("messaging: ratchet responder pub: %w", err)
	}
	copy(s.selfPub[:], pub)
	return s, nil
}

// rotateSelfKeys generates a fresh X25519 ratchet keypair. Caller must
// hold s.mu.
func (s *RatchetSession) rotateSelfKeys() error {
	if _, err := io.ReadFull(rand.Reader, s.selfPriv[:]); err != nil {
		return fmt.Errorf("messaging: ratchet keygen: %w", err)
	}
	// Clamp per RFC 7748.
	s.selfPriv[0] &= 248
	s.selfPriv[31] &= 127
	s.selfPriv[31] |= 64

	pub, err := curve25519.X25519(s.selfPriv[:], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("messaging: ratchet derive pub: %w", err)
	}
	copy(s.selfPub[:], pub)
	return nil
}

// dhRatchetSend performs a DH step using our current selfPriv and the
// peer's current remotePub, feeding the result into HKDF(rootKey) to
// derive a new rootKey and sendChain. Caller must hold s.mu.
func (s *RatchetSession) dhRatchetSend() error {
	if !s.remotePubSet {
		return fmt.Errorf("messaging: ratchet send DH: remote pub unset")
	}
	shared, err := curve25519.X25519(s.selfPriv[:], s.remotePub[:])
	if err != nil {
		return fmt.Errorf("messaging: ratchet send DH: %w", err)
	}
	newRoot, newChain, err := kdfRootStep(s.rootKey[:], shared)
	if err != nil {
		return err
	}
	s.rootKey = newRoot
	s.sendChain = newChain
	s.sendChainSet = true
	s.prevSendN = s.sendN
	s.sendN = 0
	return nil
}

// dhRatchetRecv advances the receive chain in response to a new remote
// ratchet public key. Caller must hold s.mu.
func (s *RatchetSession) dhRatchetRecv(remotePub [32]byte) error {
	shared, err := curve25519.X25519(s.selfPriv[:], remotePub[:])
	if err != nil {
		return fmt.Errorf("messaging: ratchet recv DH: %w", err)
	}
	newRoot, newChain, err := kdfRootStep(s.rootKey[:], shared)
	if err != nil {
		return err
	}
	s.rootKey = newRoot
	s.recvChain = newChain
	s.recvChainSet = true
	s.recvN = 0
	s.remotePub = remotePub
	s.remotePubSet = true
	return nil
}

// kdfRootStep derives a (newRootKey, chainKey) pair from the previous
// rootKey and a DH output using HKDF-SHA256.
func kdfRootStep(rootKey, dhOutput []byte) ([32]byte, [32]byte, error) {
	var outRoot, outChain [32]byte
	r := hkdf.New(sha256.New, dhOutput, rootKey, []byte(kdfInfoRootChain))
	if _, err := io.ReadFull(r, outRoot[:]); err != nil {
		return outRoot, outChain, fmt.Errorf("messaging: hkdf root: %w", err)
	}
	if _, err := io.ReadFull(r, outChain[:]); err != nil {
		return outRoot, outChain, fmt.Errorf("messaging: hkdf chain: %w", err)
	}
	return outRoot, outChain, nil
}

// advanceChain advances a symmetric chain key one step and returns the
// resulting (messageKey, nextChainKey). Uses HMAC-SHA256 as a PRF, which
// is sufficient for forward secrecy: given the chain key at step N, an
// attacker cannot recover the chain key at step N-1.
func advanceChain(chainKey [32]byte) (msgKey, nextChain [32]byte) {
	// msgKey = HMAC(chainKey, 0x01)
	m := hmac.New(sha256.New, chainKey[:])
	m.Write([]byte{0x01})
	copy(msgKey[:], m.Sum(nil))
	// nextChain = HMAC(chainKey, 0x02)
	m = hmac.New(sha256.New, chainKey[:])
	m.Write([]byte{0x02})
	copy(nextChain[:], m.Sum(nil))
	return
}

// deriveMsgKey expands a 32-byte symmetric-ratchet output into a
// ChaCha20-Poly1305 key + 12-byte nonce pair using HKDF.
func deriveMsgKey(msgRoot [32]byte) (key [32]byte, nonce [12]byte, err error) {
	r := hkdf.New(sha256.New, msgRoot[:], nil, []byte(kdfInfoMsgKey))
	if _, err = io.ReadFull(r, key[:]); err != nil {
		return
	}
	if _, err = io.ReadFull(r, nonce[:]); err != nil {
		return
	}
	return
}

// EncryptRatchet encrypts plaintext under the session's sending chain and
// returns a self-contained ciphertext: ratchetHeader || AEAD ciphertext.
// Callers frame this value however their transport requires; the envelope
// is opaque to the rest of the messaging package.
func EncryptRatchet(plaintext []byte, session *RatchetSession) ([]byte, error) {
	if session == nil {
		return nil, ErrRatchetSessionMissing
	}
	session.mu.Lock()
	defer session.mu.Unlock()

	if !session.sendChainSet {
		// Responder is being asked to send for the first time after
		// having received. Rotate keys and do a DH send ratchet.
		if err := session.rotateSelfKeys(); err != nil {
			return nil, err
		}
		if err := session.dhRatchetSend(); err != nil {
			return nil, err
		}
	}

	msgRoot, next := advanceChain(session.sendChain)
	session.sendChain = next

	header := &ratchetHeader{
		Pub:   session.selfPub,
		PrevN: session.prevSendN,
		N:     session.sendN,
	}
	session.sendN++

	key, nonce, err := deriveMsgKey(msgRoot)
	if err != nil {
		return nil, fmt.Errorf("messaging: derive msg key: %w", err)
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("messaging: chacha20poly1305: %w", err)
	}
	hdrBytes := header.marshal()
	ct := aead.Seal(nil, nonce[:], plaintext, hdrBytes)

	out := make([]byte, 0, len(hdrBytes)+len(ct))
	out = append(out, hdrBytes...)
	out = append(out, ct...)
	return out, nil
}

// DecryptRatchet reverses EncryptRatchet. Handles out-of-order messages
// by caching skipped message keys up to maxSkippedKeys per chain.
func DecryptRatchet(ciphertext []byte, session *RatchetSession) ([]byte, error) {
	if session == nil {
		return nil, ErrRatchetSessionMissing
	}
	if len(ciphertext) < ratchetHeaderLen {
		return nil, fmt.Errorf("messaging: ratchet ciphertext too short")
	}
	header, err := parseRatchetHeader(ciphertext[:ratchetHeaderLen])
	if err != nil {
		return nil, err
	}
	body := ciphertext[ratchetHeaderLen:]
	hdrBytes := ciphertext[:ratchetHeaderLen]

	session.mu.Lock()
	defer session.mu.Unlock()

	// Try the skipped-keys cache first: maybe this is a late arrival.
	key := skippedKey{pub: header.Pub, n: header.N}
	if mk, ok := session.skipped[key]; ok {
		pt, err := openMsgRoot(mk, hdrBytes, body)
		if err != nil {
			return nil, err
		}
		delete(session.skipped, key)
		session.removeSkippedFIFO(key)
		return pt, nil
	}

	// If the remote has rotated its ratchet key, we need a DH ratchet
	// step. Cache any keys we'd skip in the old receive chain.
	if !session.remotePubSet || session.remotePub != header.Pub {
		if session.recvChainSet {
			if err := session.stashSkippedRecv(session.remotePub, header.PrevN); err != nil {
				return nil, err
			}
		}
		if err := session.dhRatchetRecv(header.Pub); err != nil {
			return nil, err
		}
		// Rotate our sending keys so the next outbound message starts
		// a new sending chain.
		if err := session.rotateSelfKeys(); err != nil {
			return nil, err
		}
		if err := session.dhRatchetSend(); err != nil {
			return nil, err
		}
	}

	// Same chain — stash any skipped keys up to header.N, then derive.
	if err := session.stashSkippedRecv(header.Pub, header.N); err != nil {
		return nil, err
	}

	msgRoot, next := advanceChain(session.recvChain)
	session.recvChain = next
	session.recvN++

	pt, err := openMsgRoot(msgRoot, hdrBytes, body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRatchetDecryptFailed, err)
	}
	return pt, nil
}

// openMsgRoot derives the AEAD key+nonce from a 32-byte chain-advance
// result (msgRoot) and opens the ciphertext with the header as AAD.
// Used both for fresh chain steps and skipped-key cache hits: both store
// the same 32-byte chain-advance output.
func openMsgRoot(msgRoot [32]byte, aad, body []byte) ([]byte, error) {
	key, nonce, err := deriveMsgKey(msgRoot)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce[:], body, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRatchetDecryptFailed, err)
	}
	return pt, nil
}

// stashSkippedRecv advances the receive chain up to (but not including)
// targetN, caching each derived message key in s.skipped. Caller must
// hold s.mu.
func (s *RatchetSession) stashSkippedRecv(pub [32]byte, targetN uint32) error {
	if !s.recvChainSet {
		return nil
	}
	if targetN <= s.recvN {
		return nil
	}
	gap := targetN - s.recvN
	if gap > maxSkippedKeys {
		return fmt.Errorf("messaging: ratchet skipped-gap %d exceeds max %d", gap, maxSkippedKeys)
	}
	for i := s.recvN; i < targetN; i++ {
		msgRoot, next := advanceChain(s.recvChain)
		s.recvChain = next
		k := skippedKey{pub: pub, n: i}
		s.skipped[k] = msgRoot
		s.skippedFIFO = append(s.skippedFIFO, k)
		// Evict oldest if we're over cap.
		for len(s.skippedFIFO) > maxSkippedKeys {
			old := s.skippedFIFO[0]
			s.skippedFIFO = s.skippedFIFO[1:]
			delete(s.skipped, old)
		}
	}
	s.recvN = targetN
	return nil
}

// removeSkippedFIFO drops the given key from the FIFO tracker. Linear but
// maxSkippedKeys is small.
func (s *RatchetSession) removeSkippedFIFO(target skippedKey) {
	for i, k := range s.skippedFIFO {
		if k == target {
			s.skippedFIFO = append(s.skippedFIFO[:i], s.skippedFIFO[i+1:]...)
			return
		}
	}
}

// RatchetRegistry tracks per-peer sessions and peer capability flags
// (i.e. whether each peer advertised ratchet support). Sessions are keyed
// by PeerID (lowercase hex of the peer's Ed25519 identity pub); callers
// with raw bytes should use PeerIDFromBytes to key in.
type RatchetRegistry struct {
	mu            sync.RWMutex
	sessions      map[PeerID]*RatchetSession
	supportsRatch map[PeerID]bool
}

// NewRatchetRegistry returns an empty registry.
func NewRatchetRegistry() *RatchetRegistry {
	return &RatchetRegistry{
		sessions:      make(map[PeerID]*RatchetSession),
		supportsRatch: make(map[PeerID]bool),
	}
}

// AdvertiseCapability records whether a peer supports Version 1 (ratchet).
// Called by the profile-ingest path when a signed profile is received.
func (r *RatchetRegistry) AdvertiseCapability(peer PeerID, supportsRatchet bool) {
	r.mu.Lock()
	r.supportsRatch[peer] = supportsRatchet
	r.mu.Unlock()
}

// SupportsRatchet reports whether the peer advertised Version 1.
func (r *RatchetRegistry) SupportsRatchet(peer PeerID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.supportsRatch[peer]
}

// Session returns the stored session for a peer, or nil if absent.
func (r *RatchetRegistry) Session(peer PeerID) *RatchetSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[peer]
}

// InstallSession stores a newly bootstrapped session.
func (r *RatchetRegistry) InstallSession(peer PeerID, s *RatchetSession) {
	r.mu.Lock()
	r.sessions[peer] = s
	r.mu.Unlock()
}

// DropSession removes a session (e.g. on session reset / peer re-key).
func (r *RatchetRegistry) DropSession(peer PeerID) {
	r.mu.Lock()
	delete(r.sessions, peer)
	r.mu.Unlock()
}

// BootstrapSession establishes an initial ratchet session for a peer,
// using long-term identity ECDH as the shared secret seed. initiator=true
// for the party that will send the first ratchet message.
func (r *RatchetRegistry) BootstrapSession(peer PeerID, ourPriv ed25519.PrivateKey, theirPub ed25519.PublicKey, initiator bool) (*RatchetSession, error) {
	shared, err := sharedSecret(ourPriv, theirPub)
	if err != nil {
		return nil, fmt.Errorf("messaging: bootstrap session: %w", err)
	}
	var sess *RatchetSession
	if initiator {
		sess, err = NewRatchetSessionInitiator(shared, theirPub)
	} else {
		sess, err = NewRatchetSessionResponder(shared, ourPriv)
	}
	if err != nil {
		return nil, err
	}
	r.InstallSession(peer, sess)
	return sess, nil
}
