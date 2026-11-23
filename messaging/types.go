/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * Messaging — core types shared across group / broadcast / presence /
 * receipt channels. The messaging subsystem is layered on top of Minerva's
 * CRDTs (ORSet, Sequence, LWWMap) and, optionally, a Whisper engine for
 * gossip fan-out. Every higher-level primitive reuses these types verbatim
 * so the SDK surface stays cohesive.
 */
package messaging

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ChannelID identifies a messaging channel (group, broadcast, presence,
// receipts). It is an arbitrary string chosen by the application; the SDK
// makes no attempt to interpret it beyond equality.
type ChannelID string

// PeerID is the Ed25519 public key of a peer, encoded as lowercase hex.
// Using hex (rather than raw bytes) keeps the type map-key friendly and
// lets it be passed through JSON / logs without escaping.
type PeerID string

// MessageID is a UUID v7 — a time-ordered identifier that embeds a
// millisecond wall-clock prefix. This gives messages a natural sort order
// even across peers whose clocks drift slightly, while the random suffix
// keeps collisions effectively impossible.
type MessageID string

// MessageKind discriminates the payload semantics of a Message. The body
// format depends on the kind: text is arbitrary bytes (potentially
// encrypted), attachments are CID + metadata, presence and receipt payloads
// are structured sub-types.
type MessageKind int

const (
	// KindText is a regular chat message. Body is UTF-8 text (plaintext for
	// broadcast channels, ChaCha20-Poly1305 ciphertext for group channels).
	KindText MessageKind = iota

	// KindAttachment carries a content-addressed blob reference plus
	// optional metadata (filename, mime, size).
	KindAttachment

	// KindPresence is a typing / online / away update. Body encodes the
	// state string; presence messages have short TTL and do not persist.
	KindPresence

	// KindReceipt is a read / delivery acknowledgement. Body encodes the
	// MessageID being acknowledged along with the reader's signature.
	KindReceipt

	// KindJoin announces a peer joined a channel. Body is empty.
	KindJoin

	// KindLeave announces a peer left a channel. Body is empty.
	KindLeave
)

// String returns the canonical name of the kind.
func (k MessageKind) String() string {
	switch k {
	case KindText:
		return "text"
	case KindAttachment:
		return "attachment"
	case KindPresence:
		return "presence"
	case KindReceipt:
		return "receipt"
	case KindJoin:
		return "join"
	case KindLeave:
		return "leave"
	default:
		return fmt.Sprintf("kind(%d)", int(k))
	}
}

// Message is the canonical envelope for every piece of content that flows
// through the messaging subsystem. It is designed to round-trip through
// JSON and CRDT deltas unchanged.
//
// Signature covers the tuple (ID || ChannelID || SentAt || Body || Kind)
// using the author's Ed25519 private key. Recipients verify against the
// author's published public key (peerID decoded from hex). Body is
// encrypted according to the channel's policy; signing happens over the
// ciphertext so peers can verify authorship without decrypting.
type Message struct {
	ID        MessageID   `json:"id"`
	ChannelID ChannelID   `json:"channelId"`
	Author    PeerID      `json:"author"`
	SentAt    time.Time   `json:"sentAt"`
	Body      []byte      `json:"body,omitempty"`
	Kind      MessageKind `json:"kind"`
	ReplyTo   MessageID   `json:"replyTo,omitempty"`
	EditOf    MessageID   `json:"editOf,omitempty"`
	Deleted   bool        `json:"deleted,omitempty"`
	Signature []byte      `json:"signature,omitempty"`
}

// ErrBadSignature is returned when a Message's signature fails verification.
var ErrBadSignature = errors.New("messaging: bad signature")

// ErrNoIdentity is returned when a messaging operation requires an author
// identity but none was supplied.
var ErrNoIdentity = errors.New("messaging: no identity configured")

// ErrChannelClosed is returned when a channel has been closed / left and
// further operations are rejected.
var ErrChannelClosed = errors.New("messaging: channel closed")

// ErrNotMember is returned from group operations when the author is not a
// recognised member of the channel.
var ErrNotMember = errors.New("messaging: not a member of channel")

// NewMessageID returns a freshly-generated UUID v7 wrapped as a
// MessageID. The first 48 bits are the current unix-millisecond
// timestamp; the remaining 74 bits are cryptographically-random. This is
// the RFC-9562 §5.7 layout, implemented inline so the package takes no
// third-party UUID dependency.
func NewMessageID() MessageID {
	var b [16]byte

	// Random fill first, then overwrite the structured bits.
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is catastrophic; panic is appropriate because
		// callers have no way to recover without entropy.
		panic(fmt.Sprintf("messaging: rand.Read: %v", err))
	}

	// 48-bit unix-millisecond timestamp in the leading bytes.
	ms := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(b[0:8], ms<<16|uint64(b[6])<<8|uint64(b[7]))

	// Version nibble: 7.
	b[6] = (b[6] & 0x0f) | 0x70
	// Variant bits: 10xx.
	b[8] = (b[8] & 0x3f) | 0x80

	// Canonical 8-4-4-4-12 formatting.
	out := make([]byte, 36)
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return MessageID(out)
}

// signingBytes returns the deterministic byte sequence over which an
// author's signature is computed. The format is intentionally simple:
// fixed-length binary fields followed by the body. It is *not* meant for
// human inspection — only for cryptographic verification.
func (m *Message) signingBytes() []byte {
	out := make([]byte, 0, 64+len(m.Body))
	out = append(out, []byte(m.ID)...)
	out = append(out, 0)
	out = append(out, []byte(m.ChannelID)...)
	out = append(out, 0)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(m.SentAt.UnixNano()))
	out = append(out, ts[:]...)
	out = append(out, byte(m.Kind))
	out = append(out, m.Body...)
	return out
}

// peerIDFromHex decodes a PeerID back to a 32-byte Ed25519 public key.
// Returns an error if the string is not valid hex or is the wrong length.
func peerIDFromHex(p PeerID) ([]byte, error) {
	raw, err := hex.DecodeString(string(p))
	if err != nil {
		return nil, fmt.Errorf("messaging: decode peerID: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("messaging: peerID wrong length (%d)", len(raw))
	}
	return raw, nil
}

// PeerIDFromBytes encodes a 32-byte Ed25519 public key into a PeerID.
func PeerIDFromBytes(pub []byte) PeerID {
	return PeerID(hex.EncodeToString(pub))
}
