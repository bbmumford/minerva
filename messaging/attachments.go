/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * attachments.go — large-payload handling for the messaging subsystem.
 * Attachments are content-addressed, ChaCha20-Poly1305 encrypted blobs
 * stored in an external BlobStore; the encryption key rides inside the
 * E2E-encrypted Message body alongside the CID so only the intended
 * recipients can decrypt.
 *
 * The BlobStore interface declared here is the Session-B-harmonised
 * shape: ctx on every method plus Delete + Size. It matches
 * ledger.ContextBlobStore exactly so a value satisfying either can be
 * passed in interchangeably; the legacy ledger.BlobStore (no ctx) can be
 * adapted via ledger.NewBlobStoreAdapter.
 */
package messaging

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// BlobStore is the interface Minerva needs from a content-addressed blob
// backend. Identical to ledger.ContextBlobStore so any implementation
// satisfies both packages without re-wiring. Legacy (no-ctx)
// ledger.BlobStore callers can be adapted via ledger.NewBlobStoreAdapter.
type BlobStore interface {
	Put(ctx context.Context, data []byte) (cid string, err error)
	Get(ctx context.Context, cid string) ([]byte, error)
	Has(ctx context.Context, cid string) (bool, error)
	Delete(ctx context.Context, cid string) error
	Size(ctx context.Context) (int64, error)
}

// ErrAttachmentNotFound is returned when FetchBlob cannot locate the
// encrypted blob in the store.
var ErrAttachmentNotFound = errors.New("messaging: attachment blob not found")

// ErrAttachmentKeyMissing is returned when the Message body did not carry
// an encryption key for the attachment.
var ErrAttachmentKeyMissing = errors.New("messaging: attachment encryption key missing")

// maxAttachmentSize caps the plaintext attachment size at 25 MiB so a
// misbehaving peer cannot exhaust memory. Callers may wrap with their
// own tighter limits.
const maxAttachmentSize = 25 * 1024 * 1024

// Attachment is the message-embedded reference to a content-addressed,
// encrypted blob in the mesh blob store.
type Attachment struct {
	// CID is the content-addressable hash of the *plaintext* bytes,
	// used so callers can deduplicate across messages. It is encoded
	// as an IPFS-style base32 multihash prefix + SHA-256 digest.
	CID string `json:"cid"`

	// MimeType is a best-effort content type hint (not authoritative).
	MimeType string `json:"mimeType"`

	// Filename is a suggestive display name; not validated.
	Filename string `json:"filename,omitempty"`

	// Size is the plaintext size in bytes.
	Size int64 `json:"size"`

	// EncryptedCID is the hash of the encrypted blob — this is what
	// peers actually fetch from the mesh blob store.
	EncryptedCID string `json:"encryptedCid"`

	// EncryptionKey is the per-attachment ChaCha20-Poly1305 key. It is
	// carried inside the end-to-end encrypted Message body so only the
	// intended recipient(s) can decrypt the blob.
	EncryptionKey []byte `json:"encryptionKey"`
}

// AttachmentBody is the canonical JSON shape of a Message body that
// carries attachments. The text may be empty for attachment-only sends.
//
//	{
//	  "text": "Check this out",
//	  "attachments": [{"cid":"bafy...", ...}]
//	}
type AttachmentBody struct {
	Text        string       `json:"text"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

// MarshalAttachmentBody is a convenience wrapper for callers building an
// attachment-bearing message body.
func MarshalAttachmentBody(text string, attachments []Attachment) ([]byte, error) {
	return json.Marshal(AttachmentBody{Text: text, Attachments: attachments})
}

// UnmarshalAttachmentBody parses a JSON body produced by
// MarshalAttachmentBody. Returns a zero-value body on empty input.
func UnmarshalAttachmentBody(data []byte) (AttachmentBody, error) {
	var b AttachmentBody
	if len(data) == 0 {
		return b, nil
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("messaging: decode attachment body: %w", err)
	}
	return b, nil
}

// multihashCID returns an IPFS-style base32 multihash ("b" + base32(0x12
// 0x20 || sha256(data))) for the given data. 0x12 is the SHA2-256 code
// and 0x20 is the 32-byte length in the multihash varint encoding.
func multihashCID(data []byte) string {
	sum := sha256.Sum256(data)
	mh := make([]byte, 0, 2+32)
	mh = append(mh, 0x12, 0x20)
	mh = append(mh, sum[:]...)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mh)
	return "b" + enc
}

// attachmentStoreRef is the lazy hook that connects the attachment API to
// the blob backend. Kept package-level so AttachBlob / FetchBlob work
// without needing a per-service receiver; the Messenger API wires in
// later (Session B).
type attachmentStoreRef struct {
	mu    sync.RWMutex
	store BlobStore
}

var attachmentRef attachmentStoreRef

// SetBlobStore wires the blob backend used by AttachBlob / FetchBlob.
// Call once during SDK init. Passing nil disables attachments.
func SetBlobStore(store BlobStore) {
	attachmentRef.mu.Lock()
	attachmentRef.store = store
	attachmentRef.mu.Unlock()
}

// currentBlobStore returns the wired blob store, or nil.
func currentBlobStore() BlobStore {
	attachmentRef.mu.RLock()
	defer attachmentRef.mu.RUnlock()
	return attachmentRef.store
}

// AttachBlob uploads `content` to the blob store. It:
//
//  1. Generates a fresh 32-byte ChaCha20-Poly1305 key.
//  2. Encrypts the plaintext with a random 12-byte nonce (the nonce is
//     prepended to the ciphertext so the fetcher can read it back).
//  3. Writes the encrypted bytes to the blob store; the store's Put
//     returns the CID of the *encrypted* bytes (EncryptedCID).
//  4. Returns an Attachment with CID (plaintext hash), EncryptedCID,
//     size, mime, filename, and the encryption key. The caller embeds
//     this value in a Message body (see MarshalAttachmentBody) and sends
//     the body through the normal encrypt path, so the key itself is
//     end-to-end encrypted alongside the rest of the message.
func AttachBlob(ctx context.Context, content []byte, mimeType, filename string) (*Attachment, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("messaging: attachment content is empty")
	}
	if int64(len(content)) > maxAttachmentSize {
		return nil, fmt.Errorf("messaging: attachment size %d exceeds max %d", len(content), maxAttachmentSize)
	}
	store := currentBlobStore()
	if store == nil {
		return nil, fmt.Errorf("messaging: no blob store configured (call SetBlobStore)")
	}

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("messaging: attachment keygen: %w", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("messaging: attachment aead init: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("messaging: attachment nonce: %w", err)
	}

	// Associated data binds the plaintext CID so a relay can't swap
	// ciphertexts between distinct attachments without invalidating
	// authentication.
	plainCID := multihashCID(content)
	ct := aead.Seal(nil, nonce, content, []byte(plainCID))

	// Blob payload = nonce || ciphertext. The fetcher splits them back
	// apart using aead.NonceSize() before calling Open.
	blob := make([]byte, 0, len(nonce)+len(ct))
	blob = append(blob, nonce...)
	blob = append(blob, ct...)

	encCID, err := store.Put(ctx, blob)
	if err != nil {
		return nil, fmt.Errorf("messaging: attachment store put: %w", err)
	}

	return &Attachment{
		CID:           plainCID,
		MimeType:      mimeType,
		Filename:      filename,
		Size:          int64(len(content)),
		EncryptedCID:  encCID,
		EncryptionKey: key,
	}, nil
}

// FetchBlob retrieves and decrypts an attachment. The caller must pass
// the Attachment value extracted from the decrypted Message body so that
// EncryptionKey is available.
func FetchBlob(ctx context.Context, att Attachment) ([]byte, error) {
	if len(att.EncryptionKey) != chacha20poly1305.KeySize {
		return nil, ErrAttachmentKeyMissing
	}
	store := currentBlobStore()
	if store == nil {
		return nil, fmt.Errorf("messaging: no blob store configured")
	}
	has, err := store.Has(ctx, att.EncryptedCID)
	if err != nil {
		return nil, fmt.Errorf("messaging: attachment has: %w", err)
	}
	if !has {
		return nil, ErrAttachmentNotFound
	}
	blob, err := store.Get(ctx, att.EncryptedCID)
	if err != nil {
		return nil, fmt.Errorf("messaging: attachment get: %w", err)
	}

	aead, err := chacha20poly1305.New(att.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("messaging: attachment aead: %w", err)
	}
	if len(blob) < aead.NonceSize() {
		return nil, fmt.Errorf("messaging: attachment blob truncated")
	}
	nonce := blob[:aead.NonceSize()]
	ct := blob[aead.NonceSize():]

	// Bind the plaintext CID as AAD (mirrors AttachBlob).
	plain, err := aead.Open(nil, nonce, ct, []byte(att.CID))
	if err != nil {
		return nil, fmt.Errorf("messaging: attachment decrypt: %w", err)
	}

	// Defence-in-depth: verify that the decrypted bytes really do hash
	// to the claimed CID, so a malicious sender cannot lie about the
	// plaintext hash.
	if multihashCID(plain) != att.CID {
		return nil, fmt.Errorf("messaging: attachment CID mismatch")
	}
	return plain, nil
}
