/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package messaging

import (
	"bytes"
	"context"
	"crypto/rand"
	"sync"
	"testing"
)

// memBlobStore implements BlobStore using an in-memory map.
type memBlobStore struct {
	mu    sync.RWMutex
	blobs map[string][]byte
}

func newMemBlobStore() *memBlobStore {
	return &memBlobStore{blobs: make(map[string][]byte)}
}

func (s *memBlobStore) Put(_ context.Context, data []byte) (string, error) {
	cid := multihashCID(data)
	cp := make([]byte, len(data))
	copy(cp, data)
	s.mu.Lock()
	s.blobs[cid] = cp
	s.mu.Unlock()
	return cid, nil
}

func (s *memBlobStore) Get(_ context.Context, cid string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.blobs[cid]
	if !ok {
		return nil, ErrAttachmentNotFound
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp, nil
}

func (s *memBlobStore) Has(_ context.Context, cid string) (bool, error) {
	s.mu.RLock()
	_, ok := s.blobs[cid]
	s.mu.RUnlock()
	return ok, nil
}

func (s *memBlobStore) Delete(_ context.Context, cid string) error {
	s.mu.Lock()
	delete(s.blobs, cid)
	s.mu.Unlock()
	return nil
}

func (s *memBlobStore) Size(_ context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var total int64
	for _, b := range s.blobs {
		total += int64(len(b))
	}
	return total, nil
}

// withTestBlobStore installs a fresh store for the duration of a test
// and returns a cleanup func restoring the prior binding.
func withTestBlobStore(t *testing.T) *memBlobStore {
	t.Helper()
	prev := currentBlobStore()
	s := newMemBlobStore()
	SetBlobStore(s)
	t.Cleanup(func() { SetBlobStore(prev) })
	return s
}

func TestAttachment_Roundtrip(t *testing.T) {
	_ = withTestBlobStore(t)
	ctx := context.Background()

	original := []byte("hello attachment world")
	att, err := AttachBlob(ctx, original, "text/plain", "note.txt")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if att.EncryptedCID == "" || att.CID == "" {
		t.Fatalf("missing CID fields")
	}
	if att.Size != int64(len(original)) {
		t.Fatalf("size = %d want %d", att.Size, len(original))
	}

	got, err := FetchBlob(ctx, *att)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestAttachment_LargeFile(t *testing.T) {
	withTestBlobStore(t)
	ctx := context.Background()

	big := make([]byte, 5*1024*1024)
	if _, err := rand.Read(big); err != nil {
		t.Fatalf("rand: %v", err)
	}
	att, err := AttachBlob(ctx, big, "application/octet-stream", "big.bin")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	got, err := FetchBlob(ctx, *att)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Fatalf("large roundtrip mismatch")
	}
}

func TestAttachment_MissingBlob(t *testing.T) {
	withTestBlobStore(t)
	ctx := context.Background()

	att, err := AttachBlob(ctx, []byte("data"), "text/plain", "")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	// Mutate the CID so the fetcher can't find it.
	att.EncryptedCID = "bogus"
	if _, err := FetchBlob(ctx, *att); err != ErrAttachmentNotFound {
		t.Fatalf("want ErrAttachmentNotFound, got %v", err)
	}
}

func TestAttachment_WrongKeyFails(t *testing.T) {
	withTestBlobStore(t)
	ctx := context.Background()

	att, err := AttachBlob(ctx, []byte("secret"), "text/plain", "")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	// Swap the key for a random one.
	badKey := make([]byte, len(att.EncryptionKey))
	if _, err := rand.Read(badKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	att.EncryptionKey = badKey
	if _, err := FetchBlob(ctx, *att); err == nil {
		t.Fatalf("expected decrypt failure with wrong key")
	}
}

func TestAttachment_BodyMarshal(t *testing.T) {
	att := Attachment{
		CID:          "bafy123",
		MimeType:     "image/png",
		Size:         42,
		EncryptedCID: "bafy456",
	}
	data, err := MarshalAttachmentBody("caption", []Attachment{att})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b, err := UnmarshalAttachmentBody(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.Text != "caption" || len(b.Attachments) != 1 || b.Attachments[0].CID != "bafy123" {
		t.Fatalf("bad roundtrip: %+v", b)
	}
}
