/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package messaging

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// testRelayMessage builds a minimal Message suitable for buffering. The
// relay does not verify signatures (that is the delivery layer's job),
// so we leave Signature empty and rely on unique IDs.
func testRelayMessage(id string, author PeerID) Message {
	return Message{
		ID:        MessageID(id),
		ChannelID: ChannelID("dm"),
		Author:    author,
		SentAt:    time.Now().UTC(),
		Body:      []byte("x"),
		Kind:      KindText,
	}
}

func TestBoundedMessageStore_RingBuffer(t *testing.T) {
	t.Parallel()
	s := NewBoundedMessageStore(3, time.Hour)

	sender := PeerID("sender")
	recipient := PeerID("recipient")

	now := time.Now()
	for i := 0; i < 5; i++ {
		m := testRelayMessage(fmt.Sprintf("msg-%d", i), sender)
		_, _ = s.Push(recipient, m, now)
	}
	msgs := s.Peek(recipient, now)
	if len(msgs) != 3 {
		t.Fatalf("want 3 buffered, got %d", len(msgs))
	}
	if msgs[0].ID != MessageID("msg-2") {
		t.Fatalf("oldest should be msg-2, got %s", msgs[0].ID)
	}
}

func TestBoundedMessageStore_TTL(t *testing.T) {
	t.Parallel()
	s := NewBoundedMessageStore(10, 50*time.Millisecond)

	m := testRelayMessage("old", PeerID("sender"))
	pastTime := time.Now().Add(-time.Hour)
	s.Push(PeerID("r"), m, pastTime)

	got := s.Peek(PeerID("r"), time.Now())
	if len(got) != 0 {
		t.Fatalf("expected ttl-dropped, got %d", len(got))
	}
}

func TestMessageRelay_BufferAndReplay(t *testing.T) {
	t.Parallel()
	relay := NewMessageRelay(nil, RelayRoleRelay, WithRelayMaxPerPeer(10))
	ctx := context.Background()

	sender := PeerID("sender")
	recipient := PeerID("recipient")

	for i := 0; i < 5; i++ {
		m := testRelayMessage(fmt.Sprintf("msg-%d", i), sender)
		ack, err := relay.BufferMessage(ctx, recipient, m)
		if err != nil {
			t.Fatalf("buffer %d: %v", i, err)
		}
		if ack.Overflow {
			t.Fatalf("unexpected overflow at msg %d", i)
		}
	}
	if n := relay.BufferedCount(recipient); n != 5 {
		t.Fatalf("want 5 buffered, got %d", n)
	}
	if n := relay.TotalBuffered(); n != 5 {
		t.Fatalf("want total 5, got %d", n)
	}
}

func TestMessageRelay_Overflow(t *testing.T) {
	t.Parallel()
	relay := NewMessageRelay(nil, RelayRoleRelay, WithRelayMaxPerPeer(3))
	ctx := context.Background()

	sender := PeerID("sender")
	recipient := PeerID("recipient")

	sawOverflow := false
	for i := 0; i < 4; i++ {
		m := testRelayMessage(fmt.Sprintf("msg-%d", i), sender)
		ack, err := relay.BufferMessage(ctx, recipient, m)
		if err != nil {
			t.Fatalf("buffer %d: %v", i, err)
		}
		if ack.Overflow {
			sawOverflow = true
		}
	}
	if !sawOverflow {
		t.Fatalf("expected overflow ack for 4th message")
	}
}

func TestMessageRelay_TTLExpiration(t *testing.T) {
	t.Parallel()
	relay := NewMessageRelay(nil, RelayRoleRelay, WithRelayTTL(10*time.Millisecond))
	ctx := context.Background()

	sender := PeerID("sender")
	recipient := PeerID("recipient")

	m := testRelayMessage("ttl-drop", sender)
	if _, err := relay.BufferMessage(ctx, recipient, m); err != nil {
		t.Fatalf("buffer: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := relay.BufferedCount(recipient); n != 0 {
		t.Fatalf("expected 0 after TTL, got %d", n)
	}
}

func TestMessageRelay_OnlineOfflineTracking(t *testing.T) {
	t.Parallel()
	relay := NewMessageRelay(nil, RelayRoleRelay)
	r1 := PeerID("r1")
	relay.MarkOffline(r1)
	if relay.IsOnline(r1) {
		t.Fatalf("r1 should be offline")
	}
	relay.mu.Lock()
	relay.online[r1] = true
	relay.mu.Unlock()
	if !relay.IsOnline(r1) {
		t.Fatalf("r1 should be online")
	}
}

func TestMessageRelay_StandardRoleCannotBuffer(t *testing.T) {
	t.Parallel()
	relay := NewMessageRelay(nil, RelayRoleStandard)
	ctx := context.Background()

	m := testRelayMessage("x", PeerID("sender"))
	if _, err := relay.BufferMessage(ctx, PeerID("recipient"), m); err == nil {
		t.Fatalf("expected error for standard role, got nil")
	}
}

// fakePersistent exercises the persistent-store hook.
type fakePersistent struct {
	appended map[PeerID][]Message
	loaded   map[PeerID][]Message
}

func newFakePersistent() *fakePersistent {
	return &fakePersistent{
		appended: make(map[PeerID][]Message),
		loaded:   make(map[PeerID][]Message),
	}
}

func (f *fakePersistent) Append(_ context.Context, recipient PeerID, msg Message) error {
	f.appended[recipient] = append(f.appended[recipient], msg)
	return nil
}

func (f *fakePersistent) Load(_ context.Context, recipient PeerID) ([]Message, error) {
	return f.loaded[recipient], nil
}

func (f *fakePersistent) Delete(_ context.Context, recipient PeerID, deliveredIDs []MessageID) error {
	return nil
}

func TestMessageRelay_PersistentHookInvoked(t *testing.T) {
	t.Parallel()
	fake := newFakePersistent()
	relay := NewMessageRelay(nil, RelayRoleRelay, WithRelayPersistentStore(fake))
	ctx := context.Background()

	recipient := PeerID("recipient")
	m := testRelayMessage("persist-1", PeerID("sender"))
	if _, err := relay.BufferMessage(ctx, recipient, m); err != nil {
		t.Fatalf("buffer: %v", err)
	}
	if len(fake.appended[recipient]) != 1 {
		t.Fatalf("persistent Append not called")
	}
}

func TestMessageRelay_RestoreFromPersistent(t *testing.T) {
	t.Parallel()
	recipient := PeerID("recipient")
	sender := PeerID("sender")

	fake := newFakePersistent()
	m := testRelayMessage("restored", sender)
	fake.loaded[recipient] = []Message{m}

	relay := NewMessageRelay(nil, RelayRoleRelay, WithRelayPersistentStore(fake))
	if err := relay.RestoreFromPersistent(context.Background(), recipient); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if n := relay.BufferedCount(recipient); n != 1 {
		t.Fatalf("want 1 restored, got %d", n)
	}
}

func TestMessageRelay_MarkOnlineReplay(t *testing.T) {
	t.Parallel()
	relay := NewMessageRelay(nil, RelayRoleRelay)
	ctx := context.Background()

	recipient := PeerID("recipient")
	sender := PeerID("sender")

	for i := 0; i < 3; i++ {
		m := testRelayMessage(fmt.Sprintf("m-%d", i), sender)
		if _, err := relay.BufferMessage(ctx, recipient, m); err != nil {
			t.Fatalf("buffer %d: %v", i, err)
		}
	}

	var delivered []MessageID
	relay.OnDelivery(func(r PeerID, m Message) {
		if r != recipient {
			t.Errorf("delivery to wrong peer: %s", r)
		}
		delivered = append(delivered, m.ID)
	})

	if err := relay.MarkOnline(ctx, recipient); err != nil {
		t.Fatalf("mark online: %v", err)
	}
	if len(delivered) != 3 {
		t.Fatalf("expected 3 delivered, got %d", len(delivered))
	}
	if n := relay.BufferedCount(recipient); n != 0 {
		t.Fatalf("buffer should be drained, got %d", n)
	}
}
