/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package messaging

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// alicebobPair constructs two Ed25519 identities and bootstraps
// double-ratchet sessions on both sides.
func alicebobPair(t *testing.T) (aliceSess, bobSess *RatchetSession, alicePriv ed25519.PrivateKey, alicePub ed25519.PublicKey, bobPriv ed25519.PrivateKey, bobPub ed25519.PublicKey) {
	t.Helper()
	var err error
	alicePub, alicePriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("alice keygen: %v", err)
	}
	bobPub, bobPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("bob keygen: %v", err)
	}

	// Both sides derive the same shared secret from identity ECDH.
	aliceSecret, err := sharedSecret(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("alice shared: %v", err)
	}
	bobSecret, err := sharedSecret(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("bob shared: %v", err)
	}
	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Fatalf("shared secrets differ")
	}

	aliceSess, err = NewRatchetSessionInitiator(aliceSecret, bobPub)
	if err != nil {
		t.Fatalf("alice init: %v", err)
	}
	bobSess, err = NewRatchetSessionResponder(bobSecret, bobPriv)
	if err != nil {
		t.Fatalf("bob responder: %v", err)
	}
	return
}

func TestRatchet_FullDuplex(t *testing.T) {
	t.Parallel()
	alice, bob, _, _, _, _ := alicebobPair(t)

	// Alice -> Bob
	msg1, err := EncryptRatchet([]byte("hello bob"), alice)
	if err != nil {
		t.Fatalf("alice encrypt: %v", err)
	}
	pt1, err := DecryptRatchet(msg1, bob)
	if err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	if string(pt1) != "hello bob" {
		t.Fatalf("bob got %q", pt1)
	}

	// Bob -> Alice (triggers bob's first send ratchet)
	msg2, err := EncryptRatchet([]byte("hi alice"), bob)
	if err != nil {
		t.Fatalf("bob encrypt: %v", err)
	}
	pt2, err := DecryptRatchet(msg2, alice)
	if err != nil {
		t.Fatalf("alice decrypt: %v", err)
	}
	if string(pt2) != "hi alice" {
		t.Fatalf("alice got %q", pt2)
	}

	// Alice -> Bob (new alice ratchet key)
	msg3, err := EncryptRatchet([]byte("second message"), alice)
	if err != nil {
		t.Fatalf("alice encrypt #2: %v", err)
	}
	pt3, err := DecryptRatchet(msg3, bob)
	if err != nil {
		t.Fatalf("bob decrypt #2: %v", err)
	}
	if string(pt3) != "second message" {
		t.Fatalf("bob got %q", pt3)
	}
}

func TestRatchet_OutOfOrder(t *testing.T) {
	t.Parallel()
	alice, bob, _, _, _, _ := alicebobPair(t)

	// Alice sends 6 messages in a row (same sending chain).
	var cts [6][]byte
	for i := 0; i < 6; i++ {
		pt := []byte{byte('a' + i)}
		ct, err := EncryptRatchet(pt, alice)
		if err != nil {
			t.Fatalf("alice encrypt #%d: %v", i, err)
		}
		cts[i] = ct
	}

	// Bob receives in the order 1, 3, 5, 2, 4, 6 (0-indexed: 0,2,4,1,3,5).
	order := []int{0, 2, 4, 1, 3, 5}
	got := make([]byte, 6)
	for _, idx := range order {
		pt, err := DecryptRatchet(cts[idx], bob)
		if err != nil {
			t.Fatalf("bob decrypt idx=%d: %v", idx, err)
		}
		if len(pt) != 1 {
			t.Fatalf("idx=%d bad pt %q", idx, pt)
		}
		got[idx] = pt[0]
	}
	for i := 0; i < 6; i++ {
		if got[i] != byte('a'+i) {
			t.Fatalf("position %d: got %q want %q", i, got[i], byte('a'+i))
		}
	}
}

func TestRatchet_ForwardSecrecy(t *testing.T) {
	t.Parallel()
	alice, bob, _, _, _, _ := alicebobPair(t)

	// Send two messages.
	ct1, err := EncryptRatchet([]byte("secret 1"), alice)
	if err != nil {
		t.Fatalf("encrypt1: %v", err)
	}
	if _, err := DecryptRatchet(ct1, bob); err != nil {
		t.Fatalf("decrypt1: %v", err)
	}
	ct2, err := EncryptRatchet([]byte("secret 2"), alice)
	if err != nil {
		t.Fatalf("encrypt2: %v", err)
	}
	if _, err := DecryptRatchet(ct2, bob); err != nil {
		t.Fatalf("decrypt2: %v", err)
	}

	// Snapshot bob's *current* state and replay ct1. Because the chain
	// has advanced past ct1's position and it's not in the skipped
	// cache (it was already consumed), replay must fail.
	if _, err := DecryptRatchet(ct1, bob); err == nil {
		t.Fatalf("expected replay failure, got nil")
	}
}

func TestRatchet_SessionRestart(t *testing.T) {
	t.Parallel()
	_, _, alicePriv, alicePub, bobPriv, bobPub := alicebobPair(t)

	reg := NewRatchetRegistry()
	bobPeer := PeerIDFromBytes(bobPub)
	alicePeer := PeerIDFromBytes(alicePub)

	aliceSess, err := reg.BootstrapSession(bobPeer, alicePriv, bobPub, true)
	if err != nil {
		t.Fatalf("alice bootstrap: %v", err)
	}
	bobSess, err := reg.BootstrapSession(alicePeer, bobPriv, alicePub, false)
	if err != nil {
		t.Fatalf("bob bootstrap: %v", err)
	}

	ct, err := EncryptRatchet([]byte("restart test"), aliceSess)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptRatchet(ct, bobSess); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	// Drop the session and re-bootstrap.
	reg.DropSession(bobPeer)
	reg.DropSession(alicePeer)
	if reg.Session(bobPeer) != nil {
		t.Fatalf("session should be nil after drop")
	}

	aliceSess2, err := reg.BootstrapSession(bobPeer, alicePriv, bobPub, true)
	if err != nil {
		t.Fatalf("alice re-bootstrap: %v", err)
	}
	bobSess2, err := reg.BootstrapSession(alicePeer, bobPriv, alicePub, false)
	if err != nil {
		t.Fatalf("bob re-bootstrap: %v", err)
	}
	ct2, err := EncryptRatchet([]byte("after restart"), aliceSess2)
	if err != nil {
		t.Fatalf("encrypt post-restart: %v", err)
	}
	pt, err := DecryptRatchet(ct2, bobSess2)
	if err != nil {
		t.Fatalf("decrypt post-restart: %v", err)
	}
	if string(pt) != "after restart" {
		t.Fatalf("bad pt %q", pt)
	}
}

func TestRatchet_CapabilityFlags(t *testing.T) {
	t.Parallel()
	reg := NewRatchetRegistry()

	reg.AdvertiseCapability(PeerID("peer_v1"), true)
	reg.AdvertiseCapability(PeerID("peer_v0"), false)

	if !reg.SupportsRatchet(PeerID("peer_v1")) {
		t.Fatalf("peer_v1 should support ratchet")
	}
	if reg.SupportsRatchet(PeerID("peer_v0")) {
		t.Fatalf("peer_v0 should NOT support ratchet")
	}
	if reg.SupportsRatchet(PeerID("unknown")) {
		t.Fatalf("unknown peer should default to non-ratchet")
	}
}

func TestRatchet_SkippedGapBound(t *testing.T) {
	t.Parallel()
	alice, bob, _, _, _, _ := alicebobPair(t)

	// Alice sends maxSkippedKeys+2 messages.
	var ct []byte
	for i := 0; i < maxSkippedKeys+2; i++ {
		var err error
		ct, err = EncryptRatchet([]byte{byte(i)}, alice)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
	}
	// Bob has seen nothing. Trying to jump straight to the last
	// message requires stashing maxSkippedKeys+1 keys — over the bound.
	if _, err := DecryptRatchet(ct, bob); err == nil {
		t.Fatalf("expected bound-exceeded error, got nil")
	}
}
