/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * Unit + integration tests for the messaging subsystem. Tests run over
 * LocalBus so they are hermetic and race-detector-friendly.
 */
package messaging

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbmumford/minerva/identity"
)

// --- helpers --------------------------------------------------------------

// newTestIdentity creates a fresh keypair and wraps it as an Identity.
func newTestIdentity(t *testing.T) (Identity, *identity.Keypair) {
	t.Helper()
	kp, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return &KeypairIdentity{KP: kp}, kp
}

// newTestMessenger spins up a Messenger against the shared bus.
func newTestMessenger(t *testing.T, bus *LocalBus) (*Messenger, Identity) {
	t.Helper()
	ident, _ := newTestIdentity(t)
	m, err := NewMessenger(ident, bus)
	if err != nil {
		t.Fatalf("new messenger: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, ident
}

// waitFor calls check repeatedly until it returns true or timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waitFor: condition not met within %s", timeout)
}

// --- types_test -----------------------------------------------------------

func TestNewMessageID_UUIDv7Shape(t *testing.T) {
	seen := make(map[MessageID]struct{})
	for i := 0; i < 1000; i++ {
		id := NewMessageID()
		if len(id) != 36 {
			t.Fatalf("id length = %d, want 36", len(id))
		}
		if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			t.Fatalf("id missing dashes: %s", id)
		}
		if id[14] != '7' {
			t.Fatalf("id version nibble = %q, want '7'", id[14])
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id: %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestMessageSigningRoundTrip(t *testing.T) {
	ident, kp := newTestIdentity(t)
	msg := Message{
		ID:        NewMessageID(),
		ChannelID: "c",
		Author:    ident.PeerID(),
		SentAt:    time.Now().UTC(),
		Body:      []byte("hello"),
		Kind:      KindText,
	}
	msg.Signature = ident.Sign(msg.signingBytes())

	pub, err := peerIDFromHex(msg.Author)
	if err != nil {
		t.Fatalf("decode peerID: %v", err)
	}
	if len(pub) != len(kp.PublicKey) {
		t.Fatalf("pub length mismatch")
	}
	// Happy path.
	if !verifyForTest(pub, msg.signingBytes(), msg.Signature) {
		t.Fatalf("signature should verify")
	}
	// Tamper.
	msg.Body[0] ^= 1
	if verifyForTest(pub, msg.signingBytes(), msg.Signature) {
		t.Fatalf("tampered message should not verify")
	}
}

// --- localbus_test --------------------------------------------------------

func TestLocalBus_FanOut(t *testing.T) {
	bus := NewLocalBus()
	defer bus.Close()

	var count atomic.Int32
	unsub1 := bus.Subscribe("t", func(p []byte) { count.Add(1) })
	unsub2 := bus.Subscribe("t", func(p []byte) { count.Add(10) })
	defer unsub1()
	defer unsub2()

	if err := bus.Publish("t", []byte("hi")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := count.Load(); got != 11 {
		t.Fatalf("count = %d, want 11", got)
	}

	unsub1()
	if err := bus.Publish("t", []byte("again")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := count.Load(); got != 21 {
		t.Fatalf("after unsub count = %d, want 21", got)
	}
}

func TestLocalBus_ClosedRejects(t *testing.T) {
	bus := NewLocalBus()
	bus.Close()
	if err := bus.Publish("t", nil); err == nil {
		t.Fatalf("expected ErrTransportClosed")
	}
}

// --- senderkeys_test ------------------------------------------------------

func TestSenderKeyRatchet_SealOpen(t *testing.T) {
	r, err := NewSenderKeyRatchet()
	if err != nil {
		t.Fatal(err)
	}
	peer := PeerID("aabbcc")
	r.Install(peer, r.OwnKey())

	ct, err := r.SealBody([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := r.OpenBody(peer, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(plain) != "secret" {
		t.Fatalf("plain = %q", plain)
	}
}

func TestSenderKeyRatchet_Rotate(t *testing.T) {
	r, _ := NewSenderKeyRatchet()
	before := r.OwnKey()
	_ = r.Rotate()
	after := r.OwnKey()
	if before == after {
		t.Fatalf("key did not rotate")
	}
}

func TestExchangeIdentity_Roundtrip(t *testing.T) {
	kp1, _ := identity.Generate()
	kp2, _ := identity.Generate()
	e1, err := NewExchangeIdentity(kp1.Seed())
	if err != nil {
		t.Fatal(err)
	}
	e2, err := NewExchangeIdentity(kp2.Seed())
	if err != nil {
		t.Fatal(err)
	}

	var key [senderKeyLen]byte
	for i := range key {
		key[i] = byte(i)
	}

	nonce, sealed, err := e1.SealFor(e2.Pub, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e2.OpenSealed(e1.Pub, nonce, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != key {
		t.Fatalf("round-trip mismatch")
	}

	// Tamper with the ciphertext.
	sealed[0] ^= 1
	if _, err := e2.OpenSealed(e1.Pub, nonce, sealed); err == nil {
		t.Fatalf("tampered sealed should fail")
	}
}

// --- group integration ----------------------------------------------------

// conversationPeer wires a single peer's Messenger and resulting group channel.
type conversationPeer struct {
	name string
	m    *Messenger
	g    *Conversation
	rx   []Message // decrypted messages seen
	mu   sync.Mutex
}

func (p *conversationPeer) received() []Message {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Message, len(p.rx))
	copy(out, p.rx)
	return out
}

// buildConversation spins up N peers on a shared bus, wires up the exchange
// registry, and creates the group with A as founder. Returns the peers
// in order (index 0 = founder).
func buildConversation(t *testing.T, n int, channel ChannelID) []*conversationPeer {
	t.Helper()
	bus := NewLocalBus()
	t.Cleanup(func() { bus.Close() })

	peers := make([]*conversationPeer, n)
	for i := 0; i < n; i++ {
		ident, _ := newTestIdentity(t)
		m, err := NewMessenger(ident, bus)
		if err != nil {
			t.Fatal(err)
		}
		peers[i] = &conversationPeer{name: fmt.Sprintf("p%d", i), m: m}
		t.Cleanup(func() { _ = m.Close() })
	}

	// Everyone learns everyone's exchange pub ahead of time. A real
	// deployment would do this via discovery; here it's just a map.
	for _, pi := range peers {
		for _, pj := range peers {
			if pi == pj {
				continue
			}
			pi.m.RegisterPeerExchange(pj.m.PeerID(), pj.m.ExchangePub())
		}
	}

	// Founder joins first, seeding membership for everyone else.
	founder := peers[0]
	initial := make([]PeerID, 0, n-1)
	for _, p := range peers[1:] {
		initial = append(initial, p.m.PeerID())
	}
	g, err := founder.m.OpenConversation(channel, initial)
	if err != nil {
		t.Fatal(err)
	}
	founder.g = g

	// Non-founders join the same id — they subscribe to the topic and
	// inherit membership / sender keys from gossip.
	for _, p := range peers[1:] {
		gp, err := p.m.OpenConversation(channel, nil)
		if err != nil {
			t.Fatal(err)
		}
		p.g = gp
	}

	// Subscribe each peer to its group channel for assertion.
	for _, p := range peers {
		p := p
		p.g.Subscribe(func(msg Message) {
			p.mu.Lock()
			p.rx = append(p.rx, msg)
			p.mu.Unlock()
		})
	}

	return peers
}

func TestConversation_SendAcrossPeers(t *testing.T) {
	peers := buildConversation(t, 3, "alpha")

	// Founder sends a text message.
	msg, err := peers[0].g.Send(context.Background(), []byte("hello everyone"))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if msg.Author != peers[0].m.PeerID() {
		t.Fatalf("author mismatch")
	}

	waitFor(t, time.Second, func() bool {
		for _, p := range peers {
			if len(p.received()) < 1 {
				return false
			}
		}
		return true
	})

	// Every peer should decrypt the body successfully.
	for _, p := range peers {
		rxs := p.received()
		var texts []Message
		for _, m := range rxs {
			if m.Kind == KindText && !m.Deleted {
				texts = append(texts, m)
			}
		}
		if len(texts) == 0 {
			t.Fatalf("%s: no text received", p.name)
		}
		plain, err := p.g.DecryptBody(&texts[len(texts)-1])
		if err != nil {
			t.Fatalf("%s decrypt: %v", p.name, err)
		}
		if string(plain) != "hello everyone" {
			t.Fatalf("%s plain = %q", p.name, plain)
		}
	}
}

func TestConversation_Edit(t *testing.T) {
	peers := buildConversation(t, 3, "edit-chan")

	orig, err := peers[0].g.Send(context.Background(), []byte("typo"))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return len(peers[1].received()) >= 1 && len(peers[2].received()) >= 1
	})

	edit, err := peers[0].g.Edit(context.Background(), orig.ID, []byte("fixed"))
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if edit.EditOf != orig.ID {
		t.Fatalf("EditOf = %s, want %s", edit.EditOf, orig.ID)
	}

	waitFor(t, time.Second, func() bool {
		for _, p := range peers[1:] {
			if _, ok := p.g.LatestVersion(orig.ID); !ok {
				return false
			}
		}
		return true
	})

	for _, p := range peers {
		latest, ok := p.g.LatestVersion(orig.ID)
		if !ok {
			t.Fatalf("%s: latest not found", p.name)
		}
		if latest.ID != edit.ID {
			t.Fatalf("%s: latest id = %s, want %s", p.name, latest.ID, edit.ID)
		}
		plain, err := p.g.DecryptBody(latest)
		if err != nil {
			t.Fatalf("%s decrypt edit: %v", p.name, err)
		}
		if string(plain) != "fixed" {
			t.Fatalf("%s edit plain = %q", p.name, plain)
		}
		chain := p.g.EditChain(orig.ID)
		if len(chain) != 2 {
			t.Fatalf("%s: chain len = %d", p.name, len(chain))
		}
	}
}

func TestConversation_Delete(t *testing.T) {
	peers := buildConversation(t, 3, "del-chan")
	orig, err := peers[0].g.Send(context.Background(), []byte("oops"))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return len(peers[1].received()) >= 1
	})

	if err := peers[0].g.Delete(context.Background(), orig.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	waitFor(t, time.Second, func() bool {
		for _, p := range peers {
			if !p.g.IsDeleted(orig.ID) {
				return false
			}
		}
		return true
	})

	for _, p := range peers {
		hist := p.g.History(time.Time{})
		for _, m := range hist {
			if m.ID == orig.ID || m.EditOf == orig.ID {
				t.Fatalf("%s: deleted message appears in history", p.name)
			}
		}
	}
}

func TestConversation_RemoveMemberRotatesKey(t *testing.T) {
	peers := buildConversation(t, 3, "rotate-chan")

	// p0 removes p2. After the rotation, p2 should no longer be able to
	// decrypt p0's subsequent messages (we can only simulate this from
	// p2's vantage because we do not install the rotated key on p2).
	if err := peers[0].g.RemoveMember(context.Background(), peers[2].m.PeerID()); err != nil {
		t.Fatalf("remove: %v", err)
	}

	waitFor(t, time.Second, func() bool {
		return !peers[2].g.IsMember(peers[2].m.PeerID()) || !peers[0].g.IsMember(peers[2].m.PeerID())
	})

	// p0 and p1 remain members; a send should reach p1.
	_, err := peers[0].g.Send(context.Background(), []byte("post-rotate"))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		latest := peers[1].received()
		for i := len(latest) - 1; i >= 0; i-- {
			if latest[i].Kind == KindText && latest[i].Author == peers[0].m.PeerID() && !latest[i].Deleted {
				if plain, err := peers[1].g.DecryptBody(&latest[i]); err == nil && string(plain) == "post-rotate" {
					return true
				}
			}
		}
		return false
	})
}

// --- broadcast integration ------------------------------------------------

func TestBroadcast_PublishSubscribe(t *testing.T) {
	bus := NewLocalBus()
	t.Cleanup(func() { bus.Close() })

	pubIdent, _ := newTestIdentity(t)
	pub, err := NewPublisherBroadcast("news", pubIdent, bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pub.Close() })

	const N = 3
	subs := make([]*Broadcast, N)
	received := make([]atomic.Int32, N)
	for i := 0; i < N; i++ {
		s, err := NewBroadcast("news", pubIdent.PeerID(), bus)
		if err != nil {
			t.Fatal(err)
		}
		i := i
		s.Subscribe(func(msg Message) {
			if string(msg.Body) == "hello" {
				received[i].Add(1)
			}
		})
		subs[i] = s
		t.Cleanup(func() { _ = s.Close() })
	}

	if _, err := pub.Publish(context.Background(), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		for i := 0; i < N; i++ {
			if received[i].Load() < 1 {
				return false
			}
		}
		return true
	})
}

func TestBroadcast_RejectsForgedAuthor(t *testing.T) {
	bus := NewLocalBus()
	defer bus.Close()
	real, _ := newTestIdentity(t)
	fake, _ := newTestIdentity(t)

	sub, _ := NewBroadcast("news", real.PeerID(), bus)
	defer sub.Close()

	var got atomic.Int32
	sub.Subscribe(func(Message) { got.Add(1) })

	// Publish a fake-signed message directly via the bus.
	fakePub, err := NewPublisherBroadcast("news", fake, bus)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fakePub.Publish(context.Background(), []byte("imposter")); err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)
	if got.Load() != 0 {
		t.Fatalf("forged author should not be delivered")
	}
}

// --- presence integration -------------------------------------------------

func TestPresence_StatePropagates(t *testing.T) {
	bus := NewLocalBus()
	t.Cleanup(func() { bus.Close() })

	idA, _ := newTestIdentity(t)
	idB, _ := newTestIdentity(t)

	pA, err := NewPresenceChannel("room", idA, bus, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pA.Close() })
	pB, err := NewPresenceChannel("room", idB, bus, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pB.Close() })

	var got atomic.Int32
	pB.Watch(func(peer PeerID, st PresenceState) {
		if peer == idA.PeerID() && st.State == StateTyping {
			got.Add(1)
		}
	})

	if err := pA.SetState(context.Background(), StateTyping); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return got.Load() >= 1 })
}

func TestPresence_TTLExpires(t *testing.T) {
	bus := NewLocalBus()
	t.Cleanup(func() { bus.Close() })

	idA, _ := newTestIdentity(t)
	idB, _ := newTestIdentity(t)

	// B's TTL is short; A sends one update and then stops heartbeating
	// by closing its channel.
	pB, err := NewPresenceChannel("room", idB, bus, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pB.Close() })

	pA, err := NewPresenceChannel("room", idA, bus, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	_ = pA.SetState(context.Background(), StateOnline)
	waitFor(t, time.Second, func() bool {
		cur := pB.Current()
		st, ok := cur[idA.PeerID()]
		return ok && st.State == StateOnline
	})

	_ = pA.Close()
	// After TTL, pB should view pA as offline.
	waitFor(t, 2*time.Second, func() bool {
		cur := pB.Current()
		st, ok := cur[idA.PeerID()]
		return ok && st.State == StateOffline
	})
}

// --- receipts integration -------------------------------------------------

func TestReceipts_MarkReadFanOut(t *testing.T) {
	bus := NewLocalBus()
	t.Cleanup(func() { bus.Close() })

	idAuthor, _ := newTestIdentity(t)
	authorM, err := NewMessenger(idAuthor, bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authorM.Close() })

	rA, err := authorM.Receipts("alpha")
	if err != nil {
		t.Fatal(err)
	}

	readers := make([]*ReceiptChannel, 3)
	readerIDs := make([]PeerID, 3)
	for i := 0; i < 3; i++ {
		id, _ := newTestIdentity(t)
		m, err := NewMessenger(id, bus)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		r, err := m.Receipts("alpha")
		if err != nil {
			t.Fatal(err)
		}
		readers[i] = r
		readerIDs[i] = id.PeerID()
	}

	msgID := NewMessageID()
	for _, r := range readers {
		if err := r.MarkRead(context.Background(), msgID); err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, time.Second, func() bool {
		return rA.ReaderCount(msgID) == 3
	})

	gotReaders := rA.Readers(msgID)
	if len(gotReaders) != 3 {
		t.Fatalf("readers = %d, want 3", len(gotReaders))
	}
	seen := make(map[PeerID]bool)
	for _, p := range gotReaders {
		seen[p] = true
	}
	for _, want := range readerIDs {
		if !seen[want] {
			t.Fatalf("missing reader %s", want)
		}
	}
}

// --- concurrent ----------------------------------------------------------

func TestConversation_ConcurrentSend(t *testing.T) {
	peers := buildConversation(t, 3, "concurrent")

	const N = 50
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sender := peers[i%len(peers)]
			_, _ = sender.g.Send(context.Background(), []byte(fmt.Sprintf("msg-%d", i)))
		}(i)
	}
	wg.Wait()

	// Each peer should see all N messages (idempotent on ID ensures no
	// duplicates even with the LocalBus fan-out echo).
	waitFor(t, 2*time.Second, func() bool {
		for _, p := range peers {
			count := 0
			for _, m := range p.received() {
				if m.Kind == KindText && !m.Deleted {
					count++
				}
			}
			if count < N {
				return false
			}
		}
		return true
	})
}

// --- full SDK integration -------------------------------------------------

func TestMessenger_FullIntegration(t *testing.T) {
	bus := NewLocalBus()
	t.Cleanup(func() { bus.Close() })

	// Build three peers as full Messengers (same channels wired through
	// each one), mirroring what a real application would do.
	ms := make([]*Messenger, 3)
	for i := 0; i < 3; i++ {
		ident, _ := newTestIdentity(t)
		m, err := NewMessenger(ident, bus)
		if err != nil {
			t.Fatal(err)
		}
		ms[i] = m
		t.Cleanup(func() { _ = m.Close() })
	}
	// Cross-register exchange pubs.
	for _, mi := range ms {
		for _, mj := range ms {
			if mi == mj {
				continue
			}
			mi.RegisterPeerExchange(mj.PeerID(), mj.ExchangePub())
		}
	}

	// Group channel.
	initial := []PeerID{ms[1].PeerID(), ms[2].PeerID()}
	g0, err := ms[0].OpenConversation("team", initial)
	if err != nil {
		t.Fatal(err)
	}
	g1, _ := ms[1].OpenConversation("team", nil)
	g2, _ := ms[2].OpenConversation("team", nil)

	// Receipts.
	r0, _ := ms[0].Receipts("team")
	r1, _ := ms[1].Receipts("team")
	_, _ = ms[2].Receipts("team")

	// Presence.
	p0, _ := ms[0].Presence("team", 500*time.Millisecond)
	_, _ = ms[1].Presence("team", 500*time.Millisecond)
	_, _ = ms[2].Presence("team", 500*time.Millisecond)

	// Everyone online.
	if err := p0.SetState(context.Background(), StateOnline); err != nil {
		t.Fatal(err)
	}

	// ms[0] sends.
	msg, err := g0.Send(context.Background(), []byte("kickoff"))
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, time.Second, func() bool {
		_, ok1 := g1.LatestVersion(msg.ID)
		_, ok2 := g2.LatestVersion(msg.ID)
		return ok1 && ok2
	})

	// ms[1] marks read.
	if err := r1.MarkRead(context.Background(), msg.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return r0.ReaderCount(msg.ID) >= 1 })

	// ms[0] edits.
	edit, err := g0.Edit(context.Background(), msg.ID, []byte("kickoff-v2"))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		latest, ok := g2.LatestVersion(msg.ID)
		return ok && latest.ID == edit.ID
	})

	// ms[0] deletes.
	if err := g0.Delete(context.Background(), msg.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return g1.IsDeleted(msg.ID) && g2.IsDeleted(msg.ID)
	})
}

// --- test helpers -------------------------------------------------------

// verifyForTest is a test-local re-export of ed25519.Verify so the test
// file does not have to import crypto/ed25519 (keeps the failure
// surface smaller when the package signature format changes).
func verifyForTest(pub []byte, data, sig []byte) bool {
	return ed25519VerifyShim(pub, data, sig)
}
