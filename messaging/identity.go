/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * Identity abstraction + pluggable Transport. The messaging subsystem must
 * work both with a real Whisper engine (gossip fan-out, rate limits, all
 * the production goodies) and a pure in-memory bus for testing. Neither
 * case should leak into the higher-level APIs, so we expose a narrow
 * Transport interface and provide two implementations: WhisperTransport
 * and LocalBus.
 */
package messaging

import (
	"crypto/ed25519"
	"errors"
	"sync"

	"github.com/bbmumford/minerva/identity"
	"github.com/bbmumford/whisper"
)

// Identity captures the minimum an author needs to send signed messages.
// Consumers wire this via adapters around *identity.Keypair, a hardware
// token, a KMS, etc. Keeping the surface this small means the messaging
// package does not depend on any particular key-management story.
type Identity interface {
	// PeerID returns the author's hex-encoded Ed25519 public key.
	PeerID() PeerID
	// Sign produces an Ed25519 signature over data.
	Sign(data []byte) []byte
	// Public returns the 32-byte Ed25519 public key. Used to pre-share a
	// curve25519 box key with peers (derived in senderkeys.go).
	Public() ed25519.PublicKey
	// Private returns the 64-byte Ed25519 private key. Required to derive
	// the curve25519 scalar for nacl/box. Callers that cannot expose the
	// raw private key may substitute an Identity whose SenderKeyEnvelope /
	// OpenEnvelope methods are pre-negotiated out-of-band.
	Private() ed25519.PrivateKey
}

// KeypairIdentity adapts a *identity.Keypair to the Identity interface.
// Most consumers will use this directly; it is the wiring used by the
// Messenger constructor below.
type KeypairIdentity struct {
	KP *identity.Keypair
}

// PeerID returns the hex-encoded public key.
func (k *KeypairIdentity) PeerID() PeerID { return PeerIDFromBytes(k.KP.PublicKey) }

// Sign delegates to the underlying keypair.
func (k *KeypairIdentity) Sign(data []byte) []byte { return k.KP.Sign(data) }

// Public returns the Ed25519 public key.
func (k *KeypairIdentity) Public() ed25519.PublicKey { return k.KP.PublicKey }

// Private returns the Ed25519 private key.
func (k *KeypairIdentity) Private() ed25519.PrivateKey { return k.KP.PrivateKey }

// Transport is a narrow fan-out interface used by every channel. Two
// implementations ship with the package:
//
//   - WhisperTransport — wraps a *whisper.Engine and registers each
//     channel as a BroadcastOnly topic.
//   - LocalBus — in-process fan-out, used by tests and intra-process
//     peers sharing a single Messenger.
//
// Transports MUST NOT mutate the payload after Publish returns; the
// channel layer retains no back-reference.
type Transport interface {
	// Publish pushes payload to every peer subscribed to topic. May be
	// called concurrently from many goroutines.
	Publish(topic string, payload []byte) error
	// Subscribe registers cb for messages delivered to topic. The returned
	// unsubscribe func is safe to call concurrently and is idempotent.
	Subscribe(topic string, cb func(payload []byte)) (unsubscribe func())
}

// ErrTransportClosed indicates the underlying transport has been torn down.
var ErrTransportClosed = errors.New("messaging: transport closed")

// --- LocalBus ------------------------------------------------------------

// LocalBus is an in-process fan-out used by tests (and by a single
// Messenger to broadcast to multiple in-process channel instances). It is
// safe for concurrent use.
type LocalBus struct {
	mu     sync.RWMutex
	subs   map[string]map[int]func([]byte)
	nextID int
	closed bool
}

// NewLocalBus returns a ready-to-use in-process bus.
func NewLocalBus() *LocalBus {
	return &LocalBus{subs: make(map[string]map[int]func([]byte))}
}

// Publish fans out payload to every subscriber of topic.
func (b *LocalBus) Publish(topic string, payload []byte) error {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return ErrTransportClosed
	}
	// Snapshot to avoid holding the lock while invoking callbacks that
	// may re-enter Publish (tests occasionally do this).
	subs := make([]func([]byte), 0, len(b.subs[topic]))
	for _, cb := range b.subs[topic] {
		subs = append(subs, cb)
	}
	b.mu.RUnlock()

	// Deliver a defensive copy so callbacks can retain the slice.
	for _, cb := range subs {
		buf := make([]byte, len(payload))
		copy(buf, payload)
		cb(buf)
	}
	return nil
}

// Subscribe registers cb for topic and returns an idempotent
// unsubscribe function.
func (b *LocalBus) Subscribe(topic string, cb func([]byte)) func() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subs[topic] == nil {
		b.subs[topic] = make(map[int]func([]byte))
	}
	id := b.nextID
	b.nextID++
	b.subs[topic][id] = cb

	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if m, ok := b.subs[topic]; ok {
			delete(m, id)
			if len(m) == 0 {
				delete(b.subs, topic)
			}
		}
	}
}

// Close marks the bus as closed; further Publish calls return
// ErrTransportClosed. Existing subscribers are not invoked again. Close is
// idempotent.
func (b *LocalBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.subs = nil
}

// --- WhisperTransport ----------------------------------------------------

// WhisperTransport adapts a *whisper.Engine. Topics are registered lazily
// as BroadcastOnly on first use; subsequent Subscribe calls reuse the same
// topic registration.
type WhisperTransport struct {
	engine *whisper.Engine

	mu     sync.Mutex
	topics map[string]struct{}
	subs   map[string][]*whisperSubscriber
}

// NewWhisperTransport wraps an engine. The caller retains ownership of the
// engine and is responsible for calling engine.Stop at shutdown.
func NewWhisperTransport(engine *whisper.Engine) *WhisperTransport {
	return &WhisperTransport{
		engine: engine,
		topics: make(map[string]struct{}),
		subs:   make(map[string][]*whisperSubscriber),
	}
}

// Publish sends payload to topic, lazy-registering the topic if needed.
func (w *WhisperTransport) Publish(topic string, payload []byte) error {
	if err := w.ensureTopic(topic); err != nil {
		return err
	}
	return w.engine.Publish(topic, payload)
}

// Subscribe registers cb for topic. The returned unsubscribe detaches the
// callback; it cannot un-register the topic from the engine (whisper has
// no such API), but subsequent messages to topic will be ignored by the
// detached callback.
func (w *WhisperTransport) Subscribe(topic string, cb func([]byte)) func() {
	if err := w.ensureTopic(topic); err != nil {
		// ensureTopic only errors on genuinely bad topic registrations —
		// log behaviour is up to the caller; returning a no-op unsub
		// lets the subscriber pretend they're subscribed to nothing.
		return func() {}
	}
	sub := &whisperSubscriber{cb: cb}

	w.mu.Lock()
	w.subs[topic] = append(w.subs[topic], sub)
	w.mu.Unlock()

	w.engine.Subscribe(topic, sub)

	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		sub.detach()
		subs := w.subs[topic]
		for i, s := range subs {
			if s == sub {
				w.subs[topic] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
	}
}

// ensureTopic registers topic with the engine exactly once per transport
// instance. It is safe for concurrent callers.
func (w *WhisperTransport) ensureTopic(topic string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.topics[topic]; ok {
		return nil
	}
	if err := w.engine.RegisterTopic(topic, whisper.TopicConfig{
		Mode: whisper.BroadcastOnly,
	}); err != nil {
		// If the engine already registered this topic under a different
		// identity it returns an error — treat that as "already good".
		// Any other error bubbles up.
		if !isAlreadyRegistered(err) {
			return err
		}
	}
	w.topics[topic] = struct{}{}
	return nil
}

// whisperSubscriber adapts a func callback to whisper.Subscriber.
// detach() swaps in a no-op so the engine's retained pointer becomes inert
// after Unsubscribe.
type whisperSubscriber struct {
	mu sync.Mutex
	cb func([]byte)
}

// OnBroadcast implements whisper.Subscriber.
func (s *whisperSubscriber) OnBroadcast(_topic, _from string, payload []byte) {
	s.mu.Lock()
	cb := s.cb
	s.mu.Unlock()
	if cb != nil {
		cb(payload)
	}
}

func (s *whisperSubscriber) detach() {
	s.mu.Lock()
	s.cb = nil
	s.mu.Unlock()
}

// isAlreadyRegistered is a trivial string check — whisper returns an
// fmt.Errorf with that phrase, and we don't want to depend on its
// concrete error type.
func isAlreadyRegistered(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	const needle = "already registered"
	for i := 0; i+len(needle) <= len(msg); i++ {
		if msg[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
