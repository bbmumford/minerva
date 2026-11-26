/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * Messenger — the unified front-door. Applications typically hold one
 * Messenger per Node and call OpenConversation / OpenBroadcast / Presence /
 * Receipts to obtain channel handles. The Messenger tracks channel
 * instances per-ID so repeat calls return the same handle; this keeps
 * subscription fan-out cheap.
 *
 * Session B additions:
 *   - RatchetRegistry  — per-peer double-ratchet sessions, accessed via
 *     (*Messenger).RatchetFor(peer).
 *   - AttachmentService — Attach / FetchAttachment methods wrap the
 *     package-level AttachBlob / FetchBlob while letting the Messenger
 *     hold the BlobStore handle.
 *   - MessageRelay — store-and-forward relay for offline recipients,
 *     enabled via (*Messenger).EnableRelay.
 *   - Capability registry — AdvertiseCapability / SupportsFeature drive
 *     per-peer feature flags (v1-ratchet, v2-attachments, …).
 *
 * A Conversation with exactly 2 members IS the direct-chat primitive.
 * There is no separate DirectChannel type. When both participants of a
 * 2-member Conversation advertise CapabilityV1Ratchet, Send routes
 * encryption through the per-peer double-ratchet session; otherwise the
 * legacy sender-key path is used. 3+ member Conversations always use the
 * sender-key path because the double-ratchet does not generalise
 * cleanly to multi-party.
 */
package messaging

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Capability strings advertised by peers. Matched verbatim between peers,
// so adding a new flavour requires updating both sides or downgrading to
// the closest supported predecessor.
const (
	CapabilityV1Ratchet     = "v1-ratchet"
	CapabilityV2Attachments = "v2-attachments"
	CapabilityV3Relay       = "v3-relay"
	CapabilityV4Edit        = "v4-edit"
	CapabilityV5Delete      = "v5-delete"
	CapabilityV6Presence    = "v6-presence"
	CapabilityV7Receipts    = "v7-receipts"
)

// messageSentCounterHook is an optional observability hook wired by a
// higher-level package (Mercury in Session C) without forcing Minerva to
// import plutus/observability directly. The atomic.Pointer keeps Minerva
// self-contained while preserving the MessagingSentCount span-continuity
// story: callers that want OTel counters register a hook in their SDK
// init and the Conversation send path invokes it exactly once per send.
var messageSentCounterHook atomic.Pointer[func(ctx context.Context)]

// SetMessageSentHook registers (or clears with nil) the observability hook
// invoked after a successful Conversation.Send / Broadcast.Publish. The
// hook is intentionally narrow — callers who need richer spans can wrap
// it in their own tracer; this package stays dependency-light.
func SetMessageSentHook(fn func(ctx context.Context)) {
	if fn == nil {
		messageSentCounterHook.Store(nil)
		return
	}
	f := fn
	messageSentCounterHook.Store(&f)
}

// invokeMessageSentHook dispatches to the registered hook if any. Called
// from the Conversation send path so the counter is mirror-compatible with
// the MessagingSentCount metric Mercury already ships.
func invokeMessageSentHook(ctx context.Context) {
	if h := messageSentCounterHook.Load(); h != nil && *h != nil {
		(*h)(ctx)
	}
}

// AttachmentService is the method-oriented attachment API bound to a
// Messenger. It wraps the package-level AttachBlob / FetchBlob functions
// so callers that already hold a *Messenger don't need a second handle.
type AttachmentService struct {
	mu    sync.Mutex
	store BlobStore
}

// SetStore installs a BlobStore. Passing nil disables the service.
func (a *AttachmentService) SetStore(store BlobStore) {
	a.mu.Lock()
	a.store = store
	a.mu.Unlock()
	// Keep the package-level attachment ref in sync so direct AttachBlob
	// callers continue to work; the service is purely additive.
	SetBlobStore(store)
}

// Store returns the currently-configured blob store, or nil.
func (a *AttachmentService) Store() BlobStore {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.store
}

// Messenger is the top-level API for the messaging subsystem.
type Messenger struct {
	identity Identity
	exchange *ExchangeIdentity
	trans    Transport

	mu            sync.Mutex
	conversations map[ChannelID]*Conversation
	broadcasts    map[ChannelID]*Broadcast
	receipts      map[ChannelID]*ReceiptChannel
	presence      map[ChannelID]*PresenceChannel

	// exchangeKeys caches per-peer curve25519 pubkeys registered via
	// RegisterPeerExchange so that conversations created later inherit
	// them.
	exchangeKeys map[PeerID][32]byte

	// Session B additions — always non-nil after NewMessenger.
	Ratchet     *RatchetRegistry
	Attachments *AttachmentService
	relay       *MessageRelay

	// Per-peer capability map. capabilities[peer][cap] = true means the
	// peer advertised the capability as enabled; absence means the peer
	// has not advertised it (treated as disabled).
	capMu        sync.RWMutex
	capabilities map[PeerID]map[string]bool

	// identityPriv caches the ed25519 private key once at construction so
	// BootstrapRatchet doesn't need to re-read Identity on every call.
	identityPriv ed25519.PrivateKey
}

// NewMessenger constructs a Messenger. The identity's Ed25519 seed is
// used to derive a per-node ExchangeIdentity for sender-key distribution.
// If the identity is not a *KeypairIdentity, callers may pass the
// exchange identity explicitly via NewMessengerWithExchange.
func NewMessenger(ident Identity, trans Transport) (*Messenger, error) {
	if ident == nil {
		return nil, ErrNoIdentity
	}
	if trans == nil {
		return nil, errors.New("messaging: nil transport")
	}
	priv := ident.Private()
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("messaging: identity must expose an ed25519 private key")
	}
	exch, err := NewExchangeIdentity(priv[:32])
	if err != nil {
		return nil, err
	}
	return NewMessengerWithExchange(ident, exch, trans)
}

// NewMessengerWithExchange constructs a Messenger with a caller-provided
// ExchangeIdentity. Useful when the Identity is backed by a KMS / HSM
// that does not expose the Ed25519 seed.
func NewMessengerWithExchange(ident Identity, exch *ExchangeIdentity, trans Transport) (*Messenger, error) {
	if ident == nil {
		return nil, ErrNoIdentity
	}
	if exch == nil {
		return nil, errors.New("messaging: nil exchange identity")
	}
	if trans == nil {
		return nil, errors.New("messaging: nil transport")
	}
	priv := ident.Private()
	privCopy := make(ed25519.PrivateKey, len(priv))
	copy(privCopy, priv)

	return &Messenger{
		identity:      ident,
		exchange:      exch,
		trans:         trans,
		conversations: make(map[ChannelID]*Conversation),
		broadcasts:    make(map[ChannelID]*Broadcast),
		receipts:      make(map[ChannelID]*ReceiptChannel),
		presence:      make(map[ChannelID]*PresenceChannel),
		exchangeKeys:  make(map[PeerID][32]byte),
		Ratchet:       NewRatchetRegistry(),
		Attachments:   &AttachmentService{},
		capabilities:  make(map[PeerID]map[string]bool),
		identityPriv:  privCopy,
	}, nil
}

// PeerID returns the local peer identifier.
func (m *Messenger) PeerID() PeerID { return m.identity.PeerID() }

// ExchangePub returns the local Curve25519 public key used for sealing
// sender-key envelopes. Applications should publish this alongside their
// PeerID so peers can seal envelopes back.
func (m *Messenger) ExchangePub() [32]byte { return m.exchange.Pub }

// Transport returns the underlying transport.
func (m *Messenger) Transport() Transport { return m.trans }

// OpenConversation returns (creating if needed) a conversation handle for
// id. initialMembers are added to the ORSet and, if their exchange keys
// have been previously registered via RegisterPeerExchange, receive sealed
// sender-key envelopes. The local identity is always auto-added. Repeat
// calls with the same id are idempotent: the same handle is returned,
// initialMembers additions are merged.
func (m *Messenger) OpenConversation(id ChannelID, initialMembers []PeerID) (*Conversation, error) {
	m.mu.Lock()
	if c, ok := m.conversations[id]; ok {
		m.mu.Unlock()
		// Idempotent: merge any new initialMembers the caller provided.
		for _, peer := range initialMembers {
			if peer == m.identity.PeerID() || c.IsMember(peer) {
				continue
			}
			if err := c.AddMember(context.Background(), peer); err != nil {
				return nil, err
			}
		}
		return c, nil
	}
	m.mu.Unlock()

	c, err := NewConversation(id, m.identity, m.exchange, m.trans)
	if err != nil {
		return nil, err
	}
	c.installRatchetBridge(m)

	m.mu.Lock()
	m.conversations[id] = c
	// Inherit any exchange keys registered before the conversation
	// existed.
	for peer, pub := range m.exchangeKeys {
		c.RegisterExchangeKey(peer, pub)
	}
	m.mu.Unlock()

	// Always auto-add self so the author can Send/Edit/Delete straight
	// away AND so every other peer sees our AddMember envelope and can
	// seal their own sender key to us (the catch-up path in conversation.go).
	if err := c.AddMember(context.Background(), m.identity.PeerID()); err != nil {
		return nil, err
	}
	for _, peer := range initialMembers {
		if peer == m.identity.PeerID() {
			continue
		}
		if err := c.AddMember(context.Background(), peer); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Conversation returns an existing conversation, or nil if not opened.
func (m *Messenger) Conversation(id ChannelID) *Conversation {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conversations[id]
}

// OpenBroadcast returns a publisher broadcast channel owned by the local
// identity. Same id is reused on repeat calls.
func (m *Messenger) OpenBroadcast(id ChannelID) (*Broadcast, error) {
	m.mu.Lock()
	if b, ok := m.broadcasts[id]; ok {
		m.mu.Unlock()
		return b, nil
	}
	m.mu.Unlock()

	b, err := NewPublisherBroadcast(id, m.identity, m.trans)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.broadcasts[id] = b
	m.mu.Unlock()
	return b, nil
}

// SubscribeBroadcast returns a subscriber-only broadcast channel for id
// published by publisher. Useful when the caller wants to read another
// peer's broadcast.
func (m *Messenger) SubscribeBroadcast(id ChannelID, publisher PeerID) (*Broadcast, error) {
	// We do not cache subscriber broadcasts by id alone because different
	// publishers might use the same channel id; caching would silently
	// ignore the publisher parameter on repeat calls.
	return NewBroadcast(id, publisher, m.trans)
}

// Presence returns the presence channel for id (creating on first call).
// ttl is only honoured on construction; subsequent calls reuse the
// existing channel regardless of ttl.
func (m *Messenger) Presence(id ChannelID, ttl time.Duration) (*PresenceChannel, error) {
	m.mu.Lock()
	if p, ok := m.presence[id]; ok {
		m.mu.Unlock()
		return p, nil
	}
	m.mu.Unlock()

	p, err := NewPresenceChannel(id, m.identity, m.trans, ttl)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.presence[id] = p
	m.mu.Unlock()
	return p, nil
}

// Receipts returns the receipt channel for id (creating on first call).
func (m *Messenger) Receipts(id ChannelID) (*ReceiptChannel, error) {
	m.mu.Lock()
	if r, ok := m.receipts[id]; ok {
		m.mu.Unlock()
		return r, nil
	}
	m.mu.Unlock()

	r, err := NewReceiptChannel(id, m.identity, m.trans)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.receipts[id] = r
	m.mu.Unlock()
	return r, nil
}

// RegisterPeerExchange tells every currently-open conversation about
// peer's curve25519 public key, and caches the key so future conversations
// created on this Messenger inherit it automatically. Typically called by
// the SDK on peer discovery, so that subsequent AddMember / sender-key
// rotation can seal envelopes.
func (m *Messenger) RegisterPeerExchange(peer PeerID, pub [32]byte) {
	m.mu.Lock()
	if m.exchangeKeys != nil {
		m.exchangeKeys[peer] = pub
	}
	convs := make([]*Conversation, 0, len(m.conversations))
	for _, c := range m.conversations {
		convs = append(convs, c)
	}
	m.mu.Unlock()
	for _, c := range convs {
		c.RegisterExchangeKey(peer, pub)
	}
}

// --- Capability registry --------------------------------------------------

// AdvertiseCapability records that the local node (or a peer, when
// peer=="") supports cap. When the local flag changes it is meant to be
// gossiped by the application via the profile system; this method is the
// bookkeeping half of that flow. For bookkeeping about a remote peer the
// caller should use ObservePeerCapability — kept as a distinct method so
// that local self-advertisement cannot be spoofed by a peer handler.
func (m *Messenger) AdvertiseCapability(cap string, enabled bool) {
	m.ObservePeerCapability(m.identity.PeerID(), cap, enabled)
	// Keep the ratchet registry in sync for the canonical v1-ratchet flag
	// so downstream code reading m.Ratchet directly sees a consistent
	// view even if it never consults the general capability map.
	if cap == CapabilityV1Ratchet {
		m.Ratchet.AdvertiseCapability(m.identity.PeerID(), enabled)
	}
}

// ObservePeerCapability records a capability flag advertised by peer.
// Typically invoked by the profile-ingest path when a signed profile is
// received; exposed separately from AdvertiseCapability to keep the
// "self vs. peer" intent explicit.
func (m *Messenger) ObservePeerCapability(peer PeerID, cap string, enabled bool) {
	m.capMu.Lock()
	bucket, ok := m.capabilities[peer]
	if !ok {
		bucket = make(map[string]bool)
		m.capabilities[peer] = bucket
	}
	bucket[cap] = enabled
	m.capMu.Unlock()
	if cap == CapabilityV1Ratchet {
		m.Ratchet.AdvertiseCapability(peer, enabled)
	}
}

// SupportsFeature reports whether peer advertised cap as enabled. Unknown
// peers / unknown capabilities return false (fail-closed).
func (m *Messenger) SupportsFeature(peer PeerID, cap string) bool {
	m.capMu.RLock()
	defer m.capMu.RUnlock()
	bucket, ok := m.capabilities[peer]
	if !ok {
		return false
	}
	return bucket[cap]
}

// --- Ratchet bridge -------------------------------------------------------

// RatchetFor returns the per-peer double-ratchet session, or nil if none
// has been bootstrapped. Callers that expect to begin sending before any
// peer message has arrived should call BootstrapRatchet first.
func (m *Messenger) RatchetFor(peer PeerID) *RatchetSession {
	return m.Ratchet.Session(peer)
}

// BootstrapRatchet initiates the double-ratchet session with peer using
// their Ed25519 identity public key. initiator=true means the local node
// will send first (typical for the party that opens a 1:1 conversation).
// The session is cached in the Ratchet registry and returned.
func (m *Messenger) BootstrapRatchet(peer PeerID, peerIdentityPub ed25519.PublicKey, initiator bool) (*RatchetSession, error) {
	if sess := m.Ratchet.Session(peer); sess != nil {
		return sess, nil
	}
	return m.Ratchet.BootstrapSession(peer, m.identityPriv, peerIdentityPub, initiator)
}

// shouldUseRatchet implements ratchetBridge for *Messenger. We route
// through the ratchet only for two-party conversations where both sides
// have advertised CapabilityV1Ratchet and a session has been
// bootstrapped; anything else falls back to sender-key to avoid the
// half-ratcheted state.
func (m *Messenger) shouldUseRatchet(remoteMembers []PeerID) bool {
	if len(remoteMembers) != 1 {
		return false
	}
	peer := remoteMembers[0]
	if !m.SupportsFeature(peer, CapabilityV1Ratchet) {
		return false
	}
	if !m.SupportsFeature(m.identity.PeerID(), CapabilityV1Ratchet) {
		return false
	}
	return m.Ratchet.Session(peer) != nil
}

// ratchetSessionFor implements ratchetBridge for *Messenger.
func (m *Messenger) ratchetSessionFor(peer PeerID) *RatchetSession {
	return m.Ratchet.Session(peer)
}

// observeRatchetMessage marks peer as clearly supporting v1-ratchet.
// Called when we successfully decode a ratchet-version ciphertext from
// that peer. This gives us a second source of truth alongside the
// profile-declared capability so a peer that silently drops the flag mid-
// session can still be recognised.
func (m *Messenger) observeRatchetMessage(peer PeerID) {
	m.ObservePeerCapability(peer, CapabilityV1Ratchet, true)
}

// --- Attachments ----------------------------------------------------------

// Attach uploads content to the Messenger's BlobStore and returns an
// Attachment value suitable for embedding in a Conversation message body
// via MarshalAttachmentBody. Returns an error if no BlobStore has been
// wired via Attachments.SetStore.
func (m *Messenger) Attach(ctx context.Context, content []byte, mimeType, filename string) (*Attachment, error) {
	if m.Attachments.Store() == nil {
		return nil, fmt.Errorf("messaging: no blob store configured (call Attachments.SetStore)")
	}
	return AttachBlob(ctx, content, mimeType, filename)
}

// FetchAttachment decrypts an attachment previously produced by Attach.
// The caller must pass the Attachment value extracted from the decrypted
// message body (so EncryptionKey is populated).
func (m *Messenger) FetchAttachment(ctx context.Context, att Attachment) ([]byte, error) {
	if m.Attachments.Store() == nil {
		return nil, fmt.Errorf("messaging: no blob store configured")
	}
	return FetchBlob(ctx, att)
}

// --- Relay ----------------------------------------------------------------

// EnableRelay wires a store-and-forward relay to this Messenger. role
// matches RelayRoleRelay / RelayRoleStandard. Idempotent: repeat calls
// return the same relay instance with the role updated (Standard -> Relay
// promotion is the typical flow).
func (m *Messenger) EnableRelay(role string, opts ...RelayOption) *MessageRelay {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.relay == nil {
		m.relay = NewMessageRelay(m.trans, role, opts...)
		return m.relay
	}
	// Role updates only — buffers / transport stay put so any in-flight
	// acks the caller has posted are preserved.
	m.relay.mu.Lock()
	m.relay.peerRole = role
	m.relay.mu.Unlock()
	return m.relay
}

// Relay returns the currently-enabled MessageRelay, or nil.
func (m *Messenger) Relay() *MessageRelay {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.relay
}

// BufferForOffline is the Send-path hook: callers with knowledge that
// recipient is offline call this to park the message in the relay. On
// non-relay nodes this is a no-op (the returned RelayAck is zero-valued).
// The method is deliberately not wired into Conversation.Send
// automatically — Conversations are channel-addressed, so "who is offline"
// is a routing decision the caller makes; we only provide the plumbing.
func (m *Messenger) BufferForOffline(ctx context.Context, recipient PeerID, msg Message) (RelayAck, error) {
	m.mu.Lock()
	r := m.relay
	m.mu.Unlock()
	if r == nil || r.Role() != RelayRoleRelay {
		return RelayAck{}, nil
	}
	return r.BufferMessage(ctx, recipient, msg)
}

// Close tears down every channel owned by the Messenger. Idempotent.
func (m *Messenger) Close() error {
	m.mu.Lock()
	convs := m.conversations
	broadcasts := m.broadcasts
	receipts := m.receipts
	presence := m.presence
	relay := m.relay
	m.conversations = nil
	m.broadcasts = nil
	m.receipts = nil
	m.presence = nil
	m.relay = nil
	m.mu.Unlock()

	var first error
	for _, c := range convs {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, b := range broadcasts {
		if err := b.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, r := range receipts {
		if err := r.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, p := range presence {
		if err := p.Close(); err != nil && first == nil {
			first = err
		}
	}
	if relay != nil {
		if err := relay.Stop(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
