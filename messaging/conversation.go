/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * Conversation — many-to-many encrypted chat built on ORSet (membership)
 * plus a message log keyed by MessageID. Encryption uses the sender-keys
 * scheme defined in senderkeys.go by default; when every participant of a
 * 2-member Conversation has advertised the v1-ratchet capability, Send
 * routes through the double-ratchet session from ratchet.go instead
 * (providing forward secrecy + post-compromise security).
 *
 * A Conversation with exactly 2 members IS the direct-chat primitive —
 * there is no separate DirectChannel type. 3+ member Conversations always
 * use the sender-key path because the double ratchet does not generalise
 * to multi-party trivially.
 *
 * A Conversation is the bulkhead between the pure-CRDT bookkeeping and
 * the production wire path. Every mutation (add member, send, edit,
 * delete) produces a wire Envelope that is Publish()ed via the transport;
 * peers apply the envelope locally which updates the same CRDTs.
 */
package messaging

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/bbmumford/minerva/crdt"
)

// Envelope is the wire format for every message that crosses a conversation
// topic. Kind discriminates the payload; only the relevant field is set.
type envelope struct {
	Kind       envKind            `json:"kind"`
	Message    *Message           `json:"message,omitempty"`
	MemberAdd  *memberOp          `json:"memberAdd,omitempty"`
	MemberRem  *memberOp          `json:"memberRem,omitempty"`
	SenderKey  *envelopeSenderKey `json:"senderKey,omitempty"`
}

// envKind discriminates envelope payloads.
type envKind int

const (
	envMessage envKind = iota
	envMemberAdd
	envMemberRemove
	envSenderKey
)

// memberOp is the payload for ORSet membership mutations.
type memberOp struct {
	Peer   PeerID `json:"peer"`
	Author PeerID `json:"author"`
	At     uint64 `json:"at"` // HLC
}

// envelopeSenderKey carries a sealed sender key to one recipient.
type envelopeSenderKey struct {
	Author    PeerID   `json:"author"`
	AuthorPub [32]byte `json:"authorPub"` // curve25519 public key
	Recipient PeerID   `json:"recipient"`
	Nonce     [24]byte `json:"nonce"`
	Sealed    []byte   `json:"sealed"`
}

// ciphertextVersion is the leading byte prepended to every encrypted body
// so the decrypt path can choose between sender-key and double-ratchet.
// Version 0 = sender-key (legacy, channel-wide symmetric key). Version 1
// = double ratchet (per-peer, per-direction forward-secret chain). The
// version byte is outside the AEAD so it is not covered by authentication;
// on mismatch the decrypt path falls back cleanly to the sender-key
// branch rather than erroring.
const (
	ciphertextVersionSenderKey byte = 0x00
	ciphertextVersionRatchet   byte = 0x01
)

// Conversation is the many-to-many encrypted chat primitive. A
// Conversation with exactly 2 members models 1:1 direct messages; there
// is no separate DirectChannel type. 3+ member Conversations always use
// the sender-key path; 2-member Conversations may upgrade to double
// ratchet when both peers advertise v1-ratchet support (see Messenger's
// capability registry).
type Conversation struct {
	id       ChannelID
	identity Identity
	exchange *ExchangeIdentity
	trans    Transport
	topic    string

	// hlc drives both the membership ORSet and the message ordering.
	hlc *crdt.HLC

	mu sync.RWMutex

	// members is an ORSet of member PeerIDs. Add/remove are soft (ORSet
	// tombstone) which means history is preserved for delta-sync even
	// after a peer has left the channel.
	members *crdt.ORSet

	// log is the ordered message store keyed by MessageID. It is a plain
	// map rather than a CRDT because messages are immutable after send —
	// edits live as new messages whose EditOf points at the original;
	// deletes are tombstones on the top-level `tombstones` ORSet.
	log map[MessageID]*Message

	// order is the insertion order (MessageID list) for History().
	order []MessageID

	// tombstones records deleted MessageIDs (author-signed).
	tombstones map[MessageID]bool

	// edits indexes edits by the original MessageID so a UI can walk the
	// edit chain without scanning the whole log.
	edits map[MessageID][]MessageID

	// ratchet holds the local sender key + known peer sender keys.
	ratchet *SenderKeyRatchet

	// peerExchange maps PeerID to the curve25519 public key we use when
	// sealing sender-key envelopes. Populated whenever a peer publishes
	// their key (either on join or on sender-key rotation).
	peerExchange map[PeerID][32]byte

	// subscribers are notified when a new Message is decrypted and
	// applied. Registered via Subscribe, detached via the returned
	// unsubscribe func.
	subMu      sync.RWMutex
	subs       map[int]func(Message)
	nextSubID  int
	unsubTrans func()
	closed     bool

	// ratchetBridge provides per-peer double-ratchet sessions and
	// capability flags. Set by Messenger when a Conversation is opened
	// through that API; left nil for direct NewConversation callers who
	// operate on the legacy sender-key path only.
	ratchetBridge ratchetBridge
}

// ratchetBridge is the narrow hook the Conversation uses to route through
// the per-peer double ratchet without importing the full Messenger type.
// Implemented by *Messenger.
type ratchetBridge interface {
	// shouldUseRatchet reports whether every remote participant of the
	// conversation has advertised v1-ratchet AND the session pair has
	// been bootstrapped. Callers only use ratchet when this returns true
	// to avoid half-ratcheted conversations.
	shouldUseRatchet(remoteMembers []PeerID) bool
	// ratchetSessionFor returns the session for a given remote peer, or
	// nil if one has not been bootstrapped yet.
	ratchetSessionFor(peer PeerID) *RatchetSession
	// observeRatchetMessage is invoked whenever we decode a ciphertext
	// that carries the ratchet version byte, so the capability registry
	// can note that the peer clearly supports v1-ratchet.
	observeRatchetMessage(peer PeerID)
}

// NewConversation creates a new Conversation bound to the given identity
// and transport. The caller is responsible for calling AddMember for every
// initial participant (including themselves) and publishing the initial
// sender-key envelopes — convenience shortcuts are provided by
// Messenger.OpenConversation in sdk.go.
func NewConversation(id ChannelID, ident Identity, exch *ExchangeIdentity, trans Transport) (*Conversation, error) {
	if ident == nil {
		return nil, ErrNoIdentity
	}
	if trans == nil {
		return nil, errors.New("messaging: nil transport")
	}
	if exch == nil {
		return nil, errors.New("messaging: nil exchange identity")
	}
	hlc := crdt.NewHLC(string(ident.PeerID()))
	ratchet, err := NewSenderKeyRatchet()
	if err != nil {
		return nil, err
	}

	c := &Conversation{
		id:           id,
		identity:     ident,
		exchange:     exch,
		trans:        trans,
		topic:        "mnrv.conv." + string(id),
		hlc:          hlc,
		members:      crdt.NewORSet("members", string(ident.PeerID()), hlc),
		log:          make(map[MessageID]*Message),
		tombstones:   make(map[MessageID]bool),
		edits:        make(map[MessageID][]MessageID),
		ratchet:      ratchet,
		peerExchange: make(map[PeerID][32]byte),
		subs:         make(map[int]func(Message)),
	}

	// Self is always an installed sender key so that SealBody/OpenBody
	// round-trips locally (useful for tests and for re-hydrating history).
	c.ratchet.Install(ident.PeerID(), ratchet.OwnKey())
	c.peerExchange[ident.PeerID()] = exch.Pub

	c.unsubTrans = trans.Subscribe(c.topic, c.onWire)
	return c, nil
}

// ID returns the channel identifier.
func (c *Conversation) ID() ChannelID { return c.id }

// Topic returns the transport topic used by this conversation.
func (c *Conversation) Topic() string { return c.topic }

// installRatchetBridge wires the per-peer double-ratchet hook. Package-
// internal so only the Messenger (same package) can bridge the two.
func (c *Conversation) installRatchetBridge(b ratchetBridge) {
	c.mu.Lock()
	c.ratchetBridge = b
	c.mu.Unlock()
}

// Close detaches the transport subscription and rejects further
// operations. Close is idempotent.
func (c *Conversation) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	unsub := c.unsubTrans
	c.mu.Unlock()
	if unsub != nil {
		unsub()
	}
	return nil
}

// --- Membership ----------------------------------------------------------

// AddMember inserts peer into the ORSet and publishes a sealed sender-key
// envelope addressed to peer so they can decrypt future messages. The
// caller must have previously learned peer's curve25519 exchange public
// key via RegisterExchangeKey (normally the SDK does that as soon as a
// peer joins the Messenger).
func (c *Conversation) AddMember(ctx context.Context, peer PeerID) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrChannelClosed
	}
	recipPub, ok := c.peerExchange[peer]
	ownKey := c.ratchet.OwnKey()
	c.members.Add(string(peer))
	c.mu.Unlock()

	env := envelope{
		Kind: envMemberAdd,
		MemberAdd: &memberOp{
			Peer:   peer,
			Author: c.identity.PeerID(),
			At:     c.hlc.Now(),
		},
	}
	if err := c.publish(env); err != nil {
		return err
	}

	// Distribute our sender key to the newly-added member. If we don't yet
	// know their exchange key, skip — the recipient will request it
	// (see onWire / envSenderKey below) when they first see a message
	// they can't decrypt. This keeps the add atomic rather than tying it
	// to a blocking out-of-band lookup.
	if ok {
		if err := c.distributeSenderKeyTo(peer, recipPub, ownKey); err != nil {
			return err
		}
	}
	return nil
}

// RemoveMember soft-removes peer from the conversation (ORSet tombstone)
// and rotates the local sender key so future messages are forward-secret
// against the departed member. The rotated key is distributed to
// remaining members.
func (c *Conversation) RemoveMember(ctx context.Context, peer PeerID) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrChannelClosed
	}
	c.members.Remove(string(peer))
	c.ratchet.Forget(peer)
	delete(c.peerExchange, peer)
	c.mu.Unlock()

	env := envelope{
		Kind: envMemberRemove,
		MemberRem: &memberOp{
			Peer:   peer,
			Author: c.identity.PeerID(),
			At:     c.hlc.Now(),
		},
	}
	if err := c.publish(env); err != nil {
		return err
	}

	// Rotate and re-distribute. Errors in distribution are returned to
	// the caller — leaving a stale key would compromise the whole point
	// of rotation.
	if err := c.ratchet.Rotate(); err != nil {
		return err
	}
	c.ratchet.Install(c.identity.PeerID(), c.ratchet.OwnKey())
	return c.redistributeSenderKey()
}

// Members returns the current live member PeerIDs (sorted).
func (c *Conversation) Members() []PeerID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	vals := c.members.Elements()
	out := make([]PeerID, 0, len(vals))
	for _, v := range vals {
		out = append(out, PeerID(v))
	}
	return out
}

// IsMember reports whether peer is currently in the ORSet.
func (c *Conversation) IsMember(peer PeerID) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.members.Contains(string(peer))
}

// RegisterExchangeKey associates peer's curve25519 public key with their
// PeerID so subsequent AddMember / re-distribute calls can seal sender-key
// envelopes to them. Typically called by the SDK on peer discovery.
func (c *Conversation) RegisterExchangeKey(peer PeerID, pub [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerExchange[peer] = pub
}

// distributeSenderKeyTo seals the current own-sender-key and publishes a
// SenderKey envelope to a single recipient. Called under no lock.
func (c *Conversation) distributeSenderKeyTo(recipient PeerID, recipPub [32]byte, key [senderKeyLen]byte) error {
	nonce, sealed, err := c.exchange.SealFor(recipPub, key)
	if err != nil {
		return err
	}
	return c.publish(envelope{
		Kind: envSenderKey,
		SenderKey: &envelopeSenderKey{
			Author:    c.identity.PeerID(),
			AuthorPub: c.exchange.Pub,
			Recipient: recipient,
			Nonce:     nonce,
			Sealed:    sealed,
		},
	})
}

// redistributeSenderKey seals the current own-sender-key for every live
// member (except self) whose exchange key is known.
func (c *Conversation) redistributeSenderKey() error {
	c.mu.RLock()
	var recipients []struct {
		id  PeerID
		pub [32]byte
	}
	for _, m := range c.members.Elements() {
		pid := PeerID(m)
		if pid == c.identity.PeerID() {
			continue
		}
		if pub, ok := c.peerExchange[pid]; ok {
			recipients = append(recipients, struct {
				id  PeerID
				pub [32]byte
			}{pid, pub})
		}
	}
	own := c.ratchet.OwnKey()
	c.mu.RUnlock()

	for _, r := range recipients {
		if err := c.distributeSenderKeyTo(r.id, r.pub, own); err != nil {
			return err
		}
	}
	return nil
}

// --- Send / Edit / Delete -----------------------------------------------

// Send encrypts body, signs the resulting message, and publishes it. For
// 2-member conversations where both peers have advertised v1-ratchet, the
// body is ciphertext from the double-ratchet session; otherwise it is
// ciphertext from the legacy sender-key ratchet. The returned Message
// reflects what peers will see (Body is ciphertext).
func (c *Conversation) Send(ctx context.Context, body []byte) (*Message, error) {
	return c.sendKind(ctx, body, KindText, "", "")
}

// SendKind is like Send but lets the caller pick the MessageKind and
// optional ReplyTo / EditOf references. Used by Edit and by higher-level
// feature code (attachments, announcements, etc.).
func (c *Conversation) SendKind(ctx context.Context, body []byte, kind MessageKind, replyTo, editOf MessageID) (*Message, error) {
	return c.sendKind(ctx, body, kind, replyTo, editOf)
}

func (c *Conversation) sendKind(ctx context.Context, body []byte, kind MessageKind, replyTo, editOf MessageID) (*Message, error) {
	c.mu.RLock()
	closed := c.closed
	bridge := c.ratchetBridge
	c.mu.RUnlock()
	if closed {
		return nil, ErrChannelClosed
	}

	// Only members may send; authors are always their own members once
	// the initial AddMember has run.
	if !c.IsMember(c.identity.PeerID()) {
		return nil, ErrNotMember
	}

	ct, err := c.encryptBody(bridge, body)
	if err != nil {
		return nil, err
	}

	msg := &Message{
		ID:        NewMessageID(),
		ChannelID: c.id,
		Author:    c.identity.PeerID(),
		SentAt:    time.Now().UTC(),
		Body:      ct,
		Kind:      kind,
		ReplyTo:   replyTo,
		EditOf:    editOf,
	}
	msg.Signature = c.identity.Sign(msg.signingBytes())

	if err := c.publish(envelope{Kind: envMessage, Message: msg}); err != nil {
		return nil, err
	}
	// Mirror the MessagingSentCount metric Mercury publishes on its own
	// send path. The hook is registered by higher-level SDKs (Mercury in
	// Session C) so Minerva stays free of the plutus/observability
	// dependency. Invoked unconditionally — the hook is idempotent and
	// nil-safe.
	if ctx == nil {
		ctx = context.Background()
	}
	invokeMessageSentHook(ctx)
	// Apply locally too — publishers process their own envelopes via
	// onWire (LocalBus fans out to every subscriber including the sender;
	// WhisperTransport also notifies local subscribers). No double-apply
	// because applyMessage is idempotent on ID.
	return msg, nil
}

// encryptBody routes through either the double ratchet (2-member conv,
// both peers advertise v1-ratchet and a session exists) or the sender-key
// ratchet (everything else). The returned bytes carry a leading version
// byte so DecryptBody can dispatch without needing side-band metadata.
func (c *Conversation) encryptBody(bridge ratchetBridge, plain []byte) ([]byte, error) {
	remotes := c.remoteMembers()
	if bridge != nil && len(remotes) == 1 && bridge.shouldUseRatchet(remotes) {
		sess := bridge.ratchetSessionFor(remotes[0])
		if sess != nil {
			ct, err := EncryptRatchet(plain, sess)
			if err != nil {
				return nil, err
			}
			out := make([]byte, 0, len(ct)+1)
			out = append(out, ciphertextVersionRatchet)
			out = append(out, ct...)
			return out, nil
		}
	}

	// Fall back to the sender-key path.
	raw, err := c.ratchet.SealBody(plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(raw)+1)
	out = append(out, ciphertextVersionSenderKey)
	out = append(out, raw...)
	return out, nil
}

// remoteMembers returns every live member except the local identity.
// Sorted so the output is deterministic (callers such as shouldUseRatchet
// may compare against their own capability map).
func (c *Conversation) remoteMembers() []PeerID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]PeerID, 0)
	for _, m := range c.members.Elements() {
		pid := PeerID(m)
		if pid == c.identity.PeerID() {
			continue
		}
		out = append(out, pid)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Edit creates a new Message with EditOf=msgID and the same ChannelID.
// Consumers resolve "latest" by walking EditOf and picking the most
// recent by SentAt.
func (c *Conversation) Edit(ctx context.Context, msgID MessageID, newBody []byte) (*Message, error) {
	c.mu.RLock()
	orig, ok := c.log[msgID]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("messaging: edit target %s not found", msgID)
	}
	if orig.Author != c.identity.PeerID() {
		return nil, fmt.Errorf("messaging: cannot edit another author's message")
	}
	return c.SendKind(ctx, newBody, orig.Kind, orig.ReplyTo, msgID)
}

// Delete tombstones msgID. The tombstone is itself a signed Message of
// KindText with Deleted=true so peers can verify the author actually
// requested the deletion.
func (c *Conversation) Delete(ctx context.Context, msgID MessageID) error {
	c.mu.RLock()
	orig, ok := c.log[msgID]
	c.mu.RUnlock()
	if !ok {
		return fmt.Errorf("messaging: delete target %s not found", msgID)
	}
	if orig.Author != c.identity.PeerID() {
		return fmt.Errorf("messaging: cannot delete another author's message")
	}

	tomb := &Message{
		ID:        NewMessageID(),
		ChannelID: c.id,
		Author:    c.identity.PeerID(),
		SentAt:    time.Now().UTC(),
		Kind:      KindText,
		EditOf:    msgID,
		Deleted:   true,
	}
	tomb.Signature = c.identity.Sign(tomb.signingBytes())
	return c.publish(envelope{Kind: envMessage, Message: tomb})
}

// --- History / Subscribe ------------------------------------------------

// History returns every non-tombstoned message with SentAt >= since,
// sorted by SentAt ascending. Edits replace their originals so only the
// latest version per original-ID is returned.
func (c *Conversation) History(since time.Time) []Message {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Resolve latest per original ID using the same tiebreak rules as
	// LatestVersion (edits beat originals on equal SentAt; ID lex break
	// on otherwise equal edits).
	latest := make(map[MessageID]*Message, len(c.log))
	for _, m := range c.log {
		root := m.ID
		if m.EditOf != "" {
			root = m.EditOf
		}
		if c.tombstones[root] || c.tombstones[m.ID] {
			continue
		}
		if existing, ok := latest[root]; ok {
			if versionBeats(m, existing) {
				latest[root] = m
			}
		} else {
			latest[root] = m
		}
	}

	out := make([]Message, 0, len(latest))
	for _, m := range latest {
		if m.SentAt.Before(since) {
			continue
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SentAt.Equal(out[j].SentAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].SentAt.Before(out[j].SentAt)
	})
	return out
}

// Subscribe registers cb for every message (including membership /
// sender-key envelopes applied locally). Returns an idempotent
// unsubscribe func.
func (c *Conversation) Subscribe(cb func(Message)) func() {
	c.subMu.Lock()
	id := c.nextSubID
	c.nextSubID++
	c.subs[id] = cb
	c.subMu.Unlock()
	return func() {
		c.subMu.Lock()
		delete(c.subs, id)
		c.subMu.Unlock()
	}
}

// DecryptBody opens the ciphertext of a message whose author key we
// hold. Dispatches on the leading version byte: 0x01 = double ratchet,
// 0x00 (or missing, for wire-backward-compat) = sender-key. Returns the
// plaintext, or an error if we lack the key / the ciphertext is invalid.
func (c *Conversation) DecryptBody(msg *Message) ([]byte, error) {
	if msg.Deleted {
		return nil, nil
	}
	body := msg.Body
	if len(body) == 0 {
		return nil, nil
	}

	c.mu.RLock()
	bridge := c.ratchetBridge
	c.mu.RUnlock()

	// Version byte dispatch.
	switch body[0] {
	case ciphertextVersionRatchet:
		if bridge == nil {
			return nil, fmt.Errorf("messaging: ratchet ciphertext but no bridge installed")
		}
		sess := bridge.ratchetSessionFor(msg.Author)
		if sess == nil {
			return nil, ErrRatchetSessionMissing
		}
		pt, err := DecryptRatchet(body[1:], sess)
		if err != nil {
			return nil, err
		}
		bridge.observeRatchetMessage(msg.Author)
		return pt, nil
	case ciphertextVersionSenderKey:
		return c.ratchet.OpenBody(msg.Author, body[1:])
	default:
		// Back-compat: any byte that is not a known version is treated as
		// raw sender-key ciphertext. This matters for messages created
		// before the version-byte was introduced.
		return c.ratchet.OpenBody(msg.Author, body)
	}
}

// --- Wire path -----------------------------------------------------------

// publish marshals env and hands it to the transport.
func (c *Conversation) publish(env envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("messaging: marshal envelope: %w", err)
	}
	return c.trans.Publish(c.topic, data)
}

// onWire receives every envelope published on our topic and applies it.
// Concurrent deliveries are serialised by c.mu.
func (c *Conversation) onWire(payload []byte) {
	var env envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return // malformed; drop
	}
	switch env.Kind {
	case envMessage:
		if env.Message != nil {
			c.applyMessage(env.Message)
		}
	case envMemberAdd:
		if env.MemberAdd != nil {
			added := env.MemberAdd.Peer
			c.mu.Lock()
			c.members.Add(string(added))
			// If we have an exchange pub for the newcomer and they aren't
			// us, seal our current sender key to them. This is the
			// "catch-up" path: when a peer joins late, every existing
			// author responds to their AddMember announcement by
			// distributing their own sender key.
			recipPub, havePub := c.peerExchange[added]
			ownKey := c.ratchet.OwnKey()
			isSelf := added == c.identity.PeerID()
			c.mu.Unlock()
			if !isSelf && havePub {
				_ = c.distributeSenderKeyTo(added, recipPub, ownKey)
			}
		}
	case envMemberRemove:
		if env.MemberRem != nil {
			c.mu.Lock()
			c.members.Remove(string(env.MemberRem.Peer))
			c.ratchet.Forget(env.MemberRem.Peer)
			delete(c.peerExchange, env.MemberRem.Peer)
			c.mu.Unlock()
		}
	case envSenderKey:
		if env.SenderKey != nil {
			c.applySenderKey(env.SenderKey)
		}
	}
}

// applyMessage verifies the author signature and adds the message to the
// log / tombstone index. Idempotent on MessageID.
func (c *Conversation) applyMessage(msg *Message) {
	if msg.ChannelID != c.id {
		return
	}
	authorPub, err := peerIDFromHex(msg.Author)
	if err != nil {
		return
	}
	if !ed25519.Verify(authorPub, msg.signingBytes(), msg.Signature) {
		return
	}

	c.mu.Lock()
	if _, exists := c.log[msg.ID]; exists {
		c.mu.Unlock()
		return
	}
	cp := *msg
	c.log[msg.ID] = &cp
	c.order = append(c.order, msg.ID)
	if msg.Deleted && msg.EditOf != "" {
		c.tombstones[msg.EditOf] = true
	}
	if msg.EditOf != "" && !msg.Deleted {
		c.edits[msg.EditOf] = append(c.edits[msg.EditOf], msg.ID)
	}
	c.mu.Unlock()

	c.fanoutToSubs(cp)
}

// applySenderKey stores a peer's sender key if the envelope was
// addressed to us and unwraps under the author's curve25519 key.
func (c *Conversation) applySenderKey(sk *envelopeSenderKey) {
	// Remember the author's exchange pub regardless of whether the
	// envelope is addressed to us — we may need it later.
	c.mu.Lock()
	c.peerExchange[sk.Author] = sk.AuthorPub
	c.mu.Unlock()

	if sk.Recipient != c.identity.PeerID() {
		return
	}
	key, err := c.exchange.OpenSealed(sk.AuthorPub, sk.Nonce, sk.Sealed)
	if err != nil {
		return
	}
	c.ratchet.Install(sk.Author, key)
}

// fanoutToSubs delivers msg to every registered subscriber under a
// snapshot of the subs map (so subscribers can unsubscribe without
// deadlocking).
func (c *Conversation) fanoutToSubs(msg Message) {
	c.subMu.RLock()
	subs := make([]func(Message), 0, len(c.subs))
	for _, cb := range c.subs {
		subs = append(subs, cb)
	}
	c.subMu.RUnlock()
	for _, cb := range subs {
		cb(msg)
	}
}

// DebugExchangePub returns the local author's curve25519 public key.
// Exposed for tests and for SDKs that publish the key out-of-band.
func (c *Conversation) DebugExchangePub() [32]byte { return c.exchange.Pub }

// DebugHexPub returns the exchange pubkey hex for logs.
func (c *Conversation) DebugHexPub() string {
	p := c.exchange.Pub
	return hex.EncodeToString(p[:])
}
