/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * relay.go — store-and-forward relay for messages destined for offline
 * recipients. A node runs in "relay" mode to opt into buffering messages
 * on behalf of peers that are currently disconnected, and replays them
 * when those peers reconnect.
 *
 * Minerva's Message type (unlike Mercury's) does not carry an explicit
 * recipient pubkey (messaging is channel-addressed, not peer-addressed).
 * The relay therefore takes recipient as an explicit parameter on the
 * buffering API, and the transport layer picks a per-recipient topic of
 * the form "mnrv.relay.<peerHex>".
 */
package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Store-and-forward defaults.
const (
	// RelayMaxPerPeer is the ring buffer size per recipient.
	RelayMaxPerPeer = 500
	// RelayDefaultTTL matches the existing offline message retention.
	RelayDefaultTTL = 7 * 24 * time.Hour
	// RelayAdvertiseTopic is where nodes announce their relay role so
	// senders can discover which peers to trust for store-and-forward.
	RelayAdvertiseTopic = "mnrv.relay.advertise"
	// RelayAckTopic is where relays send delivery acknowledgements back
	// to senders after they durably buffer a message.
	RelayAckTopic = "mnrv.relay.ack"
	// RelayRoleRelay / RelayRoleStandard label the two supported modes.
	RelayRoleRelay    = "relay"
	RelayRoleStandard = "standard"

	// relayRecipientTopicPrefix is the per-recipient topic namespace used
	// when replaying buffered messages to a peer that has come online.
	relayRecipientTopicPrefix = "mnrv.relay."
)

// ErrRelayStopped is returned when operations are attempted on a stopped
// relay.
var ErrRelayStopped = errors.New("messaging: relay stopped")

// RelayOption configures optional behaviour on NewMessageRelay.
type RelayOption func(*MessageRelay)

// WithRelayMaxPerPeer overrides the default per-peer buffer size.
func WithRelayMaxPerPeer(n int) RelayOption {
	return func(r *MessageRelay) {
		if n > 0 {
			r.maxPerPeer = n
		}
	}
}

// WithRelayTTL overrides the default buffered-message TTL.
func WithRelayTTL(d time.Duration) RelayOption {
	return func(r *MessageRelay) {
		if d > 0 {
			r.ttl = d
		}
	}
}

// WithRelayPersistentStore wires an optional persistent backend (e.g.
// ledger-backed). If unset, buffers are in-memory only and lost on
// restart. The store is keyed by recipient PeerID.
func WithRelayPersistentStore(s RelayPersistentStore) RelayOption {
	return func(r *MessageRelay) { r.persistent = s }
}

// RelayPersistentStore abstracts the durable backing store for buffered
// messages. Implementations MUST be safe for concurrent use.
type RelayPersistentStore interface {
	// Append records a buffered message for the recipient. Must be
	// crash-safe (fsync on return) when the relay is long-running.
	Append(ctx context.Context, recipient PeerID, msg Message) error
	// Load returns all persisted messages for a recipient, ordered by
	// arrival. Called once on startup for each recipient whose topic
	// we resume subscription to.
	Load(ctx context.Context, recipient PeerID) ([]Message, error)
	// Delete removes persisted messages older than the cutoff or whose
	// IDs are in the provided list after successful delivery.
	Delete(ctx context.Context, recipient PeerID, deliveredIDs []MessageID) error
}

// BoundedMessageStore is a per-recipient ring buffer of pending messages
// with TTL enforcement. Safe for concurrent use.
type BoundedMessageStore struct {
	mu         sync.Mutex
	byPeer     map[PeerID][]bufferedMessage
	maxPerPeer int
	ttl        time.Duration
}

type bufferedMessage struct {
	msg      Message
	storedAt time.Time
}

// NewBoundedMessageStore returns a buffer with the given bounds.
func NewBoundedMessageStore(maxPerPeer int, ttl time.Duration) *BoundedMessageStore {
	if maxPerPeer <= 0 {
		maxPerPeer = RelayMaxPerPeer
	}
	if ttl <= 0 {
		ttl = RelayDefaultTTL
	}
	return &BoundedMessageStore{
		byPeer:     make(map[PeerID][]bufferedMessage),
		maxPerPeer: maxPerPeer,
		ttl:        ttl,
	}
}

// Push appends a message for the recipient. Returns (accepted, evicted):
// accepted=false when the message was a duplicate (same MessageID),
// evicted=true when appending caused the ring buffer to drop the oldest
// entry.
func (s *BoundedMessageStore) Push(recipient PeerID, msg Message, now time.Time) (accepted, evicted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf := s.byPeer[recipient]
	// Drop TTL-expired entries up front.
	buf = dropExpired(buf, now, s.ttl)

	// Dedup by ID.
	for _, b := range buf {
		if b.msg.ID == msg.ID {
			s.byPeer[recipient] = buf
			return false, false
		}
	}

	buf = append(buf, bufferedMessage{msg: msg, storedAt: now})
	if len(buf) > s.maxPerPeer {
		buf = buf[len(buf)-s.maxPerPeer:]
		evicted = true
	}
	s.byPeer[recipient] = buf
	return true, evicted
}

// Drain returns (and clears) all non-expired messages for the recipient.
func (s *BoundedMessageStore) Drain(recipient PeerID, now time.Time) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf := dropExpired(s.byPeer[recipient], now, s.ttl)
	delete(s.byPeer, recipient)

	out := make([]Message, 0, len(buf))
	for _, b := range buf {
		out = append(out, b.msg)
	}
	return out
}

// Peek returns a copy of the buffer for a recipient without clearing.
func (s *BoundedMessageStore) Peek(recipient PeerID, now time.Time) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf := dropExpired(s.byPeer[recipient], now, s.ttl)
	s.byPeer[recipient] = buf
	out := make([]Message, 0, len(buf))
	for _, b := range buf {
		out = append(out, b.msg)
	}
	return out
}

// Size returns the number of buffered messages across all recipients.
func (s *BoundedMessageStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for _, buf := range s.byPeer {
		n += len(buf)
	}
	return n
}

func dropExpired(buf []bufferedMessage, now time.Time, ttl time.Duration) []bufferedMessage {
	if len(buf) == 0 || ttl <= 0 {
		return buf
	}
	cutoff := now.Add(-ttl)
	var out []bufferedMessage
	for _, b := range buf {
		if b.storedAt.After(cutoff) {
			out = append(out, b)
		}
	}
	return out
}

// RelayAck is the structure relays publish on RelayAckTopic after a
// message has been durably buffered. Signed so senders can verify origin.
type RelayAck struct {
	MessageID MessageID `json:"messageId"`
	Recipient PeerID    `json:"recipient"`
	Relay     PeerID    `json:"relay,omitempty"`
	StoredAt  time.Time `json:"storedAt"`
	// Overflow is true when accepting this message caused an eviction.
	Overflow bool `json:"overflow,omitempty"`
}

// MessageRelay implements store-and-forward for offline recipients. A
// node runs in "relay" mode (peerRole = RelayRoleRelay) to opt in.
//
// The relay is transport-agnostic: it takes a Transport (Minerva's
// Publish/Subscribe abstraction) rather than raw whisper.Engine, so the
// same code path can be exercised over an in-process LocalBus in tests or
// over a real mesh in production.
type MessageRelay struct {
	store      *BoundedMessageStore
	transport  Transport
	peerRole   string
	maxPerPeer int
	ttl        time.Duration
	persistent RelayPersistentStore

	mu       sync.Mutex
	running  bool
	stopped  bool
	ctx      context.Context
	cancel   context.CancelFunc
	online   map[PeerID]bool // recipient -> true when subscribed
	handlers []func(recipient PeerID, msg Message)
}

// NewMessageRelay constructs a relay wired to a Transport. The transport
// may be nil for tests that exercise buffering in isolation.
func NewMessageRelay(transport Transport, role string, opts ...RelayOption) *MessageRelay {
	r := &MessageRelay{
		transport:  transport,
		peerRole:   role,
		maxPerPeer: RelayMaxPerPeer,
		ttl:        RelayDefaultTTL,
		online:     make(map[PeerID]bool),
	}
	for _, opt := range opts {
		opt(r)
	}
	r.store = NewBoundedMessageStore(r.maxPerPeer, r.ttl)
	return r
}

// Start begins the relay loop. For relay-mode nodes, this advertises
// the node's role so senders can discover it. For standard nodes, Start
// is a no-op.
func (r *MessageRelay) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return ErrRelayStopped
	}
	if r.running {
		r.mu.Unlock()
		return nil
	}
	r.running = true
	r.ctx, r.cancel = context.WithCancel(ctx)
	r.mu.Unlock()

	if r.peerRole == RelayRoleRelay {
		if err := r.advertiseRole(); err != nil {
			return fmt.Errorf("messaging: relay advertise: %w", err)
		}
	}
	return nil
}

// Stop halts the relay. Stop is idempotent.
func (r *MessageRelay) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return nil
	}
	r.running = false
	r.stopped = true
	if r.cancel != nil {
		r.cancel()
	}
	return nil
}

// Role returns the configured role (relay or standard).
func (r *MessageRelay) Role() string { return r.peerRole }

// OnDelivery registers a callback fired whenever the relay replays a
// buffered message to an online recipient.
func (r *MessageRelay) OnDelivery(fn func(recipient PeerID, msg Message)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers = append(r.handlers, fn)
}

// advertiseRole publishes a lightweight announcement on a well-known
// topic so senders can discover relays. A nil transport is a no-op.
func (r *MessageRelay) advertiseRole() error {
	if r.transport == nil {
		return nil
	}
	ann := map[string]any{
		"role":         r.peerRole,
		"maxPerPeer":   r.maxPerPeer,
		"ttlSeconds":   int(r.ttl.Seconds()),
		"advertisedAt": time.Now().UTC(),
	}
	payload, err := json.Marshal(ann)
	if err != nil {
		return err
	}
	return r.transport.Publish(RelayAdvertiseTopic, payload)
}

// BufferMessage accepts a message destined for an offline recipient.
// Returns a RelayAck describing the outcome. Relays call this from the
// inbound-message pipeline after deciding the recipient is offline.
//
// recipient is explicit because Minerva's Message is channel-addressed
// rather than peer-addressed. Session B/C will revisit whether to layer
// a dedicated direct-message envelope on top of Message.
func (r *MessageRelay) BufferMessage(ctx context.Context, recipient PeerID, msg Message) (RelayAck, error) {
	if r.peerRole != RelayRoleRelay {
		return RelayAck{}, fmt.Errorf("messaging: node role %q cannot buffer messages", r.peerRole)
	}
	now := time.Now().UTC()
	accepted, evicted := r.store.Push(recipient, msg, now)
	if !accepted && !evicted {
		// Duplicate — still ack so the sender knows it's stored.
		return RelayAck{
			MessageID: msg.ID,
			Recipient: recipient,
			StoredAt:  now,
		}, nil
	}

	if r.persistent != nil {
		if err := r.persistent.Append(ctx, recipient, msg); err != nil {
			return RelayAck{}, fmt.Errorf("messaging: relay persist: %w", err)
		}
	}
	return RelayAck{
		MessageID: msg.ID,
		Recipient: recipient,
		StoredAt:  now,
		Overflow:  evicted,
	}, nil
}

// MarkOnline is called when the relay detects (e.g. via presence signal)
// that a previously-offline recipient has come online. All buffered
// messages for that recipient are replayed in order via the transport
// on the recipient's relay topic, then cleared from the buffer.
func (r *MessageRelay) MarkOnline(ctx context.Context, recipient PeerID) error {
	if r.peerRole != RelayRoleRelay {
		return nil
	}
	r.mu.Lock()
	r.online[recipient] = true
	handlers := make([]func(PeerID, Message), len(r.handlers))
	copy(handlers, r.handlers)
	r.mu.Unlock()

	now := time.Now().UTC()
	pending := r.store.Drain(recipient, now)
	if len(pending) == 0 {
		return nil
	}

	topic := relayRecipientTopicPrefix + string(recipient)
	var firstErr error
	delivered := make([]MessageID, 0, len(pending))
	for _, m := range pending {
		payload, err := json.Marshal(m)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if r.transport != nil {
			if err := r.transport.Publish(topic, payload); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
		}
		delivered = append(delivered, m.ID)
		for _, h := range handlers {
			h(recipient, m)
		}
	}

	if r.persistent != nil && len(delivered) > 0 {
		if err := r.persistent.Delete(ctx, recipient, delivered); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("messaging: relay persist delete: %w", err)
		}
	}
	return firstErr
}

// MarkOffline records that the recipient's subscriber has disconnected.
// Future messages to that recipient should be buffered.
func (r *MessageRelay) MarkOffline(recipient PeerID) {
	r.mu.Lock()
	delete(r.online, recipient)
	r.mu.Unlock()
}

// IsOnline reports whether the recipient is currently marked online.
func (r *MessageRelay) IsOnline(recipient PeerID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.online[recipient]
}

// BufferedCount returns the number of messages currently buffered for a
// recipient.
func (r *MessageRelay) BufferedCount(recipient PeerID) int {
	now := time.Now().UTC()
	return len(r.store.Peek(recipient, now))
}

// TotalBuffered returns the total number of messages buffered across all
// recipients.
func (r *MessageRelay) TotalBuffered() int { return r.store.Size() }

// RestoreFromPersistent rehydrates buffers from the persistent store for
// a specific recipient. Relays call this during Start after the list of
// tracked recipients is known.
func (r *MessageRelay) RestoreFromPersistent(ctx context.Context, recipient PeerID) error {
	if r.persistent == nil {
		return nil
	}
	msgs, err := r.persistent.Load(ctx, recipient)
	if err != nil {
		return fmt.Errorf("messaging: relay restore: %w", err)
	}
	now := time.Now().UTC()
	for _, m := range msgs {
		r.store.Push(recipient, m, now)
	}
	return nil
}
