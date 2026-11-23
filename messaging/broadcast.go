/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * Broadcast — 1-to-many pub/sub with no membership bookkeeping. Any peer
 * can subscribe; only the publisher (whose PeerID was fixed at
 * construction time) is expected to Publish. The channel verifies the
 * signature on every inbound message so random peers can't forge
 * announcements.
 *
 * Use cases: sellers broadcasting shipping updates, system-wide
 * announcements, read-only news channels. Encryption is intentionally
 * absent — if the payload is sensitive, authors should encrypt at the
 * application layer or use a Conversation instead.
 */
package messaging

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Broadcast is a signed, unencrypted fan-out channel.
type Broadcast struct {
	id          ChannelID
	publisherID PeerID
	identity    Identity // set only on the publisher side; nil on subscribers
	trans       Transport
	topic       string

	subMu     sync.RWMutex
	subs      map[int]func(Message)
	nextSubID int

	unsubTrans func()

	mu     sync.Mutex
	closed bool
}

// NewBroadcast constructs a subscriber-only broadcast channel —
// publisherID identifies the expected author; every inbound message with
// a different author or an invalid signature is dropped.
func NewBroadcast(id ChannelID, publisherID PeerID, trans Transport) (*Broadcast, error) {
	if trans == nil {
		return nil, errors.New("messaging: nil transport")
	}
	b := &Broadcast{
		id:          id,
		publisherID: publisherID,
		trans:       trans,
		topic:       "mnrv.bcast." + string(id),
		subs:        make(map[int]func(Message)),
	}
	b.unsubTrans = trans.Subscribe(b.topic, b.onWire)
	return b, nil
}

// NewPublisherBroadcast constructs a broadcast channel that the local
// identity will publish to. Subscribing is also permitted so the
// publisher sees its own echo (useful for local UIs that share code with
// remote peers).
func NewPublisherBroadcast(id ChannelID, ident Identity, trans Transport) (*Broadcast, error) {
	if ident == nil {
		return nil, ErrNoIdentity
	}
	b, err := NewBroadcast(id, ident.PeerID(), trans)
	if err != nil {
		return nil, err
	}
	b.identity = ident
	return b, nil
}

// ID returns the channel identifier.
func (b *Broadcast) ID() ChannelID { return b.id }

// Topic returns the transport topic.
func (b *Broadcast) Topic() string { return b.topic }

// Publisher returns the expected publisher PeerID.
func (b *Broadcast) Publisher() PeerID { return b.publisherID }

// Close detaches the transport subscription. Idempotent.
func (b *Broadcast) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	unsub := b.unsubTrans
	b.mu.Unlock()
	if unsub != nil {
		unsub()
	}
	return nil
}

// Publish signs and fans out a new broadcast message. Only the publisher
// identity (the one passed to NewPublisherBroadcast) is allowed to call
// this; subscriber-only channels return ErrNoIdentity.
func (b *Broadcast) Publish(ctx context.Context, body []byte) (*Message, error) {
	if b.identity == nil {
		return nil, ErrNoIdentity
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return nil, ErrChannelClosed
	}

	msg := &Message{
		ID:        NewMessageID(),
		ChannelID: b.id,
		Author:    b.identity.PeerID(),
		SentAt:    time.Now().UTC(),
		Body:      body,
		Kind:      KindText,
	}
	msg.Signature = b.identity.Sign(msg.signingBytes())

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("messaging: marshal broadcast: %w", err)
	}
	if err := b.trans.Publish(b.topic, data); err != nil {
		return nil, err
	}
	return msg, nil
}

// Subscribe registers cb for every verified inbound message. Returns an
// idempotent unsubscribe func.
func (b *Broadcast) Subscribe(cb func(Message)) func() {
	b.subMu.Lock()
	id := b.nextSubID
	b.nextSubID++
	b.subs[id] = cb
	b.subMu.Unlock()
	return func() {
		b.subMu.Lock()
		delete(b.subs, id)
		b.subMu.Unlock()
	}
}

// onWire decodes, verifies, and fans out a broadcast message.
func (b *Broadcast) onWire(payload []byte) {
	var msg Message
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}
	if msg.ChannelID != b.id || msg.Author != b.publisherID {
		return
	}
	authorPub, err := peerIDFromHex(msg.Author)
	if err != nil {
		return
	}
	if !ed25519.Verify(authorPub, msg.signingBytes(), msg.Signature) {
		return
	}

	b.subMu.RLock()
	subs := make([]func(Message), 0, len(b.subs))
	for _, cb := range b.subs {
		subs = append(subs, cb)
	}
	b.subMu.RUnlock()
	for _, cb := range subs {
		cb(msg)
	}
}
