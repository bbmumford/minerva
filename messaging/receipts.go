/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * ReceiptChannel — signed read / delivery receipts.
 *
 * Each MarkRead publishes a Receipt signed by the reader. Receipts are
 * aggregated into an ORSet keyed on "msgID::readerID" so duplicates from
 * the same reader merge idempotently and deletions (rare — "I didn't
 * mean to mark this read") are CRDT-safe.
 *
 * Callers query ReaderCount / Readers for a given MessageID to drive UI
 * "seen by X, Y and 3 others".
 */
package messaging

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bbmumford/minerva/crdt"
)

// Receipt is the signed acknowledgement a reader publishes for a
// particular MessageID.
type Receipt struct {
	MessageID MessageID `json:"messageId"`
	Reader    PeerID    `json:"reader"`
	ReadAt    time.Time `json:"readAt"`
	Signature []byte    `json:"signature"`
}

// signingBytes returns the deterministic bytes over which Signature is
// computed. Fixed-length fields, no body, easy to verify.
func (r *Receipt) signingBytes() []byte {
	out := make([]byte, 0, 64)
	out = append(out, []byte(r.MessageID)...)
	out = append(out, 0)
	out = append(out, []byte(r.Reader)...)
	out = append(out, 0)
	out = append(out, []byte(r.ReadAt.UTC().Format(time.RFC3339Nano))...)
	return out
}

// ReceiptChannel tracks signed receipts for a channel.
type ReceiptChannel struct {
	id       ChannelID
	identity Identity
	trans    Transport
	topic    string

	mu       sync.RWMutex
	receipts *crdt.ORSet
	// decoded caches Receipt structs so Readers() doesn't re-parse on
	// every call. Key is the ORSet value string.
	decoded map[string]Receipt

	hlc *crdt.HLC

	unsubTrans func()

	subMu     sync.RWMutex
	subs      map[int]func(Receipt)
	nextSubID int

	closeMu sync.Mutex
	closed  bool
}

// NewReceiptChannel constructs a receipt channel for id.
func NewReceiptChannel(id ChannelID, ident Identity, trans Transport) (*ReceiptChannel, error) {
	if ident == nil {
		return nil, ErrNoIdentity
	}
	if trans == nil {
		return nil, errors.New("messaging: nil transport")
	}
	hlc := crdt.NewHLC(string(ident.PeerID()))
	r := &ReceiptChannel{
		id:       id,
		identity: ident,
		trans:    trans,
		topic:    "mnrv.rcpt." + string(id),
		receipts: crdt.NewORSet("receipts", string(ident.PeerID()), hlc),
		decoded:  make(map[string]Receipt),
		hlc:      hlc,
		subs:     make(map[int]func(Receipt)),
	}
	r.unsubTrans = trans.Subscribe(r.topic, r.onWire)
	return r, nil
}

// ID returns the channel identifier.
func (r *ReceiptChannel) ID() ChannelID { return r.id }

// Topic returns the transport topic.
func (r *ReceiptChannel) Topic() string { return r.topic }

// MarkRead signs a receipt for msgID and publishes it.
func (r *ReceiptChannel) MarkRead(ctx context.Context, msgID MessageID) error {
	r.closeMu.Lock()
	closed := r.closed
	r.closeMu.Unlock()
	if closed {
		return ErrChannelClosed
	}
	rec := Receipt{
		MessageID: msgID,
		Reader:    r.identity.PeerID(),
		ReadAt:    time.Now().UTC(),
	}
	rec.Signature = r.identity.Sign(rec.signingBytes())

	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("messaging: marshal receipt: %w", err)
	}
	// Apply locally first.
	r.apply(rec, data)
	return r.trans.Publish(r.topic, data)
}

// ReaderCount returns the number of distinct readers who have published a
// receipt for msgID.
func (r *ReceiptChannel) ReaderCount(msgID MessageID) int {
	return len(r.Readers(msgID))
}

// Readers returns the set of PeerIDs who have marked msgID as read.
func (r *ReceiptChannel) Readers(msgID MessageID) []PeerID {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[PeerID]struct{})
	for _, v := range r.receipts.Elements() {
		rec, ok := r.decoded[v]
		if !ok {
			continue
		}
		if rec.MessageID != msgID {
			continue
		}
		seen[rec.Reader] = struct{}{}
	}
	out := make([]PeerID, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out
}

// Receipts returns every known (verified) receipt.
func (r *ReceiptChannel) Receipts() []Receipt {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Receipt, 0, len(r.decoded))
	for _, v := range r.receipts.Elements() {
		if rec, ok := r.decoded[v]; ok {
			out = append(out, rec)
		}
	}
	return out
}

// Subscribe registers cb for every verified receipt applied locally.
// Returns an idempotent unsubscribe func.
func (r *ReceiptChannel) Subscribe(cb func(Receipt)) func() {
	r.subMu.Lock()
	id := r.nextSubID
	r.nextSubID++
	r.subs[id] = cb
	r.subMu.Unlock()
	return func() {
		r.subMu.Lock()
		delete(r.subs, id)
		r.subMu.Unlock()
	}
}

// Close detaches the transport subscription. Idempotent.
func (r *ReceiptChannel) Close() error {
	r.closeMu.Lock()
	if r.closed {
		r.closeMu.Unlock()
		return nil
	}
	r.closed = true
	unsub := r.unsubTrans
	r.closeMu.Unlock()
	if unsub != nil {
		unsub()
	}
	return nil
}

// apply verifies the signature, records the receipt in the ORSet, and
// notifies subscribers.
func (r *ReceiptChannel) apply(rec Receipt, raw []byte) {
	readerPub, err := peerIDFromHex(rec.Reader)
	if err != nil {
		return
	}
	if !ed25519.Verify(readerPub, rec.signingBytes(), rec.Signature) {
		return
	}
	key := receiptKey(rec.MessageID, rec.Reader)

	r.mu.Lock()
	if _, exists := r.decoded[key]; exists {
		r.mu.Unlock()
		return
	}
	r.receipts.Add(key)
	r.decoded[key] = rec
	r.mu.Unlock()

	r.subMu.RLock()
	subs := make([]func(Receipt), 0, len(r.subs))
	for _, cb := range r.subs {
		subs = append(subs, cb)
	}
	r.subMu.RUnlock()
	for _, cb := range subs {
		cb(rec)
	}
	_ = raw // reserved for future delta-sync path
}

// onWire decodes and applies an inbound receipt.
func (r *ReceiptChannel) onWire(payload []byte) {
	var rec Receipt
	if err := json.Unmarshal(payload, &rec); err != nil {
		return
	}
	r.apply(rec, payload)
}

// receiptKey returns the canonical ORSet key for (msgID, reader).
func receiptKey(msgID MessageID, reader PeerID) string {
	var sb strings.Builder
	sb.Grow(len(msgID) + 2 + len(reader))
	sb.WriteString(string(msgID))
	sb.WriteString("::")
	sb.WriteString(string(reader))
	return sb.String()
}
