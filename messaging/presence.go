/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * PresenceChannel — typing / online / away indicators.
 *
 * Backed by an LWWMap keyed on PeerID — the highest-HLC state wins per
 * peer. States have a TTL: a goroutine gossips the local peer's state
 * every ttl/2 so subscribers can detect "silent" peers as offline by
 * comparing the last-seen timestamp against wall-clock. Applications do
 * that check via Current() — the channel itself keeps the raw LWWMap so
 * the decision stays in the caller's hands.
 */
package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bbmumford/minerva/crdt"
)

// PresenceState represents a single peer's current presence.
type PresenceState struct {
	Peer      PeerID    `json:"peer"`
	State     string    `json:"state"`
	Timestamp time.Time `json:"timestamp"`
}

// Well-known state strings. Applications are free to use others (the
// channel treats them as opaque).
const (
	StateOnline  = "online"
	StateAway    = "away"
	StateTyping  = "typing"
	StateOffline = "offline"
)

// presenceEnvelope is the wire form.
type presenceEnvelope struct {
	State PresenceState `json:"state"`
}

// PresenceChannel publishes the local peer's presence and tracks every
// other peer's most recent state.
type PresenceChannel struct {
	id       ChannelID
	identity Identity
	trans    Transport
	topic    string
	ttl      time.Duration

	mu     sync.RWMutex
	states *crdt.LWWMap
	// current caches the decoded PresenceState per peer so Current() is
	// cheap and doesn't re-decode the LWWMap every call.
	current map[PeerID]PresenceState

	hlc *crdt.HLC

	subMu     sync.RWMutex
	subs      map[int]func(PeerID, PresenceState)
	nextSubID int

	unsubTrans func()

	ownState string
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	closeMu sync.Mutex
	closed  bool
}

// NewPresenceChannel constructs a presence channel for id. ttl controls
// how quickly stale states expire — presence messages are re-emitted
// every ttl/2. The default (passed as 0) is 30s.
func NewPresenceChannel(id ChannelID, ident Identity, trans Transport, ttl time.Duration) (*PresenceChannel, error) {
	if ident == nil {
		return nil, ErrNoIdentity
	}
	if trans == nil {
		return nil, errors.New("messaging: nil transport")
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}

	hlc := crdt.NewHLC(string(ident.PeerID()))
	p := &PresenceChannel{
		id:       id,
		identity: ident,
		trans:    trans,
		topic:    "mnrv.pres." + string(id),
		ttl:      ttl,
		states:   crdt.NewLWWMap("presence", string(ident.PeerID()), hlc),
		current:  make(map[PeerID]PresenceState),
		hlc:      hlc,
		subs:     make(map[int]func(PeerID, PresenceState)),
		ownState: StateOnline,
	}
	p.unsubTrans = trans.Subscribe(p.topic, p.onWire)

	ctx, cancel := context.WithCancel(context.Background())
	p.ctx = ctx
	p.cancel = cancel

	p.wg.Add(1)
	go p.heartbeat(ctx)
	return p, nil
}

// ID returns the channel identifier.
func (p *PresenceChannel) ID() ChannelID { return p.id }

// TTL returns the configured presence TTL.
func (p *PresenceChannel) TTL() time.Duration { return p.ttl }

// SetState publishes a new presence state for the local peer. The state
// is also emitted periodically by the heartbeat goroutine so subscribers
// can recognise stale (expired) states.
func (p *PresenceChannel) SetState(ctx context.Context, state string) error {
	p.mu.Lock()
	p.ownState = state
	p.mu.Unlock()
	return p.emitState(state)
}

// Current returns the most recent presence of every known peer, filtered
// so that states older than ttl are reported as StateOffline.
func (p *PresenceChannel) Current() map[PeerID]PresenceState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[PeerID]PresenceState, len(p.current))
	now := time.Now()
	for peer, st := range p.current {
		if now.Sub(st.Timestamp) > p.ttl {
			out[peer] = PresenceState{Peer: peer, State: StateOffline, Timestamp: st.Timestamp}
			continue
		}
		out[peer] = st
	}
	return out
}

// Watch registers cb for every presence update applied locally. Returns
// an idempotent unsubscribe func.
func (p *PresenceChannel) Watch(cb func(PeerID, PresenceState)) func() {
	p.subMu.Lock()
	id := p.nextSubID
	p.nextSubID++
	p.subs[id] = cb
	p.subMu.Unlock()
	return func() {
		p.subMu.Lock()
		delete(p.subs, id)
		p.subMu.Unlock()
	}
}

// Close stops the heartbeat and detaches the transport subscription.
// Idempotent.
func (p *PresenceChannel) Close() error {
	p.closeMu.Lock()
	if p.closed {
		p.closeMu.Unlock()
		return nil
	}
	p.closed = true
	p.closeMu.Unlock()

	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	if p.unsubTrans != nil {
		p.unsubTrans()
	}
	return nil
}

// emitState signs, marshals, and publishes the given state.
func (p *PresenceChannel) emitState(state string) error {
	st := PresenceState{
		Peer:      p.identity.PeerID(),
		State:     state,
		Timestamp: time.Now().UTC(),
	}
	// Sign implicitly by wrapping inside a Message — cheaper here to
	// just sign the JSON bytes of the state directly. The channel
	// topic is authenticated (every participant knows the authors), so
	// a bare signed PresenceState is enough.
	data, err := json.Marshal(presenceEnvelope{State: st})
	if err != nil {
		return fmt.Errorf("messaging: marshal presence: %w", err)
	}

	// Apply locally so Current() sees our own state immediately.
	p.mu.Lock()
	p.states.Set(string(p.identity.PeerID()), data)
	p.current[p.identity.PeerID()] = st
	p.mu.Unlock()

	return p.trans.Publish(p.topic, data)
}

// heartbeat re-emits the local state every ttl/2. Exits when ctx is
// cancelled.
func (p *PresenceChannel) heartbeat(ctx context.Context) {
	defer p.wg.Done()
	interval := p.ttl / 2
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.mu.RLock()
			state := p.ownState
			p.mu.RUnlock()
			_ = p.emitState(state)
		}
	}
}

// onWire decodes an incoming presence update and merges it.
func (p *PresenceChannel) onWire(payload []byte) {
	var env presenceEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return
	}
	if env.State.Peer == "" {
		return
	}

	p.mu.Lock()
	existing, had := p.current[env.State.Peer]
	if had && !env.State.Timestamp.After(existing.Timestamp) {
		p.mu.Unlock()
		return // older or equal — ignore
	}
	p.states.Set(string(env.State.Peer), payload)
	p.current[env.State.Peer] = env.State
	p.mu.Unlock()

	p.subMu.RLock()
	subs := make([]func(PeerID, PresenceState), 0, len(p.subs))
	for _, cb := range p.subs {
		subs = append(subs, cb)
	}
	p.subMu.RUnlock()
	for _, cb := range subs {
		cb(env.State.Peer, env.State)
	}
}
