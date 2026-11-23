/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package sdk

import "sync"

// EventType identifies the kind of event emitted by the EventBus.
type EventType int

const (
	EventPeerConnect    EventType = iota + 1
	EventPeerDisconnect
	EventStateChange
)

// Event is an envelope for bus emissions.
type Event struct {
	Type       EventType
	Peer       *Peer  // set for connect/disconnect events
	PeerID     string // set for disconnect events
	Collection string // set for state-change events
	Key        string // set for state-change events
	Value      []byte // set for state-change events
}

// EventBus provides typed, thread-safe event subscriptions for the SDK.
type EventBus struct {
	mu                   sync.RWMutex
	peerConnectHandlers  []func(Peer)
	peerDisconnHandlers  []func(peerID string)
	stateChangeHandlers  map[string][]func(key string, value []byte)
}

// NewEventBus creates an initialised EventBus.
func NewEventBus() *EventBus {
	return &EventBus{
		stateChangeHandlers: make(map[string][]func(key string, value []byte)),
	}
}

// OnPeerConnect registers a callback invoked when a new peer connects.
func (eb *EventBus) OnPeerConnect(handler func(Peer)) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.peerConnectHandlers = append(eb.peerConnectHandlers, handler)
}

// OnPeerDisconnect registers a callback invoked when a peer disconnects.
func (eb *EventBus) OnPeerDisconnect(handler func(peerID string)) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.peerDisconnHandlers = append(eb.peerDisconnHandlers, handler)
}

// OnStateChange registers a callback invoked when a CRDT collection mutates.
// The collection parameter scopes the handler to a specific collection name.
func (eb *EventBus) OnStateChange(collection string, handler func(key string, value []byte)) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.stateChangeHandlers[collection] = append(eb.stateChangeHandlers[collection], handler)
}

// Emit dispatches an event to all matching registered handlers.
// Handlers are called synchronously in registration order.
func (eb *EventBus) Emit(evt Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	switch evt.Type {
	case EventPeerConnect:
		if evt.Peer != nil {
			for _, h := range eb.peerConnectHandlers {
				h(*evt.Peer)
			}
		}
	case EventPeerDisconnect:
		for _, h := range eb.peerDisconnHandlers {
			h(evt.PeerID)
		}
	case EventStateChange:
		handlers := eb.stateChangeHandlers[evt.Collection]
		for _, h := range handlers {
			h(evt.Key, evt.Value)
		}
	}
}
