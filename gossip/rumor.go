/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package gossip

import (
	"context"
	"fmt"
	"sync"

	"github.com/bbmumford/minerva/crdt"
	gossippb "github.com/bbmumford/minerva/gossip/proto"
	"github.com/bbmumford/whisper"
	"google.golang.org/protobuf/proto"
)

// RumorPusher listens for local CRDT mutations and pushes them immediately
// via Whisper's BroadcastOnly topic. This provides sub-second propagation
// of state changes to all peers, complementing the periodic StatefulMerge
// delta sync which acts as a consistency backstop.
type RumorPusher struct {
	engine *whisper.Engine
	appID  string

	mu      sync.Mutex
	pending chan rumorItem
	cancel  context.CancelFunc
	stopped bool
}

// rumorItem is a queued delta waiting to be published.
type rumorItem struct {
	collection string
	delta      crdt.Delta
}

// NewRumorPusher creates a RumorPusher bound to the given Whisper engine.
func NewRumorPusher(engine *whisper.Engine, appID string) *RumorPusher {
	return &RumorPusher{
		engine:  engine,
		appID:   appID,
		pending: make(chan rumorItem, 256),
	}
}

// PushDelta queues a CRDT delta for immediate broadcast to peers.
// Non-blocking: if the queue is full, the delta is dropped (the periodic
// StatefulMerge sync will catch it).
func (rp *RumorPusher) PushDelta(collection string, delta crdt.Delta) error {
	select {
	case rp.pending <- rumorItem{collection: collection, delta: delta}:
		return nil
	default:
		return fmt.Errorf("gossip: rumor queue full, delta dropped (collection=%s key=%s)", collection, delta.Key)
	}
}

// Start begins the rumor push loop. It drains the pending queue and publishes
// each delta as a protobuf GossipEnvelope on the broadcast topic.
func (rp *RumorPusher) Start(ctx context.Context) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if rp.cancel != nil {
		return fmt.Errorf("gossip: rumor pusher already started")
	}

	ctx, cancel := context.WithCancel(ctx)
	rp.cancel = cancel

	go rp.run(ctx)
	return nil
}

// Stop signals the rumor pusher to shut down.
func (rp *RumorPusher) Stop() error {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if rp.cancel != nil {
		rp.cancel()
		rp.cancel = nil
	}
	rp.stopped = true
	return nil
}

func (rp *RumorPusher) run(ctx context.Context) {
	topicName := fmt.Sprintf("minerva.%s.rumor", rp.appID)

	for {
		select {
		case <-ctx.Done():
			return
		case item := <-rp.pending:
			env := &gossippb.GossipEnvelope{
				AppId:    rp.appID,
				SenderId: item.delta.NodeID,
				Deltas: []*gossippb.CRDTDelta{
					deltaToProto(item.collection, item.delta),
				},
			}

			payload, err := proto.Marshal(env)
			if err != nil {
				continue
			}

			// Publish on the BroadcastOnly topic — Whisper handles fan-out.
			_ = rp.engine.Publish(topicName, payload)
		}
	}
}
