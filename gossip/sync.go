/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bbmumford/minerva/crdt"
	gossippb "github.com/bbmumford/minerva/gossip/proto"
	"github.com/bbmumford/minerva/sdk"
	"github.com/bbmumford/whisper"
	"google.golang.org/protobuf/proto"
)

// SyncManager orchestrates CRDT gossip sync via Whisper.
// It registers CRDT topics with the Whisper engine using StatefulMerge mode,
// wires delta exchange through the CRDTStateStore adapter, and drives
// immediate rumor propagation for local mutations.
type SyncManager struct {
	store    *sdk.Store
	engine   *whisper.Engine
	appID    string
	topics   *TopicManager
	tracker  *DeltaTracker
	rumor    *RumorPusher
	eventBus *sdk.EventBus

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
}

// NewSyncManager creates a SyncManager that bridges the SDK store to Whisper.
func NewSyncManager(engine *whisper.Engine, appID string, store *sdk.Store, eventBus *sdk.EventBus) *SyncManager {
	return &SyncManager{
		store:    store,
		engine:   engine,
		appID:    appID,
		topics:   NewTopicManager(),
		tracker:  NewDeltaTracker(),
		rumor:    NewRumorPusher(engine, appID),
		eventBus: eventBus,
	}
}

// Start registers all CRDT collections from the store as Whisper topics
// and starts the rumor pusher for immediate delta propagation.
func (sm *SyncManager) Start(ctx context.Context) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.started {
		return fmt.Errorf("gossip: sync manager already started")
	}

	ctx, cancel := context.WithCancel(ctx)
	sm.cancel = cancel

	// Register each CRDT collection as a StatefulMerge topic.
	collections := sm.store.All()
	for _, col := range collections {
		topicName := sm.topicName(col.Name)
		stateStore := &CRDTStateStore{
			collection: col.Name,
			crdtType:   col.CRDTType,
			appID:      sm.appID,
		}

		err := sm.engine.RegisterTopic(topicName, whisper.TopicConfig{
			Mode:  whisper.StatefulMerge,
			Store: stateStore,
			Rumor: true,
		})
		if err != nil {
			cancel()
			return fmt.Errorf("gossip: register topic %q: %w", topicName, err)
		}
		sm.topics.Subscribe(topicName)
	}

	// Register the broadcast topic for rumor push of immediate deltas.
	rumorTopic := sm.rumorTopicName()
	err := sm.engine.RegisterTopic(rumorTopic, whisper.TopicConfig{
		Mode: whisper.BroadcastOnly,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("gossip: register rumor topic: %w", err)
	}
	sm.topics.Subscribe(rumorTopic)

	// Subscribe to rumor broadcasts to apply incoming deltas.
	sm.engine.Subscribe(rumorTopic, &rumorSubscriber{sm: sm})

	// Wire up state-change events to the rumor pusher for immediate propagation.
	for _, col := range collections {
		colName := col.Name
		colType := col.CRDTType
		sm.eventBus.OnStateChange(colName, func(key string, value []byte) {
			sm.rumor.PushDelta(colName, crdt.Delta{
				Type:  crdt.CRDTType(colType),
				Key:   key,
				Value: value,
			})
		})
	}

	// Start the rumor pusher.
	if err := sm.rumor.Start(ctx); err != nil {
		cancel()
		return fmt.Errorf("gossip: start rumor pusher: %w", err)
	}

	sm.started = true
	return nil
}

// Stop shuts down the sync manager and rumor pusher.
func (sm *SyncManager) Stop() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.started {
		return nil
	}
	sm.started = false

	if sm.cancel != nil {
		sm.cancel()
	}
	return sm.rumor.Stop()
}

// Tracker returns the per-peer delta watermark tracker.
func (sm *SyncManager) Tracker() *DeltaTracker {
	return sm.tracker
}

// Topics returns the topic manager.
func (sm *SyncManager) Topics() *TopicManager {
	return sm.topics
}

// topicName returns the Whisper topic name for a CRDT collection.
func (sm *SyncManager) topicName(collection string) string {
	return fmt.Sprintf("minerva.%s.crdt.%s", sm.appID, collection)
}

// rumorTopicName returns the broadcast topic for immediate delta pushes.
func (sm *SyncManager) rumorTopicName() string {
	return fmt.Sprintf("minerva.%s.rumor", sm.appID)
}

// rumorSubscriber implements whisper.Subscriber to receive broadcast rumors.
type rumorSubscriber struct {
	sm *SyncManager
}

func (rs *rumorSubscriber) OnBroadcast(topic string, from string, payload []byte) {
	var env gossippb.GossipEnvelope
	if err := proto.Unmarshal(payload, &env); err != nil {
		return
	}
	if env.AppId != rs.sm.appID {
		return
	}

	for _, d := range env.Deltas {
		// Advance the watermark for the sender.
		rs.sm.tracker.Advance(env.SenderId, d.Hlc)

		// Emit a state-change event so the SDK store stays in sync.
		rs.sm.eventBus.Emit(sdk.Event{
			Type:       sdk.EventStateChange,
			Collection: d.Collection,
			Key:        d.Key,
			Value:      d.Value,
		})
	}
}

// CRDTStateStore adapts the CRDT layer to whisper.StateStore for StatefulMerge topics.
type CRDTStateStore struct {
	collection string
	crdtType   sdk.CRDTType
	appID      string
}

// Fingerprint returns 0, which whisper's G2 digest never counts as a
// match, so every digest probe goes on to a G1 exchange.
// TODO: derive it from the collection's records once crdt.Store holds them.
func (cs *CRDTStateStore) Fingerprint() uint64 {
	return 0
}

// Snapshot returns no records: this store keeps no collection state of its
// own, and deltas reach peers through the rumor topic instead.
// TODO: serialise the collection's records as CRDTDelta messages once
// crdt.Store holds them.
func (cs *CRDTStateStore) Snapshot() [][]byte {
	return nil
}

// Delta returns the snapshot, for the reason Snapshot states.
func (cs *CRDTStateStore) Delta(_ time.Time) [][]byte {
	return cs.Snapshot()
}

// Apply deserialises and merges an incoming delta into local CRDT state.
func (cs *CRDTStateStore) Apply(data []byte) error {
	var delta gossippb.CRDTDelta
	if err := proto.Unmarshal(data, &delta); err != nil {
		return fmt.Errorf("gossip: unmarshal delta: %w", err)
	}

	// Validate the delta matches this store's collection.
	if delta.Collection != cs.collection {
		return fmt.Errorf("gossip: delta collection mismatch: got %q, want %q", delta.Collection, cs.collection)
	}

	// CRDT apply will be wired when crdt.Store is implemented.
	_ = delta.Key
	return nil
}

// marshalEnvelope serialises a GossipEnvelope for wire transmission.
func marshalEnvelope(env *gossippb.GossipEnvelope) ([]byte, error) {
	return proto.Marshal(env)
}

// unmarshalEnvelope deserialises a GossipEnvelope from wire bytes.
func unmarshalEnvelope(data []byte) (*gossippb.GossipEnvelope, error) {
	var env gossippb.GossipEnvelope
	if err := proto.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// deltaToProto converts a crdt.Delta to the protobuf representation.
func deltaToProto(collection string, d crdt.Delta) *gossippb.CRDTDelta {
	return &gossippb.CRDTDelta{
		Collection: collection,
		CrdtType:   int32(d.Type),
		Key:        d.Key,
		Value:      d.Value,
		Hlc:        d.HLC,
		NodeId:     d.NodeID,
		Tombstone:  d.Tombstone,
	}
}

// protoToDelta converts a protobuf CRDTDelta to the crdt.Delta type.
func protoToDelta(pb *gossippb.CRDTDelta) crdt.Delta {
	return crdt.Delta{
		Type:      crdt.CRDTType(pb.CrdtType),
		Key:       pb.Key,
		Value:     pb.Value,
		HLC:       pb.Hlc,
		NodeID:    pb.NodeId,
		Tombstone: pb.Tombstone,
	}
}

// keep json import used (for future serialization paths)
var _ = json.Marshal
