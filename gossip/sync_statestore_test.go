/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package gossip

import (
	"context"
	"testing"

	gossippb "github.com/bbmumford/minerva/gossip/proto"
	"github.com/bbmumford/minerva/sdk"
	"github.com/bbmumford/whisper"
	"google.golang.org/protobuf/proto"
)

// The collection store holds no records yet, so a delta handed to it is not
// merged anywhere: Apply must refuse it rather than report it applied, which
// whisper's G1 handler counts as a record landed.
func TestCRDTStateStore_ApplyRefusesWhatItCannotMerge(t *testing.T) {
	cs := &CRDTStateStore{collection: "todos", crdtType: sdk.TypeLWWMap, appID: "app"}
	data, err := proto.Marshal(&gossippb.CRDTDelta{Collection: "todos", Key: "k", Value: []byte("v")})
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Apply(data); err == nil {
		t.Fatal("Apply reported a delta applied that no CRDT state received")
	}
}

// Until the collection store holds its records, SyncManager registers no
// collection as a StatefulMerge topic: a topic whose store serves nothing
// and merges nothing would be state sync in name only. Deltas still travel
// on the rumor topic.
func TestSyncManager_RegistersNoCollectionAsAStateTopic(t *testing.T) {
	store := sdk.NewStore()
	if err := store.Register("todos", sdk.TypeLWWMap); err != nil {
		t.Fatal(err)
	}
	engine := whisper.NewEngine()
	sm := NewSyncManager(engine, "app", store, sdk.NewEventBus())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sm.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := sm.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	if err := engine.RegisterTopic(sm.topicName("todos"), whisper.TopicConfig{Mode: whisper.BroadcastOnly}); err != nil {
		t.Fatalf("the collection's topic is still registered after Start: %v", err)
	}
	if err := engine.RegisterTopic(sm.rumorTopicName(), whisper.TopicConfig{Mode: whisper.BroadcastOnly}); err == nil {
		t.Fatal("the rumor topic was not registered by Start")
	}
}
