/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package gossip

import (
	"fmt"
	"hash/fnv"
	"sort"
	"sync"
)

// ShardManager partitions CRDT state into shards so that nodes can subscribe
// to only the subset of data they need. Keys are mapped to shards via FNV-32a
// hashing, and each collection maintains an independent set of subscribed shard
// indices. This reduces gossip bandwidth for large deployments where each node
// only cares about a subset of the keyspace.
type ShardManager struct {
	numShards     int
	mu            sync.RWMutex
	subscriptions map[string]map[int]bool // collection -> set of shard indices
}

// NewShardManager creates a shard manager with the given number of shards.
// numShards must be >= 1; values <= 0 are clamped to 1.
func NewShardManager(numShards int) *ShardManager {
	if numShards < 1 {
		numShards = 1
	}
	return &ShardManager{
		numShards:     numShards,
		subscriptions: make(map[string]map[int]bool),
	}
}

// ShardFor returns the shard index for the given key using FNV-32a hashing.
// The result is always in [0, numShards).
func (sm *ShardManager) ShardFor(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % uint32(sm.numShards))
}

// TopicFor returns the gossip topic name for the shard that contains the given key.
// Format: "{collection}:shard:{index}"
func (sm *ShardManager) TopicFor(collection, key string) string {
	idx := sm.ShardFor(key)
	return fmt.Sprintf("%s:shard:%d", collection, idx)
}

// SubscribeShards subscribes the local node to the shards that contain the
// given keys for the specified collection. This is additive: previously
// subscribed shards are retained.
func (sm *ShardManager) SubscribeShards(collection string, keys []string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	shards, ok := sm.subscriptions[collection]
	if !ok {
		shards = make(map[int]bool)
		sm.subscriptions[collection] = shards
	}

	for _, key := range keys {
		idx := sm.ShardFor(key)
		shards[idx] = true
	}
}

// IsSubscribed returns true if the local node is subscribed to the given
// shard index for the specified collection.
func (sm *ShardManager) IsSubscribed(collection string, shardIndex int) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	shards, ok := sm.subscriptions[collection]
	if !ok {
		return false
	}
	return shards[shardIndex]
}

// AllSubscribedTopics returns all gossip topic names that the local node is
// subscribed to for the given collection. Topics are sorted for determinism.
func (sm *ShardManager) AllSubscribedTopics(collection string) []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	shards, ok := sm.subscriptions[collection]
	if !ok {
		return nil
	}

	topics := make([]string, 0, len(shards))
	for idx := range shards {
		topics = append(topics, fmt.Sprintf("%s:shard:%d", collection, idx))
	}
	sort.Strings(topics)
	return topics
}

// UnsubscribeAll removes all shard subscriptions for the given collection.
func (sm *ShardManager) UnsubscribeAll(collection string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.subscriptions, collection)
}

// NumShards returns the total number of shards.
func (sm *ShardManager) NumShards() int {
	return sm.numShards
}
