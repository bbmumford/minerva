/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package gossip

import "sync"

// TopicManager tracks which Whisper topics the local node is subscribed to.
// The SyncManager registers CRDT collection topics and the rumor broadcast topic
// on startup; external consumers can query subscription state for diagnostics.
type TopicManager struct {
	subscribed map[string]bool
	mu         sync.RWMutex
}

// NewTopicManager creates an empty TopicManager.
func NewTopicManager() *TopicManager {
	return &TopicManager{
		subscribed: make(map[string]bool),
	}
}

// Subscribe marks a topic as subscribed.
func (tm *TopicManager) Subscribe(topic string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.subscribed[topic] = true
}

// Unsubscribe removes a topic subscription.
func (tm *TopicManager) Unsubscribe(topic string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.subscribed, topic)
}

// IsSubscribed returns true if the topic is currently subscribed.
func (tm *TopicManager) IsSubscribed(topic string) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.subscribed[topic]
}

// All returns a snapshot of all subscribed topic names.
func (tm *TopicManager) All() []string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	result := make([]string, 0, len(tm.subscribed))
	for topic := range tm.subscribed {
		result = append(result, topic)
	}
	return result
}

// Count returns the number of subscribed topics.
func (tm *TopicManager) Count() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.subscribed)
}
