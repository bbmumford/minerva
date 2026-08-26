/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/bbmumford/whisper"
)

// appRegistryTopic is the Whisper topic used for broadcasting app manifests.
const appRegistryTopic = "minerva.apps"

// AppRegistry is an in-memory, thread-safe index of signed app manifests.
type AppRegistry struct {
	index         map[string]*AppManifest
	mu            sync.RWMutex
	whisperEngine *whisper.Engine
}

// NewAppRegistry creates an empty app registry wired to the given Whisper engine.
// The engine may be nil if Whisper is not available (local-only mode).
func NewAppRegistry(engine *whisper.Engine) *AppRegistry {
	return &AppRegistry{
		index:         make(map[string]*AppManifest),
		whisperEngine: engine,
	}
}

// Start subscribes to the Whisper BroadcastOnly topic for app manifests.
// Incoming manifests are validated and added to the registry automatically.
func (r *AppRegistry) Start(ctx context.Context) error {
	if r.whisperEngine == nil {
		return nil
	}

	// Register the topic as BroadcastOnly.
	if err := r.whisperEngine.RegisterTopic(appRegistryTopic, whisper.TopicConfig{
		Mode: whisper.BroadcastOnly,
	}); err != nil {
		// Topic may already be registered; ignore that error.
		if _, ok := r.whisperEngine.Registry().Get(appRegistryTopic); !ok {
			return fmt.Errorf("registry: register whisper topic: %w", err)
		}
	}

	// Subscribe to incoming manifests.
	r.whisperEngine.Subscribe(appRegistryTopic, &appRegistrySubscriber{registry: r})
	return nil
}

// Publish signs and broadcasts a manifest via Whisper.
func (r *AppRegistry) Publish(manifest *AppManifest) error {
	if r.whisperEngine == nil {
		return fmt.Errorf("registry: whisper engine not configured")
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("registry: marshal manifest: %w", err)
	}

	return r.whisperEngine.Publish(appRegistryTopic, data)
}

// appRegistrySubscriber implements whisper.Subscriber for incoming app manifests.
type appRegistrySubscriber struct {
	registry *AppRegistry
}

func (s *appRegistrySubscriber) OnBroadcast(topic string, from string, payload []byte) {
	var m AppManifest
	if err := json.Unmarshal(payload, &m); err != nil {
		return
	}
	// Validate and add — silently ignore errors (duplicate, invalid sig, etc.)
	_ = s.registry.Add(&m)
}

// Add validates and verifies the manifest signature, then adds it to the
// registry index. Returns an error if validation or signature verification
// fails, or if the AppID already exists (use Remove first to replace).
func (r *AppRegistry) Add(m *AppManifest) error {
	if err := Validate(m); err != nil {
		return err
	}
	if !VerifyManifest(m) {
		return fmt.Errorf("registry: invalid signature for app %q", m.AppID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.index[m.AppID]; exists {
		return fmt.Errorf("registry: app %q already registered", m.AppID)
	}

	r.index[m.AppID] = m
	return nil
}

// Get retrieves a manifest by AppID. Returns the manifest and true if
// found, or nil and false otherwise.
func (r *AppRegistry) Get(appID string) (*AppManifest, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.index[appID]
	return m, ok
}

// Search returns all manifests where the query string appears as a
// case-insensitive substring in the Name, Description, or any Category.
func (r *AppRegistry) Search(query string) []*AppManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()

	q := strings.ToLower(query)
	var results []*AppManifest

	for _, m := range r.index {
		if matchesQuery(m, q) {
			results = append(results, m)
		}
	}
	return results
}

// ByCategory returns all manifests that contain the given category
// (case-insensitive match).
func (r *AppRegistry) ByCategory(category string) []*AppManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cat := strings.ToLower(category)
	var results []*AppManifest

	for _, m := range r.index {
		for _, c := range m.Categories {
			if strings.ToLower(c) == cat {
				results = append(results, m)
				break
			}
		}
	}
	return results
}

// All returns a snapshot of every manifest in the registry.
func (r *AppRegistry) All() []*AppManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make([]*AppManifest, 0, len(r.index))
	for _, m := range r.index {
		results = append(results, m)
	}
	return results
}

// Remove deletes a manifest from the registry by AppID.
// No-op if the AppID does not exist.
func (r *AppRegistry) Remove(appID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.index, appID)
}

// matchesQuery checks if a manifest matches a lowercase query string.
func matchesQuery(m *AppManifest, q string) bool {
	if strings.Contains(strings.ToLower(m.Name), q) {
		return true
	}
	if strings.Contains(strings.ToLower(m.Description), q) {
		return true
	}
	for _, c := range m.Categories {
		if strings.Contains(strings.ToLower(c), q) {
			return true
		}
	}
	return false
}
