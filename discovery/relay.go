/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package discovery

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// RelayInfo describes a known relay server with latency metrics.
type RelayInfo struct {
	URL         string        // relay endpoint URL
	RTT         time.Duration // measured round-trip time
	LastChecked time.Time     // when RTT was last measured
	Available   bool          // whether the relay is currently reachable
}

// RelayDirectory maintains a ranked list of known relay servers.
// Relays are ranked by RTT for optimal relay selection.
type RelayDirectory struct {
	mu     sync.RWMutex
	relays map[string]*RelayInfo
}

// NewRelayDirectory creates an empty relay directory.
func NewRelayDirectory() *RelayDirectory {
	return &RelayDirectory{
		relays: make(map[string]*RelayInfo),
	}
}

// AddRelay adds or updates a relay with the given RTT measurement.
func (rd *RelayDirectory) AddRelay(url string, rtt time.Duration) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	rd.relays[url] = &RelayInfo{
		URL:         url,
		RTT:         rtt,
		LastChecked: time.Now(),
		Available:   true,
	}
}

// RemoveRelay removes a relay from the directory.
func (rd *RelayDirectory) RemoveRelay(url string) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	delete(rd.relays, url)
}

// BestRelay returns the URL of the lowest-RTT available relay.
// Returns an error if no available relays exist.
func (rd *RelayDirectory) BestRelay() (string, error) {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	var best *RelayInfo
	for _, info := range rd.relays {
		if !info.Available {
			continue
		}
		if best == nil || info.RTT < best.RTT {
			best = info
		}
	}

	if best == nil {
		return "", errors.New("discovery: no available relays")
	}
	return best.URL, nil
}

// AllRelays returns all known relays sorted by RTT (lowest first).
func (rd *RelayDirectory) AllRelays() []RelayInfo {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	result := make([]RelayInfo, 0, len(rd.relays))
	for _, info := range rd.relays {
		result = append(result, *info)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].RTT < result[j].RTT
	})

	return result
}

// MarkUnavailable marks a relay as unavailable without removing it.
// This allows re-checking later without losing the relay record.
func (rd *RelayDirectory) MarkUnavailable(url string) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	if info, ok := rd.relays[url]; ok {
		info.Available = false
	}
}

// MarkAvailable marks a relay as available and updates its RTT.
func (rd *RelayDirectory) MarkAvailable(url string, rtt time.Duration) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	if info, ok := rd.relays[url]; ok {
		info.Available = true
		info.RTT = rtt
		info.LastChecked = time.Now()
	}
}
