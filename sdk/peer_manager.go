/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package sdk

import "sync"

// PeerManager tracks peers and manages peer lifecycle in a thread-safe manner.
type PeerManager struct {
	mu       sync.RWMutex
	peers    map[string]*Peer
	maxPeers int
}

// NewPeerManager creates a PeerManager with the given maximum peer limit.
func NewPeerManager(maxPeers int) *PeerManager {
	return &PeerManager{
		peers:    make(map[string]*Peer),
		maxPeers: maxPeers,
	}
}

// Add registers a peer. Returns false if max peers reached.
func (pm *PeerManager) Add(p *Peer) bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.maxPeers > 0 && len(pm.peers) >= pm.maxPeers {
		return false
	}
	pm.peers[p.ID] = p
	return true
}

// Remove deletes a peer by ID. Returns the removed peer or nil.
func (pm *PeerManager) Remove(id string) *Peer {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	p, ok := pm.peers[id]
	if !ok {
		return nil
	}
	delete(pm.peers, id)
	return p
}

// Get returns a peer by ID, or nil if not found.
func (pm *PeerManager) Get(id string) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.peers[id]
}

// All returns a snapshot of all tracked peers.
func (pm *PeerManager) All() []Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	result := make([]Peer, 0, len(pm.peers))
	for _, p := range pm.peers {
		result = append(result, *p)
	}
	return result
}

// Count returns the number of tracked peers.
func (pm *PeerManager) Count() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.peers)
}

// ConnectedPeerIDs returns IDs of all peers in Connected, Syncing, or Ready state.
func (pm *PeerManager) ConnectedPeerIDs() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	var ids []string
	for id, p := range pm.peers {
		if p.State == PeerStateConnected || p.State == PeerStateSyncing || p.State == PeerStateReady {
			ids = append(ids, id)
		}
	}
	return ids
}

// UpdateState changes a peer's state. Returns ErrPeerNotFound if the peer is not tracked.
func (pm *PeerManager) UpdateState(id string, state PeerState) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	p, ok := pm.peers[id]
	if !ok {
		return ErrPeerNotFound
	}
	p.State = state
	return nil
}
