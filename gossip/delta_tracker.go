/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package gossip

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"sync"

	"github.com/bbmumford/minerva/persistence"
)

// DeltaTracker maintains per-peer HLC watermarks for CRDT delta synchronization.
// Each peer tracks the highest HLC timestamp successfully exchanged, enabling
// delta-only sync on subsequent rounds (only sending records newer than the watermark).
type DeltaTracker struct {
	mu         sync.RWMutex
	watermarks map[string]uint64 // peerID -> HLC watermark
	store      persistence.Store // optional, nil = no persistence
}

// NewDeltaTracker creates an empty DeltaTracker with no persistence.
func NewDeltaTracker() *DeltaTracker {
	return &DeltaTracker{
		watermarks: make(map[string]uint64),
	}
}

// NewDeltaTrackerWithPersistence creates a DeltaTracker backed by a persistence store.
// Watermarks are loaded from the store on creation and saved on each Advance().
func NewDeltaTrackerWithPersistence(store persistence.Store) *DeltaTracker {
	dt := &DeltaTracker{
		watermarks: make(map[string]uint64),
		store:      store,
	}
	// Load existing watermarks from persistence.
	// The persistence store hex-encodes peerID bytes, so we decode back
	// to recover the original string peerIDs used by the gossip layer.
	if store != nil {
		wm, err := store.LoadWatermarks()
		if err != nil {
			log.Printf("gossip: failed to load watermarks from persistence: %v", err)
		} else {
			for hexKey, v := range wm {
				if v == 0 {
					continue // skip zeroed (reset) watermarks
				}
				// Attempt to decode hex key back to original peerID string.
				raw, err := hex.DecodeString(hexKey)
				if err != nil {
					// If not valid hex, use the key as-is.
					dt.watermarks[hexKey] = v
				} else {
					dt.watermarks[string(raw)] = v
				}
			}
		}
	}
	return dt
}

// Watermark returns the last synced HLC for a peer.
// Returns 0 if the peer has never been seen (triggers full sync).
func (dt *DeltaTracker) Watermark(peerID string) uint64 {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return dt.watermarks[peerID]
}

// Advance sets the watermark for a peer if the given HLC is higher
// than the current value. This ensures watermarks never go backwards.
func (dt *DeltaTracker) Advance(peerID string, hlc uint64) {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if hlc > dt.watermarks[peerID] {
		dt.watermarks[peerID] = hlc
		if dt.store != nil {
			_ = dt.store.SaveWatermark([]byte(peerID), hlc)
		}
	}
}

// Reset clears the watermark for a peer (e.g., after disconnect/reconnect).
func (dt *DeltaTracker) Reset(peerID string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	delete(dt.watermarks, peerID)
	if dt.store != nil {
		// Save zero watermark to clear persisted state for this peer.
		_ = dt.store.SaveWatermark([]byte(peerID), 0)
	}
}

// All returns a snapshot of all peer watermarks.
func (dt *DeltaTracker) All() map[string]uint64 {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	result := make(map[string]uint64, len(dt.watermarks))
	for k, v := range dt.watermarks {
		result[k] = v
	}
	return result
}

// MarshalJSON serialises the watermark map for persistence.
func (dt *DeltaTracker) MarshalJSON() ([]byte, error) {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return json.Marshal(dt.watermarks)
}

// UnmarshalJSON restores the watermark map from persisted state.
func (dt *DeltaTracker) UnmarshalJSON(data []byte) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	return json.Unmarshal(data, &dt.watermarks)
}
