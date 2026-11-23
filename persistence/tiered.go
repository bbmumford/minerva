/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package persistence

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bbmumford/ledger"
)

// StorageTier identifies which tier a piece of data currently lives in.
type StorageTier int

const (
	// TierHot is the primary, fastest-access tier (local persistence store).
	TierHot StorageTier = iota
	// TierWarm is the secondary tier for less-frequently accessed data.
	TierWarm
	// TierCold is the archival tier for rarely accessed data.
	TierCold
)

var (
	// ErrTieredKeyNotFound is returned when a key is not found in any tier.
	ErrTieredKeyNotFound = errors.New("tiered: key not found in any tier")
	// ErrTieredStoreClosed is returned when operating on a closed store.
	ErrTieredStoreClosed = errors.New("tiered: store is closed")
)

// TierPolicy configures when and how data migrates between tiers.
type TierPolicy struct {
	// MaxHotSize is the maximum total bytes allowed in the hot tier.
	// When exceeded during migration, the oldest entries are promoted to warm.
	MaxHotSize int64

	// WarmAfter is the duration of inactivity after which hot data migrates to warm.
	WarmAfter time.Duration

	// ColdAfter is the duration of inactivity after which warm data migrates to cold.
	ColdAfter time.Duration

	// PinWarm prevents warm-tier data from migrating to cold even after ColdAfter.
	PinWarm bool
}

// tierEntry tracks a key's tier and last access time.
type tierEntry struct {
	tier       StorageTier
	lastAccess time.Time
	size       int64
}

// TieredStore provides transparent tiered storage across a hot persistence.Store
// and warm/cold ledger.BlobStores. Reads fall through hot -> warm -> cold.
// Writes always go to hot. Migrate() moves data between tiers based on policy.
type TieredStore struct {
	hot    Store
	warm   ledger.BlobStore
	cold   ledger.BlobStore
	policy TierPolicy

	mu        sync.RWMutex
	accessLog map[string]*tierEntry
	warmKeys  map[string]string // appKey -> warm CID
	coldKeys  map[string]string // appKey -> cold CID
	closed    bool
}

// NewTieredStore creates a new tiered store with the given backends and policy.
func NewTieredStore(hot Store, warm, cold ledger.BlobStore, policy TierPolicy) *TieredStore {
	return &TieredStore{
		hot:       hot,
		warm:      warm,
		cold:      cold,
		policy:    policy,
		accessLog: make(map[string]*tierEntry),
		warmKeys:  make(map[string]string),
		coldKeys:  make(map[string]string),
	}
}

// Get retrieves data by key, falling through hot -> warm -> cold.
// Found data is promoted back to hot on access.
func (t *TieredStore) Get(key string) ([]byte, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, ErrTieredStoreClosed
	}
	t.mu.RUnlock()

	// Try hot tier first via the collection-based store.
	data, err := t.getFromHot(key)
	if err == nil && data != nil {
		t.touch(key, TierHot, int64(len(data)))
		return data, nil
	}

	// Try warm tier via the key-to-CID mapping.
	t.mu.RLock()
	warmCID, warmOK := t.warmKeys[key]
	t.mu.RUnlock()
	if warmOK {
		data, err = t.warm.Get(warmCID)
		if err == nil {
			// Promote back to hot.
			if putErr := t.putToHot(key, data); putErr == nil {
				_ = t.warm.Delete(warmCID)
				t.mu.Lock()
				delete(t.warmKeys, key)
				t.mu.Unlock()
				t.touch(key, TierHot, int64(len(data)))
			} else {
				t.touch(key, TierWarm, int64(len(data)))
			}
			return data, nil
		}
	}

	// Try cold tier via the key-to-CID mapping.
	t.mu.RLock()
	coldCID, coldOK := t.coldKeys[key]
	t.mu.RUnlock()
	if coldOK {
		data, err = t.cold.Get(coldCID)
		if err == nil {
			// Promote back to hot.
			if putErr := t.putToHot(key, data); putErr == nil {
				_ = t.cold.Delete(coldCID)
				t.mu.Lock()
				delete(t.coldKeys, key)
				t.mu.Unlock()
				t.touch(key, TierHot, int64(len(data)))
			} else {
				t.touch(key, TierCold, int64(len(data)))
			}
			return data, nil
		}
	}

	return nil, ErrTieredKeyNotFound
}

// Put stores data in the hot tier and records its access time.
func (t *TieredStore) Put(key string, data []byte) error {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return ErrTieredStoreClosed
	}
	t.mu.RUnlock()

	if err := t.putToHot(key, data); err != nil {
		return err
	}
	t.touch(key, TierHot, int64(len(data)))
	return nil
}

// Migrate moves data between tiers based on age and the configured policy.
// It should be called periodically (e.g. every minute) from a background goroutine.
func (t *TieredStore) Migrate(ctx context.Context) error {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return ErrTieredStoreClosed
	}
	t.mu.RUnlock()

	now := time.Now()

	// Collect entries that need migration.
	t.mu.RLock()
	entries := make(map[string]*tierEntry, len(t.accessLog))
	for k, e := range t.accessLog {
		entries[k] = &tierEntry{
			tier:       e.tier,
			lastAccess: e.lastAccess,
			size:       e.size,
		}
	}
	t.mu.RUnlock()

	// Phase 1: Move stale hot entries to warm.
	var hotTotal int64
	for key, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.tier != TierHot {
			continue
		}

		age := now.Sub(entry.lastAccess)
		if t.policy.WarmAfter > 0 && age >= t.policy.WarmAfter {
			if err := t.migrateHotToWarm(key); err != nil {
				continue
			}
			entry.tier = TierWarm
		} else {
			hotTotal += entry.size
		}
	}

	// Phase 2: Enforce MaxHotSize by evicting oldest hot entries to warm.
	if t.policy.MaxHotSize > 0 && hotTotal > t.policy.MaxHotSize {
		type hotItem struct {
			key        string
			lastAccess time.Time
			size       int64
		}
		var items []hotItem
		for key, entry := range entries {
			if entry.tier == TierHot {
				items = append(items, hotItem{key: key, lastAccess: entry.lastAccess, size: entry.size})
			}
		}
		// Sort oldest first.
		for i := 0; i < len(items); i++ {
			for j := i + 1; j < len(items); j++ {
				if items[j].lastAccess.Before(items[i].lastAccess) {
					items[i], items[j] = items[j], items[i]
				}
			}
		}
		for _, item := range items {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if hotTotal <= t.policy.MaxHotSize {
				break
			}
			if err := t.migrateHotToWarm(item.key); err != nil {
				continue
			}
			hotTotal -= item.size
			if e, ok := entries[item.key]; ok {
				e.tier = TierWarm
			}
		}
	}

	// Phase 3: Move stale warm entries to cold (unless PinWarm).
	if !t.policy.PinWarm && t.policy.ColdAfter > 0 {
		for key, entry := range entries {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if entry.tier != TierWarm {
				continue
			}
			age := now.Sub(entry.lastAccess)
			if age >= t.policy.ColdAfter {
				if err := t.migrateWarmToCold(key); err != nil {
					continue
				}
				entry.tier = TierCold
			}
		}
	}

	// Update the access log with new tiers.
	t.mu.Lock()
	for key, entry := range entries {
		if existing, ok := t.accessLog[key]; ok {
			existing.tier = entry.tier
		}
	}
	t.mu.Unlock()

	return nil
}

// HotSize returns the total bytes tracked in the hot tier.
func (t *TieredStore) HotSize() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var total int64
	for _, e := range t.accessLog {
		if e.tier == TierHot {
			total += e.size
		}
	}
	return total
}

// Tier returns the current storage tier for the given key, or -1 if unknown.
func (t *TieredStore) Tier(key string) StorageTier {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if e, ok := t.accessLog[key]; ok {
		return e.tier
	}
	return StorageTier(-1)
}

// touch records a key access.
func (t *TieredStore) touch(key string, tier StorageTier, size int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.accessLog[key] = &tierEntry{
		tier:       tier,
		lastAccess: time.Now(),
		size:       size,
	}
}

// getFromHot reads a key from the hot tier using the collection-based store.
// It uses SaveCollection/LoadCollection with a synthetic collection name.
func (t *TieredStore) getFromHot(key string) ([]byte, error) {
	_, entries, _, err := t.hot.LoadCollection("__tiered")
	if err != nil {
		return nil, err
	}
	data, ok := entries[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return data, nil
}

// putToHot writes a key to the hot tier.
func (t *TieredStore) putToHot(key string, data []byte) error {
	_, entries, tombstones, _ := t.hot.LoadCollection("__tiered")
	if entries == nil {
		entries = make(map[string][]byte)
	}
	if tombstones == nil {
		tombstones = make(map[string]uint64)
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	entries[key] = cp
	delete(tombstones, key)
	return t.hot.SaveCollection("__tiered", 0, entries, tombstones)
}

// deleteFromHot removes a key from the hot tier.
func (t *TieredStore) deleteFromHot(key string) error {
	_, entries, tombstones, _ := t.hot.LoadCollection("__tiered")
	if entries == nil {
		return nil
	}
	if tombstones == nil {
		tombstones = make(map[string]uint64)
	}
	delete(entries, key)
	return t.hot.SaveCollection("__tiered", 0, entries, tombstones)
}

// migrateHotToWarm moves a single key from hot to warm.
func (t *TieredStore) migrateHotToWarm(key string) error {
	data, err := t.getFromHot(key)
	if err != nil {
		return err
	}
	cid, err := t.warm.Put(data)
	if err != nil {
		return err
	}

	// Store the mapping from application key to the warm-tier CID so
	// we can retrieve the data by key later.
	t.mu.Lock()
	t.warmKeys[key] = cid
	t.mu.Unlock()

	// Delete from hot after successful warm write.
	return t.deleteFromHot(key)
}

// migrateWarmToCold moves a single key from warm to cold.
func (t *TieredStore) migrateWarmToCold(key string) error {
	t.mu.RLock()
	warmCID, ok := t.warmKeys[key]
	t.mu.RUnlock()
	if !ok {
		return errors.New("tiered: warm CID not found for key")
	}

	data, err := t.warm.Get(warmCID)
	if err != nil {
		return err
	}
	coldCID, err := t.cold.Put(data)
	if err != nil {
		return err
	}

	// Update key mappings: remove warm, add cold.
	t.mu.Lock()
	delete(t.warmKeys, key)
	t.coldKeys[key] = coldCID
	t.mu.Unlock()

	return t.warm.Delete(warmCID)
}
