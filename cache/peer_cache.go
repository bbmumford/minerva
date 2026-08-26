/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package cache

import (
	"errors"
	"sync"
	"sync/atomic"
)

var (
	// ErrCacheFull is returned when the cache cannot evict enough to fit new data.
	ErrCacheFull = errors.New("cache: item exceeds max cache size")
)

// PeerContentCache is a thread-safe LRU cache for content-addressed blobs
// shared between peers. It tracks hits, misses, and total size.
type PeerContentCache struct {
	mu          sync.RWMutex
	blobs       map[string][]byte
	order       []string // LRU order: index 0 = oldest, last = newest
	maxSize     int64
	currentSize int64
	hits        atomic.Int64
	misses      atomic.Int64
}

// NewPeerContentCache creates a new peer content cache with the given maximum
// total size in bytes.
func NewPeerContentCache(maxSize int64) *PeerContentCache {
	return &PeerContentCache{
		blobs:   make(map[string][]byte),
		order:   make([]string, 0, 64),
		maxSize: maxSize,
	}
}

// Get retrieves a blob by CID. Returns the data and true on a hit,
// nil and false on a miss. A hit moves the entry to the most-recent position.
func (c *PeerContentCache) Get(cid string) ([]byte, bool) {
	c.mu.Lock()
	data, ok := c.blobs[cid]
	if !ok {
		c.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}
	// Move to back of order (most recently used).
	c.moveToBack(cid)
	// Return a copy to prevent mutation.
	cp := make([]byte, len(data))
	copy(cp, data)
	c.mu.Unlock()

	c.hits.Add(1)
	return cp, true
}

// Put stores a blob in the cache, evicting LRU entries as needed to stay
// within maxSize. Returns ErrCacheFull if the single item exceeds maxSize.
func (c *PeerContentCache) Put(cid string, data []byte) error {
	itemSize := int64(len(data))
	if itemSize > c.maxSize {
		return ErrCacheFull
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	c.mu.Lock()
	defer c.mu.Unlock()

	// If already present, update in place.
	if existing, ok := c.blobs[cid]; ok {
		c.currentSize -= int64(len(existing))
		c.blobs[cid] = cp
		c.currentSize += itemSize
		c.moveToBack(cid)
		// Evict if updating with larger data pushed us over.
		c.evictLocked()
		return nil
	}

	// Evict until there is room.
	for c.currentSize+itemSize > c.maxSize && len(c.order) > 0 {
		c.evictOldestLocked()
	}

	c.blobs[cid] = cp
	c.order = append(c.order, cid)
	c.currentSize += itemSize
	return nil
}

// Delete removes a specific entry from the cache.
func (c *PeerContentCache) Delete(cid string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, ok := c.blobs[cid]
	if !ok {
		return
	}
	c.currentSize -= int64(len(data))
	delete(c.blobs, cid)
	c.removeFromOrder(cid)
}

// Stats returns cache hit count, miss count, and current total size in bytes.
func (c *PeerContentCache) Stats() (hits, misses int64, size int64) {
	c.mu.RLock()
	size = c.currentSize
	c.mu.RUnlock()
	return c.hits.Load(), c.misses.Load(), size
}

// Len returns the number of entries currently in the cache.
func (c *PeerContentCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.blobs)
}

// moveToBack moves a CID to the back of the LRU order (most recently used).
// Caller must hold c.mu.
func (c *PeerContentCache) moveToBack(cid string) {
	for i, id := range c.order {
		if id == cid {
			c.order = append(c.order[:i], c.order[i+1:]...)
			c.order = append(c.order, cid)
			return
		}
	}
}

// removeFromOrder removes a CID from the order slice. Caller must hold c.mu.
func (c *PeerContentCache) removeFromOrder(cid string) {
	for i, id := range c.order {
		if id == cid {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// evictOldestLocked removes the oldest entry. Caller must hold c.mu.
func (c *PeerContentCache) evictOldestLocked() {
	if len(c.order) == 0 {
		return
	}
	oldest := c.order[0]
	c.order = c.order[1:]
	if data, ok := c.blobs[oldest]; ok {
		c.currentSize -= int64(len(data))
		delete(c.blobs, oldest)
	}
}

// evictLocked evicts entries until currentSize <= maxSize. Caller must hold c.mu.
func (c *PeerContentCache) evictLocked() {
	for c.currentSize > c.maxSize && len(c.order) > 0 {
		c.evictOldestLocked()
	}
}
