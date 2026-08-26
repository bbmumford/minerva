package crdt

import (
	"context"
	"sync"
	"time"
)

// GCTarget is the interface for any collection that supports tombstone sweeping.
// Types that implement this (LWWMap, ORSet, etc.) can be registered with the
// GarbageCollector for periodic cleanup.
type GCTarget interface {
	// SweepTombstones removes tombstones older than the given duration
	// and returns the number of entries removed.
	SweepTombstones(olderThan time.Duration) int
}

// GarbageCollector periodically removes tombstones that are older than the
// configured TTL from registered CRDT collections. This prevents unbounded
// tombstone growth at the cost of potential resurrection if a peer is offline
// longer than the TTL.
type GarbageCollector struct {
	collections []GCTarget // registered collections to sweep
	ttl         time.Duration
	interval    time.Duration
	mu          sync.Mutex
	cancel      context.CancelFunc
}

// NewGarbageCollector creates a new tombstone garbage collector.
// ttl is the minimum age a tombstone must reach before it is eligible for removal.
// The default sweep interval is ttl/2, which can be overridden by calling
// SetInterval before starting.
func NewGarbageCollector(ttl time.Duration) *GarbageCollector {
	interval := ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	return &GarbageCollector{
		ttl:      ttl,
		interval: interval,
	}
}

// SetInterval overrides the default sweep interval.
func (gc *GarbageCollector) SetInterval(d time.Duration) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.interval = d
}

// Register adds a GCTarget (any collection with SweepTombstones) to the sweep list.
func (gc *GarbageCollector) Register(target GCTarget) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.collections = append(gc.collections, target)
}

// Run starts the garbage collection loop, sweeping at the configured interval.
// It blocks until the context is cancelled or Stop is called.
func (gc *GarbageCollector) Run(ctx context.Context) {
	gc.mu.Lock()
	ctx, gc.cancel = context.WithCancel(ctx)
	interval := gc.interval
	gc.mu.Unlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gc.RunOnce()
		}
	}
}

// RunOnce performs a single garbage collection pass across all registered
// collections and returns the total number of tombstones removed.
func (gc *GarbageCollector) RunOnce() int {
	gc.mu.Lock()
	targets := make([]GCTarget, len(gc.collections))
	copy(targets, gc.collections)
	ttl := gc.ttl
	gc.mu.Unlock()

	total := 0
	for _, t := range targets {
		total += t.SweepTombstones(ttl)
	}
	return total
}

// Stop cancels the background Run loop if it is running.
func (gc *GarbageCollector) Stop() {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	if gc.cancel != nil {
		gc.cancel()
		gc.cancel = nil
	}
}
