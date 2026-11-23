/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package discovery

import (
	"context"
	"sync"
)

// MultiDiscoverer chains multiple Discoverer implementations and merges
// their results into a single deduplicated stream.
type MultiDiscoverer struct {
	discoverers []Discoverer
}

// NewMultiDiscoverer creates a discoverer that merges results from all sources.
func NewMultiDiscoverer(discoverers ...Discoverer) *MultiDiscoverer {
	return &MultiDiscoverer{
		discoverers: discoverers,
	}
}

// Discover merges channels from all underlying discoverers into a single channel.
// Results are deduplicated by PeerID — only the first (or newest) entry per peer
// is emitted. The output channel closes when all source channels are exhausted
// or the context is cancelled.
func (m *MultiDiscoverer) Discover(ctx context.Context) <-chan PeerAddress {
	out := make(chan PeerAddress, 16)

	go func() {
		defer close(out)

		var wg sync.WaitGroup
		mu := &sync.Mutex{}
		seen := make(map[string]int64) // peerID -> latest timestamp

		for _, d := range m.discoverers {
			wg.Add(1)
			go func(disc Discoverer) {
				defer wg.Done()

				ch := disc.Discover(ctx)
				for pa := range ch {
					pid := string(pa.PeerID)

					mu.Lock()
					if prev, ok := seen[pid]; ok && prev >= pa.Timestamp {
						mu.Unlock()
						continue
					}
					seen[pid] = pa.Timestamp
					mu.Unlock()

					select {
					case out <- pa:
					case <-ctx.Done():
						return
					}
				}
			}(d)
		}

		wg.Wait()
	}()

	return out
}

// Advertise broadcasts to all underlying discoverers.
// Errors from individual discoverers are ignored; best-effort.
func (m *MultiDiscoverer) Advertise(ctx context.Context, self PeerAddress) error {
	var firstErr error
	for _, d := range m.discoverers {
		if err := d.Advertise(ctx, self); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
