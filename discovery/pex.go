/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package discovery

import (
	"context"
	"sync"
	"time"

	"github.com/bbmumford/minerva/identity"
	"github.com/bbmumford/whisper"
)

// PEXDiscoverer uses Whisper's PEX (Peer Exchange) protocol to discover peers
// via gossip. Learned peer advertisements are converted to PeerAddress records
// and emitted on the discovery channel.
type PEXDiscoverer struct {
	mu      sync.Mutex
	manager *whisper.PEXManager
	seen    map[string]int64 // peerID -> last seen timestamp (dedup)
}

// NewPEXDiscoverer wraps an existing Whisper PEXManager.
func NewPEXDiscoverer(manager *whisper.PEXManager) *PEXDiscoverer {
	return &PEXDiscoverer{
		manager: manager,
		seen:    make(map[string]int64),
	}
}

// Discover returns a channel of peer addresses learned from PEX gossip.
// The channel emits new or updated peers as they are discovered. It polls
// the PEXManager periodically and closes when the context is cancelled.
func (d *PEXDiscoverer) Discover(ctx context.Context) <-chan PeerAddress {
	ch := make(chan PeerAddress, 16)

	go func() {
		defer close(ch)

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.poll(ctx, ch)
			}
		}
	}()

	return ch
}

// poll checks the PEXManager for known peers and emits any new or updated ones.
func (d *PEXDiscoverer) poll(ctx context.Context, ch chan<- PeerAddress) {
	peers := d.manager.KnownPeers()

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, entry := range peers {
		ts := entry.SignedAt.Unix()
		if prev, ok := d.seen[entry.NodeID]; ok && prev >= ts {
			continue // already emitted this or a newer version
		}
		d.seen[entry.NodeID] = ts

		pa := pexEntryToPeerAddress(entry)
		select {
		case ch <- pa:
		case <-ctx.Done():
			return
		}
	}
}

// Advertise adds a signed advertisement for the local node via PEX.
// The self PeerAddress is converted to a PEX entry and the manager is refreshed.
func (d *PEXDiscoverer) Advertise(_ context.Context, self PeerAddress) error {
	d.manager.RefreshLocalEntry(
		string(self.PeerID),
		self.Addresses,
		"", // region is not carried in PeerAddress; set externally if needed
	)
	return nil
}

// pexEntryToPeerAddress converts a Whisper PEXEntry to a Minerva PeerAddress.
func pexEntryToPeerAddress(entry whisper.PEXEntry) PeerAddress {
	var sig [64]byte
	if len(entry.Signature) >= 64 {
		copy(sig[:], entry.Signature[:64])
	}

	return PeerAddress{
		PeerID:    identity.PeerID(entry.NodeID),
		Addresses: entry.Addresses,
		Signature: sig,
		Timestamp: entry.SignedAt.Unix(),
	}
}
