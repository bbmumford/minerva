/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package discovery

import (
	"context"

	"github.com/bbmumford/minerva/identity"
)

// Discoverer is the interface for peer discovery mechanisms.
// Implementations include PEX (gossip-based), DNS SRV, and relay bootstrap.
type Discoverer interface {
	// Discover returns a channel of newly discovered peer addresses.
	// The channel is closed when the context is cancelled or discovery completes.
	Discover(ctx context.Context) <-chan PeerAddress

	// Advertise announces this node to the discovery network.
	// For passive discovery mechanisms (e.g., DNS), this is a no-op.
	Advertise(ctx context.Context, self PeerAddress) error
}

// PeerAddress represents a discovered peer with verified identity.
type PeerAddress struct {
	PeerID    identity.PeerID // hex-encoded identity derived from public key
	Addresses []string        // multiaddr format endpoints
	Pubkey    [32]byte        // ed25519 public key (compact form)
	Signature [64]byte        // signs (peerID || addresses || timestamp)
	Timestamp int64           // unix timestamp of the advertisement
}
