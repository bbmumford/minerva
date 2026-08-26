//go:build !js

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package discovery

import (
	"context"
	"fmt"

	aetherDiscovery "github.com/ORBTR/aether/discovery"
	"github.com/bbmumford/minerva/identity"
)

// DNSDiscoverer wraps Aether's DNSSRVDiscoverer to discover peers via
// DNS SRV records. This is a passive discovery mechanism — Advertise is a no-op.
type DNSDiscoverer struct {
	inner *aetherDiscovery.DNSSRVDiscoverer
}

// NewDNSDiscoverer creates a DNS-based discoverer for the given domain.
// It queries _mesh._tcp.<domain> SRV records for peer endpoints.
func NewDNSDiscoverer(domain string, opts ...aetherDiscovery.DNSSRVOption) *DNSDiscoverer {
	return &DNSDiscoverer{
		inner: aetherDiscovery.NewDNSSRVDiscoverer(domain, opts...),
	}
}

// Discover queries DNS SRV records and emits peer addresses on the returned channel.
// The channel is closed after the initial query completes or the context is cancelled.
func (d *DNSDiscoverer) Discover(ctx context.Context) <-chan PeerAddress {
	ch := make(chan PeerAddress, 16)

	go func() {
		defer close(ch)

		peers, err := d.inner.Discover(ctx)
		if err != nil {
			return
		}

		for _, p := range peers {
			addr := fmt.Sprintf("%s:%d", p.Host, p.Port)
			pa := PeerAddress{
				PeerID:    identity.PeerID(p.NodeID),
				Addresses: []string{addr},
				Timestamp: 0, // DNS records have no timestamp
			}
			select {
			case ch <- pa:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch
}

// Advertise is a no-op for DNS discovery (passive only).
func (d *DNSDiscoverer) Advertise(_ context.Context, _ PeerAddress) error {
	return nil
}
