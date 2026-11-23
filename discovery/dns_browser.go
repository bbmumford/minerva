//go:build js && wasm

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * DNS-over-HTTPS discoverer for WASM — uses the browser's fetch() API
 * to query Cloudflare's DoH resolver for SRV records, enabling peer
 * discovery without native DNS access.
 */
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/bbmumford/minerva/identity"
)

// DoHDiscoverer discovers peers via DNS-over-HTTPS SRV record lookups.
// In the browser WASM environment, native DNS is unavailable so we query
// a public DoH endpoint (defaulting to Cloudflare) using fetch().
type DoHDiscoverer struct {
	domain   string   // e.g. "example.com"
	gateways []string // DoH endpoints to try
}

// dohResponse models the JSON wire format returned by DoH resolvers
// (RFC 8484, JSON API variant used by Cloudflare and Google).
type dohResponse struct {
	Status   int         `json:"Status"`
	Answer   []dohAnswer `json:"Answer"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
}

// dohAnswer is a single DNS answer record.
type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"` // 33 = SRV
	TTL  int    `json:"TTL"`
	Data string `json:"data"` // SRV format: "priority weight port target"
}

// NewDoHDiscoverer creates a DNS-over-HTTPS discoverer for the given domain.
// It queries _minerva._tcp.<domain> SRV records via Cloudflare's DoH gateway.
func NewDoHDiscoverer(domain string) *DoHDiscoverer {
	return &DoHDiscoverer{
		domain: domain,
		gateways: []string{
			"https://cloudflare-dns.com/dns-query",
		},
	}
}

// Discover queries DoH for SRV records and emits discovered peer addresses.
// The returned channel is closed after the query completes or the context
// is cancelled.
func (d *DoHDiscoverer) Discover(ctx context.Context) <-chan PeerAddress {
	ch := make(chan PeerAddress, 16)

	go func() {
		defer close(ch)

		srvName := fmt.Sprintf("_minerva._tcp.%s", d.domain)

		var answers []dohAnswer
		var lastErr error

		for _, gateway := range d.gateways {
			a, err := d.querySRV(ctx, gateway, srvName)
			if err != nil {
				lastErr = err
				continue
			}
			answers = a
			break
		}

		if answers == nil && lastErr != nil {
			// All gateways failed — nothing to emit.
			_ = lastErr
			return
		}

		for _, ans := range answers {
			if ans.Type != 33 { // 33 = SRV
				continue
			}

			// SRV data format: "priority weight port target"
			parts := strings.Fields(ans.Data)
			if len(parts) < 4 {
				continue
			}

			port, err := strconv.Atoi(parts[2])
			if err != nil {
				continue
			}

			target := strings.TrimSuffix(parts[3], ".")
			addr := fmt.Sprintf("%s:%d", target, port)

			// The target hostname may encode the peer ID as a subdomain label,
			// or the caller resolves identity during handshake. We use the
			// target as a provisional peer ID.
			pa := PeerAddress{
				PeerID:    identity.PeerID(target),
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

// Advertise is a no-op for DoH discovery. Browser nodes cannot publish
// DNS records; advertisement must be done out-of-band (e.g., via a relay
// or a DNS provider API).
func (d *DoHDiscoverer) Advertise(_ context.Context, _ PeerAddress) error {
	return nil
}

// querySRV performs a single DoH query for the given SRV name against the
// specified gateway URL. Uses the standard net/http client which, in WASM,
// maps to the browser's fetch() API.
func (d *DoHDiscoverer) querySRV(ctx context.Context, gateway, srvName string) ([]dohAnswer, error) {
	url := fmt.Sprintf("%s?name=%s&type=SRV", gateway, srvName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("doh: build request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: fetch %s: %w", gateway, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: %s returned status %d", gateway, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("doh: read body: %w", err)
	}

	var dohResp dohResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, fmt.Errorf("doh: parse response: %w", err)
	}

	if dohResp.Status != 0 { // 0 = NOERROR
		return nil, fmt.Errorf("doh: DNS status %d for %s", dohResp.Status, srvName)
	}

	return dohResp.Answer, nil
}
