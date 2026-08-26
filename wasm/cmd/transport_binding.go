//go:build js && wasm

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * Browser WebSocket transport binding — connects an Aether session
 * through a browser-native WebSocket. After the v0.0.169
 * browser-transport-architecture migration, the WS → net.Conn wrapper
 * lives in this package (browser_ws.go) and the aether.Session layer
 * is provided by adapter.NewNoiseSession. The aether package no
 * longer owns browser-substrate code.
 *
 * WSS handles encryption at the TLS layer, so no Noise is layered on
 * top — NewNoiseSession is fed the plaintext Aether-frame byte pipe
 * directly.
 */
package main

import (
	"context"
	"fmt"
	"sync"

	aether "github.com/ORBTR/aether"
	"github.com/ORBTR/aether/adapter"
)

// browserTransport provides Aether session connectivity via browser
// WebSocket. It wraps a WS net.Conn and the full NoiseSession layered
// on top.
type browserTransport struct {
	ws      *browserWS
	session *adapter.NoiseSession
	mu      sync.Mutex
	closed  bool
}

// dialBrowserRelay establishes a WebSocket connection to a relay URL
// and creates an Aether session over it.
//
// The returned browserTransport owns both the WebSocket and the
// session. Callers must call Close() when finished.
func dialBrowserRelay(ctx context.Context, url string, localNodeID aether.NodeID) (*browserTransport, error) {
	if url == "" {
		return nil, fmt.Errorf("minerva: relay URL must not be empty")
	}

	ws, err := dialBrowserWS(url, 10_000)
	if err != nil {
		return nil, fmt.Errorf("minerva: dial ws %s: %w", url, err)
	}

	// No Noise layered on top — TLS (WSS) already encrypts. The
	// session just provides Aether framing + stream multiplexing + flow
	// control + scheduler over the plaintext byte pipe.
	//
	// Remote NodeID is unknown until the first frame arrives; we pass
	// an ephemeral placeholder. Real-mode session tracking on the
	// relay side uses Aether's connection-id negotiation, not the
	// initial NodeID claim, so this is acceptable for the browser
	// ephemeral peer use case.
	remotePlaceholder := aether.NodeID("vl1_relay")
	sess := adapter.NewNoiseSession(ws, localNodeID, remotePlaceholder, aether.DefaultSessionOptions())

	return &browserTransport{
		ws:      ws,
		session: sess,
	}, nil
}

// Session returns the underlying Aether session for stream
// multiplexing. Returns *adapter.NoiseSession (concrete) so callers
// can access session-specific methods beyond the aether.Session
// interface (e.g. CongestionWindow, Metrics).
func (bt *browserTransport) Session() *adapter.NoiseSession {
	return bt.session
}

// Close tears down the WebSocket and session.
func (bt *browserTransport) Close() error {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	if bt.closed {
		return nil
	}
	bt.closed = true

	if bt.session != nil {
		_ = bt.session.Close()
	}
	if bt.ws != nil {
		return bt.ws.Close()
	}
	return nil
}

// IsClosed reports whether the transport has been shut down.
func (bt *browserTransport) IsClosed() bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	if bt.closed {
		return true
	}
	if bt.session != nil {
		return bt.session.IsClosed()
	}
	return false
}

// dialAllRelays attempts to connect to the first available relay from
// a list. Returns the first successful transport or an error if all fail.
func dialAllRelays(ctx context.Context, relayURLs []string, localNodeID aether.NodeID) (*browserTransport, error) {
	if len(relayURLs) == 0 {
		return nil, fmt.Errorf("minerva: no relay URLs configured")
	}

	var lastErr error
	for _, url := range relayURLs {
		bt, err := dialBrowserRelay(ctx, url, localNodeID)
		if err != nil {
			lastErr = err
			continue
		}
		return bt, nil
	}
	return nil, fmt.Errorf("minerva: all relays failed, last error: %w", lastErr)
}
