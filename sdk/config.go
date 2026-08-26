/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package sdk

import "time"

// NodeConfig configures a Minerva node.
type NodeConfig struct {
	// AppID scopes this node to an application namespace (e.g. "mercury").
	AppID string

	// BootstrapRelays are WebSocket relay URLs for initial connectivity.
	// Example: ["wss://relay1.example.com/ws", "wss://relay2.example.com/ws"]
	BootstrapRelays []string

	// BootstrapPeers are known peer addresses (Aether multiaddr format).
	BootstrapPeers []string

	// DNSBootstrapDomain is a domain with TXT/SRV records for relay discovery.
	// Example: "_minerva._tcp.example.com"
	DNSBootstrapDomain string

	// IdentityPath is the filesystem path where the Ed25519 keypair is stored.
	// If empty, a new ephemeral keypair is generated at startup.
	IdentityPath string

	// ListenAddress is the local address to listen on for incoming connections.
	// Default: ":0" (random port).
	ListenAddress string

	// PersistencePath is the directory for on-disk state (SQLite, blobs).
	// If empty, state is kept in-memory only.
	PersistencePath string

	// EnableMDNS enables mDNS-based local peer discovery.
	EnableMDNS bool

	// EnablePEX enables peer exchange protocol for decentralised discovery.
	EnablePEX bool

	// GossipInterval is the base interval between gossip exchanges.
	// Default: 30 seconds.
	GossipInterval time.Duration

	// TombstoneTTL is how long deleted records are kept before GC.
	// Default: 24 hours.
	TombstoneTTL time.Duration

	// MaxPeers is the maximum number of simultaneous peer connections.
	// Default: 50.
	MaxPeers int
}

// DefaultConfig returns a NodeConfig with sensible defaults.
func DefaultConfig() NodeConfig {
	return NodeConfig{
		ListenAddress:  ":0",
		GossipInterval: 30 * time.Second,
		TombstoneTTL:   24 * time.Hour,
		MaxPeers:       50,
		EnablePEX:      true,
	}
}
