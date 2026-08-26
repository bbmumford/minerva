/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package sdk

import "time"

// PeerState represents the lifecycle state of a remote peer.
type PeerState int

const (
	PeerStateDiscovered    PeerState = iota // known but not yet connected
	PeerStateConnecting                     // handshake in progress
	PeerStateConnected                      // session established
	PeerStateSyncing                        // initial CRDT state exchange in progress
	PeerStateReady                          // fully synced, operational
	PeerStateDisconnecting                  // graceful shutdown in progress
	PeerStateDisconnected                   // session closed
)

// String returns a human-readable label for the peer state.
func (ps PeerState) String() string {
	switch ps {
	case PeerStateDiscovered:
		return "discovered"
	case PeerStateConnecting:
		return "connecting"
	case PeerStateConnected:
		return "connected"
	case PeerStateSyncing:
		return "syncing"
	case PeerStateReady:
		return "ready"
	case PeerStateDisconnecting:
		return "disconnecting"
	case PeerStateDisconnected:
		return "disconnected"
	default:
		return "unknown"
	}
}

// Peer represents a remote peer known to this node.
type Peer struct {
	// ID is the unique peer identifier (hex-encoded public key prefix).
	ID string

	// PublicKey is the peer's Ed25519 public key (32 bytes).
	PublicKey [32]byte

	// Petname is an optional human-readable label for this peer.
	Petname string

	// State is the current connection lifecycle state.
	State PeerState

	// Addresses are known network addresses for this peer.
	Addresses []string

	// RTT is the last measured round-trip time.
	RTT time.Duration

	// LastSeen is the timestamp of the last received message.
	LastSeen time.Time

	// ConnectedAt is when the session was established (zero if not connected).
	ConnectedAt time.Time

	// AppIDs lists application namespaces this peer participates in.
	AppIDs []string
}

// PeerID returns the peer's identifier.
func (p *Peer) PeerID() string {
	return p.ID
}

// RTTMs returns the round-trip time in milliseconds.
func (p *Peer) RTTMs() float64 {
	return float64(p.RTT.Microseconds()) / 1000.0
}
