/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package sdk

import "github.com/bbmumford/minerva/persistence"

// NodeOption is a functional option for configuring a Node at creation time.
type NodeOption func(*Node)

// WithConfig sets the full NodeConfig on the node.
func WithConfig(cfg NodeConfig) NodeOption {
	return func(n *Node) {
		n.config = cfg
	}
}

// WithIdentityPath sets the path to the Ed25519 keypair file.
func WithIdentityPath(path string) NodeOption {
	return func(n *Node) {
		n.config.IdentityPath = path
	}
}

// WithRelay adds a bootstrap relay URL.
func WithRelay(url string) NodeOption {
	return func(n *Node) {
		n.config.BootstrapRelays = append(n.config.BootstrapRelays, url)
	}
}

// WithPersistencePath sets the on-disk persistence directory.
func WithPersistencePath(path string) NodeOption {
	return func(n *Node) {
		n.config.PersistencePath = path
	}
}

// WithAppID sets the application namespace.
func WithAppID(appID string) NodeOption {
	return func(n *Node) {
		n.config.AppID = appID
	}
}

// WithMaxPeers sets the maximum number of simultaneous peer connections.
func WithMaxPeers(max int) NodeOption {
	return func(n *Node) {
		n.config.MaxPeers = max
	}
}

// WithPersistence sets the persistence store for the node.
// If not set, an in-memory store is created at Start().
func WithPersistence(store persistence.Store) NodeOption {
	return func(n *Node) {
		n.persistence = store
	}
}
