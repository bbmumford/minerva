//go:build js && wasm

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * IndexedDB persistence binding — wires the IndexedDB-backed persistence
 * store into Minerva WASM nodes. Each application gets its own IndexedDB
 * database namespaced by appID.
 */
package main

import (
	"github.com/bbmumford/minerva/persistence"
	"github.com/bbmumford/minerva/persistence/indexeddb"
)

// createIndexedDBStore opens (or creates) an IndexedDB database namespaced
// to the given application ID. The database name is prefixed with "minerva-"
// to avoid collisions with other browser storage.
//
// The returned Store satisfies persistence.Store and can be used for keypair
// storage, collection persistence, peer records, HLC state, and watermarks.
func createIndexedDBStore(appID string) (persistence.Store, error) {
	return indexeddb.New("minerva-" + appID)
}
