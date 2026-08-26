//go:build js && wasm

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package main

import (
	"fmt"

	// Import all minerva packages to ensure they compile to WASM.
	_ "github.com/bbmumford/minerva/crdt"
	_ "github.com/bbmumford/minerva/discovery"
	_ "github.com/bbmumford/minerva/identity"
	_ "github.com/bbmumford/minerva/persistence"
	_ "github.com/bbmumford/minerva/persistence/indexeddb"
	_ "github.com/bbmumford/minerva/persistence/memory"
	_ "github.com/bbmumford/minerva/sdk"
)

func main() {
	// Register all JS bridge functions.
	registerAll()

	fmt.Println("[MINERVA] WASM module loaded")

	// Block forever — keep WASM alive.
	select {}
}
