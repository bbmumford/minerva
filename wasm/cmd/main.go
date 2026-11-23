//go:build js && wasm

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * WASM command entry point — builds the full Minerva WASM binary
 * including transport binding, IndexedDB persistence, and JS bridge.
 *
 * Build:
 *   GOOS=js GOARCH=wasm go build -o minerva.wasm ./wasm/cmd/
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
	fmt.Println("[MINERVA] WASM module loaded (cmd build)")

	// Block forever — keep WASM alive for JS interop.
	select {}
}
