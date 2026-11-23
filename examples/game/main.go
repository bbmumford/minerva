//go:build js && wasm

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * Game example — minimal WASM entry point demonstrating a multiplayer
 * game state backed by Minerva's CRDT synchronisation and gossip.
 *
 * Build:
 *   GOOS=js GOARCH=wasm go build -o game.wasm ./examples/game/
 *
 * Serve index.html with wasm_exec.js and game.wasm in the same directory.
 */
package main

import (
	"fmt"

	_ "github.com/bbmumford/minerva/crdt"
	_ "github.com/bbmumford/minerva/sdk"
)

func main() {
	fmt.Println("[MINERVA] Game example loaded")

	// Block forever — keep WASM alive for JS interop.
	select {}
}
