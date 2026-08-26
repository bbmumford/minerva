//go:build js && wasm

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * Chat example — minimal WASM entry point demonstrating a peer-to-peer
 * chat room backed by Minerva's gossip broadcast and CRDT state.
 *
 * Build:
 *   GOOS=js GOARCH=wasm go build -o chat.wasm ./examples/chat/
 *
 * Serve index.html with wasm_exec.js and chat.wasm in the same directory.
 */
package main

import (
	"fmt"

	_ "github.com/bbmumford/minerva/crdt"
	_ "github.com/bbmumford/minerva/sdk"
)

func main() {
	fmt.Println("[MINERVA] Chat example loaded")

	// Block forever — keep WASM alive for JS interop.
	select {}
}
