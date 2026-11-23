//go:build js && wasm

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * Editor example — minimal WASM entry point demonstrating collaborative
 * text editing backed by Minerva's Sequence (RGA) CRDT.
 *
 * Build:
 *   GOOS=js GOARCH=wasm go build -o editor.wasm ./examples/editor/
 *
 * Serve index.html with wasm_exec.js and editor.wasm in the same directory.
 */
package main

import (
	"fmt"

	_ "github.com/bbmumford/minerva/crdt"
	_ "github.com/bbmumford/minerva/sdk"
)

func main() {
	fmt.Println("[MINERVA] Editor example loaded")

	// Block forever — keep WASM alive for JS interop.
	select {}
}
