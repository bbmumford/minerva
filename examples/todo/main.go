//go:build js && wasm

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * Todo example — minimal WASM entry point demonstrating a collaborative
 * todo list backed by Minerva's LWW-Map CRDT.
 *
 * Build:
 *   GOOS=js GOARCH=wasm go build -o todo.wasm ./examples/todo/
 *
 * Serve index.html with wasm_exec.js and todo.wasm in the same directory.
 */
package main

import (
	"fmt"

	_ "github.com/bbmumford/minerva/crdt"
	_ "github.com/bbmumford/minerva/sdk"
)

func main() {
	fmt.Println("[MINERVA] Todo example loaded")

	// Block forever — keep WASM alive for JS interop.
	select {}
}
