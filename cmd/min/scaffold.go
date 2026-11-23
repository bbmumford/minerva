/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// scaffoldApp creates a new Minerva app directory with the minimal project
// structure: go.mod, wasm/main.go, dist/, and index.html.
func scaffoldApp(appName string) error {
	if appName == "" {
		return fmt.Errorf("app name is required")
	}

	// Create directory structure.
	dirs := []string{
		appName,
		filepath.Join(appName, "wasm"),
		filepath.Join(appName, "dist"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", d, err)
		}
	}

	// go.mod
	goMod := fmt.Sprintf(`module %s

go 1.25.0

require github.com/bbmumford/minerva v0.0.1
`, appName)
	if err := os.WriteFile(filepath.Join(appName, "go.mod"), []byte(goMod), 0o644); err != nil {
		return fmt.Errorf("write go.mod: %w", err)
	}

	// wasm/main.go
	wasmMain := fmt.Sprintf(`//go:build js && wasm

/*
 * %s — Minerva WASM application
 */
package main

import (
	"fmt"
)

func main() {
	fmt.Println("[%s] WASM module loaded")

	// TODO: Register your JS bridge functions here.
	// Example:
	//   js.Global().Set("MyApp", js.ValueOf(map[string]interface{}{
	//       "hello": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
	//           return "Hello from %s!"
	//       }),
	//   }))

	// Block forever — keep WASM alive.
	select {}
}
`, appName, appName, appName)
	if err := os.WriteFile(filepath.Join(appName, "wasm", "main.go"), []byte(wasmMain), 0o644); err != nil {
		return fmt.Errorf("write wasm/main.go: %w", err)
	}

	// index.html
	indexHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
</head>
<body>
    <h1>%s</h1>
    <p>Minerva P2P application</p>

    <script src="wasm_exec.js"></script>
    <script src="minerva.js"></script>
    <script>
        (async function() {
            const go = new Go();
            const result = await WebAssembly.instantiateStreaming(
                fetch('app.wasm'), go.importObject
            );
            go.run(result.instance);
            console.log('%s WASM loaded');
        })();
    </script>
</body>
</html>
`, appName, appName, appName)
	if err := os.WriteFile(filepath.Join(appName, "index.html"), []byte(indexHTML), 0o644); err != nil {
		return fmt.Errorf("write index.html: %w", err)
	}

	fmt.Printf("Scaffolded Minerva app: %s/\n", appName)
	fmt.Println("  go.mod")
	fmt.Println("  wasm/main.go")
	fmt.Println("  dist/")
	fmt.Println("  index.html")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  cd " + appName)
	fmt.Println("  min build")
	fmt.Println("  min dev")
	return nil
}
