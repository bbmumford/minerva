/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// buildApp compiles the WASM binary from ./wasm/ and copies supporting
// assets (wasm_exec.js, minerva.js, index.html) into dist/.
func buildApp() error {
	// Verify wasm/ directory exists.
	if _, err := os.Stat("wasm"); os.IsNotExist(err) {
		return fmt.Errorf("wasm/ directory not found — run this from a Minerva app root")
	}

	// Create dist/ if it doesn't exist.
	if err := os.MkdirAll("dist", 0o755); err != nil {
		return fmt.Errorf("create dist/: %w", err)
	}

	// Build the WASM binary.
	fmt.Println("Building WASM binary...")
	cmd := exec.Command("go", "build", "-o", filepath.Join("dist", "app.wasm"), "./wasm/")
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build failed: %w", err)
	}
	fmt.Println("  -> dist/app.wasm")

	// Copy wasm_exec.js from the Go installation.
	wasmExecSrc := filepath.Join(goroot(), "lib", "wasm", "wasm_exec.js")
	if err := copyFile(wasmExecSrc, filepath.Join("dist", "wasm_exec.js")); err != nil {
		// Not fatal — user may provide their own.
		fmt.Printf("  Warning: could not copy wasm_exec.js from GOROOT: %v\n", err)
	} else {
		fmt.Println("  -> dist/wasm_exec.js")
	}

	// Copy minerva.js if it exists in the project.
	minervaJSSrc := findMinervaJS()
	if minervaJSSrc != "" {
		if err := copyFile(minervaJSSrc, filepath.Join("dist", "minerva.js")); err != nil {
			fmt.Printf("  Warning: could not copy minerva.js: %v\n", err)
		} else {
			fmt.Println("  -> dist/minerva.js")
		}
	}

	// Copy index.html if it exists at the project root.
	if _, err := os.Stat("index.html"); err == nil {
		if err := copyFile("index.html", filepath.Join("dist", "index.html")); err != nil {
			fmt.Printf("  Warning: could not copy index.html: %v\n", err)
		} else {
			fmt.Println("  -> dist/index.html")
		}
	}

	fmt.Println("Build complete.")
	return nil
}

// findMinervaJS searches for the minerva.js SDK file in common locations.
func findMinervaJS() string {
	candidates := []string{
		"minerva.js",
		filepath.Join("wasm", "minerva.js"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// copyFile copies a file from src to dst, creating or truncating dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// goroot returns the Go root of the go command on PATH (the one this tool
// runs for the build), falling back to GOROOT from the environment.
func goroot() string {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err == nil {
		if root := strings.TrimSpace(string(out)); root != "" {
			return root
		}
	}
	return os.Getenv("GOROOT")
}
