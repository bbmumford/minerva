/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * min — CLI toolchain for building, testing, and publishing
 * Minerva P2P WASM applications.
 *
 * Usage:
 *   min init <app-name>    Scaffold a new Minerva app
 *   min build              Build the WASM binary into dist/
 *   min dev                Build and serve with live-reload
 *   min publish <dir>      Compute CID and copy dist/ to target
 *   min verify <path>      Print the CID of a WASM file
 */
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error

	switch os.Args[1] {
	case "init":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: min init <app-name>")
			os.Exit(1)
		}
		err = scaffoldApp(os.Args[2])

	case "build":
		err = buildApp()

	case "dev":
		err = devServer()

	case "publish":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: min publish <target-dir>")
			os.Exit(1)
		}
		err = publishApp(os.Args[2])

	case "verify":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: min verify <path-to-wasm>")
			os.Exit(1)
		}
		err = verifyWASM(os.Args[2])

	case "help", "--help", "-h":
		printUsage()
		return

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// publishApp computes the SHA-256 CID of the built WASM binary and copies
// the entire dist/ directory to the target directory.
func publishApp(targetDir string) error {
	wasmPath := filepath.Join("dist", "app.wasm")
	data, err := os.ReadFile(wasmPath)
	if err != nil {
		return fmt.Errorf("read %s: %w (did you run 'min build'?)", wasmPath, err)
	}

	cid := computeCID(data)
	fmt.Printf("WASM CID: %s\n", cid)

	// Create target directory.
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}

	// Copy all files from dist/ to target.
	entries, err := os.ReadDir("dist")
	if err != nil {
		return fmt.Errorf("read dist/: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		src := filepath.Join("dist", entry.Name())
		dst := filepath.Join(targetDir, entry.Name())
		fileData, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read %s: %w", src, err)
		}
		if err := os.WriteFile(dst, fileData, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
		fmt.Printf("  %s -> %s\n", src, dst)
	}

	// Write a CID file for reference.
	cidFile := filepath.Join(targetDir, "app.wasm.cid")
	if err := os.WriteFile(cidFile, []byte(cid+"\n"), 0o644); err != nil {
		return fmt.Errorf("write CID file: %w", err)
	}
	fmt.Printf("  CID written to %s\n", cidFile)
	fmt.Println("Publish complete.")
	return nil
}

// verifyWASM reads a WASM file and prints its SHA-256 CID.
func verifyWASM(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	cid := computeCID(data)
	fmt.Printf("%s  %s\n", cid, path)
	return nil
}

// computeCID returns the SHA-256 hex digest of data.
func computeCID(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func printUsage() {
	fmt.Println(`min — CLI toolchain for Minerva P2P WASM apps

Usage:
  min init <app-name>    Scaffold a new Minerva app
  min build              Build the WASM binary into dist/
  min dev                Build and serve with live-reload
  min publish <dir>      Compute CID and copy dist/ to target
  min verify <path>      Print the CID of a WASM file
  min help               Show this help message`)
}
