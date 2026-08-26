/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * Content-addressed WASM verification — works on all platforms.
 */
package wasmcid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ComputeCID computes the SHA-256 content identifier for a WASM binary.
// Returns the hex-encoded hash string.
func ComputeCID(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// VerifyWASM checks that a WASM binary matches the expected CID.
// Returns nil on match, an error describing the mismatch otherwise.
func VerifyWASM(wasmBytes []byte, expectedCID string) error {
	actual := ComputeCID(wasmBytes)
	if actual != expectedCID {
		return fmt.Errorf("wasmcid: CID mismatch: expected %s, got %s", expectedCID, actual)
	}
	return nil
}
