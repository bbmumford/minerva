/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// AppManifest describes a published Minerva application in the registry.
type AppManifest struct {
	AppID        string
	Name         string
	Description  string
	IconCID      string
	WASMCID      string
	Version      string
	AuthorPubKey []byte
	Signature    []byte
	Permissions  []string
	Categories   []string
	Homepage     string
	MinSDK       string
	NativeOnly   bool
	CreatedAt    time.Time
}

// signaturePayload builds the deterministic byte payload that is signed.
// The signature covers all manifest fields except the Signature itself.
func signaturePayload(m *AppManifest) []byte {
	var buf []byte

	appendStr := func(s string) {
		b := []byte(s)
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(b)))
		buf = append(buf, lenBuf...)
		buf = append(buf, b...)
	}

	appendStrSlice := func(ss []string) {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(ss)))
		buf = append(buf, lenBuf...)
		for _, s := range ss {
			appendStr(s)
		}
	}

	appendStr(m.AppID)
	appendStr(m.Name)
	appendStr(m.Description)
	appendStr(m.IconCID)
	appendStr(m.WASMCID)
	appendStr(m.Version)

	// Author public key.
	keyLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(keyLenBuf, uint32(len(m.AuthorPubKey)))
	buf = append(buf, keyLenBuf...)
	buf = append(buf, m.AuthorPubKey...)

	appendStrSlice(m.Permissions)
	appendStrSlice(m.Categories)
	appendStr(m.Homepage)
	appendStr(m.MinSDK)

	if m.NativeOnly {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// Timestamp as Unix nanoseconds for determinism.
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(m.CreatedAt.UnixNano()))
	buf = append(buf, tsBuf...)

	// Hash the payload for a fixed-size signing input.
	h := sha256.Sum256(buf)
	return h[:]
}

// SignManifest signs the manifest with the given Ed25519 private key and
// writes the resulting signature into m.Signature.
func SignManifest(m *AppManifest, privateKey ed25519.PrivateKey) {
	payload := signaturePayload(m)
	m.Signature = ed25519.Sign(privateKey, payload)
}

// VerifyManifest returns true if the manifest's Signature is a valid
// Ed25519 signature over the manifest content using AuthorPubKey.
func VerifyManifest(m *AppManifest) bool {
	if len(m.AuthorPubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(m.Signature) != ed25519.SignatureSize {
		return false
	}
	payload := signaturePayload(m)
	return ed25519.Verify(ed25519.PublicKey(m.AuthorPubKey), payload, m.Signature)
}

// Validate checks that the manifest has the minimum required fields populated.
func Validate(m *AppManifest) error {
	if m.AppID == "" {
		return fmt.Errorf("registry: manifest AppID is required")
	}
	if m.Name == "" {
		return fmt.Errorf("registry: manifest Name is required")
	}
	if m.WASMCID == "" {
		return fmt.Errorf("registry: manifest WASMCID is required")
	}
	if m.Version == "" {
		return fmt.Errorf("registry: manifest Version is required")
	}
	if len(m.AuthorPubKey) == 0 {
		return fmt.Errorf("registry: manifest AuthorPubKey is required")
	}
	return nil
}
