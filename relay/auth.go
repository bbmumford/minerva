/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"
)

// RelayAuthRequest is sent by a client when authenticating to a relay.
// The relay verifies the signature to confirm the client owns the keypair.
type RelayAuthRequest struct {
	// PeerID is the hex-encoded peer identity.
	PeerID string `json:"peerID"`
	// PublicKey is the base64-encoded Ed25519 public key (32 bytes).
	PublicKey string `json:"publicKey"`
	// Timestamp is the Unix timestamp (seconds) when the request was created.
	Timestamp int64 `json:"timestamp"`
	// Signature is the base64-encoded Ed25519 signature over the auth payload.
	Signature string `json:"signature"`
}

// authPayload builds the canonical byte sequence that is signed/verified.
func authPayload(peerID string, timestamp int64) []byte {
	return []byte(fmt.Sprintf("relay-auth:%s:%d", peerID, timestamp))
}

// SignAuthRequest creates a signed RelayAuthRequest from a keypair.
func SignAuthRequest(peerID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) RelayAuthRequest {
	ts := time.Now().Unix()
	payload := authPayload(peerID, ts)
	sig := ed25519.Sign(priv, payload)
	return RelayAuthRequest{
		PeerID:    peerID,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Timestamp: ts,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

// VerifyAuthRequest checks that the signature is valid and the request is recent.
// maxAge is the maximum allowed age of the timestamp (e.g. 60 seconds).
func VerifyAuthRequest(req RelayAuthRequest, maxAge time.Duration) error {
	// Decode public key.
	pubBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		return fmt.Errorf("relay auth: decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("relay auth: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pubBytes))
	}
	pub := ed25519.PublicKey(pubBytes)

	// Check timestamp freshness.
	age := time.Since(time.Unix(req.Timestamp, 0))
	if age < 0 {
		age = -age
	}
	if age > maxAge {
		return fmt.Errorf("relay auth: request too old (%s > %s)", age, maxAge)
	}

	// Decode and verify signature.
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return fmt.Errorf("relay auth: decode signature: %w", err)
	}

	payload := authPayload(req.PeerID, req.Timestamp)
	if !ed25519.Verify(pub, payload, sigBytes) {
		return fmt.Errorf("relay auth: invalid signature")
	}

	return nil
}
