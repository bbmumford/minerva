package identity

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DeviceKeyCertificate represents a delegated device key signed by a master key.
// The master key grants the device key specific capabilities for a limited time.
type DeviceKeyCertificate struct {
	DevicePublicKey ed25519.PublicKey `json:"devicePublicKey"`
	MasterPublicKey ed25519.PublicKey `json:"masterPublicKey"`
	Capabilities    []string         `json:"capabilities"`
	ExpiresAt       time.Time        `json:"expiresAt"`
	IssuedAt        time.Time        `json:"issuedAt"`
	Signature       []byte           `json:"signature"`
}

// delegationSigningPayload builds the canonical byte payload for signing:
// devicePubKey || capabilities (sorted, joined with ",") || expiresAt (unix nanos, big-endian) || issuedAt (unix nanos, big-endian)
func delegationSigningPayload(devicePubKey ed25519.PublicKey, caps []string, expiresAt, issuedAt time.Time) []byte {
	sorted := make([]string, len(caps))
	copy(sorted, caps)
	sort.Strings(sorted)
	joined := strings.Join(sorted, ",")

	// devicePubKey (32) + joined caps + 8 bytes expiresAt + 8 bytes issuedAt
	buf := make([]byte, 0, len(devicePubKey)+len(joined)+16)
	buf = append(buf, devicePubKey...)
	buf = append(buf, []byte(joined)...)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(expiresAt.UnixNano()))
	buf = append(buf, ts[:]...)
	binary.BigEndian.PutUint64(ts[:], uint64(issuedAt.UnixNano()))
	buf = append(buf, ts[:]...)

	return buf
}

// DelegateDevice creates a DeviceKeyCertificate granting capabilities to a device key.
// The master keypair signs the certificate. ttl controls how long the delegation is valid.
func DelegateDevice(masterKeypair *Keypair, devicePubKey ed25519.PublicKey, caps []string, ttl time.Duration) (*DeviceKeyCertificate, error) {
	if masterKeypair == nil {
		return nil, fmt.Errorf("identity/delegation: master keypair is nil")
	}
	if len(devicePubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity/delegation: invalid device public key length: %d", len(devicePubKey))
	}
	if len(caps) == 0 {
		return nil, fmt.Errorf("identity/delegation: capabilities must not be empty")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("identity/delegation: ttl must be positive")
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	payload := delegationSigningPayload(devicePubKey, caps, expiresAt, now)
	sig := masterKeypair.Sign(payload)

	// Store capabilities sorted for deterministic comparison.
	sorted := make([]string, len(caps))
	copy(sorted, caps)
	sort.Strings(sorted)

	return &DeviceKeyCertificate{
		DevicePublicKey: devicePubKey,
		MasterPublicKey: masterKeypair.PublicKey,
		Capabilities:    sorted,
		ExpiresAt:       expiresAt,
		IssuedAt:        now,
		Signature:       sig,
	}, nil
}

// VerifyDeviceCertificate checks that the certificate signature is valid
// against the master public key and the canonical payload.
func VerifyDeviceCertificate(cert *DeviceKeyCertificate) bool {
	if cert == nil {
		return false
	}
	if len(cert.MasterPublicKey) != ed25519.PublicKeySize || len(cert.DevicePublicKey) != ed25519.PublicKeySize {
		return false
	}
	payload := delegationSigningPayload(cert.DevicePublicKey, cert.Capabilities, cert.ExpiresAt, cert.IssuedAt)
	return ed25519.Verify(cert.MasterPublicKey, payload, cert.Signature)
}

// IsExpired returns true if the certificate has passed its expiration time.
func (c *DeviceKeyCertificate) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// HasCapability returns true if the certificate includes the given capability.
func (c *DeviceKeyCertificate) HasCapability(cap string) bool {
	for _, v := range c.Capabilities {
		if v == cap {
			return true
		}
	}
	return false
}

// Encode serializes the certificate to JSON.
func (c *DeviceKeyCertificate) Encode() ([]byte, error) {
	return json.Marshal(c)
}

// DecodeDeviceCertificate deserializes a certificate from JSON.
func DecodeDeviceCertificate(data []byte) (*DeviceKeyCertificate, error) {
	var cert DeviceKeyCertificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, fmt.Errorf("identity/delegation: decode: %w", err)
	}
	return &cert, nil
}
