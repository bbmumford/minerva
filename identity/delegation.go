package identity

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/bbmumford/minerva/crdt"
)

// DeviceKeyCertificate represents a delegated device key signed by a master key.
// The master key grants the device key specific capabilities for a limited time.
type DeviceKeyCertificate struct {
	DevicePublicKey ed25519.PublicKey `json:"devicePublicKey"`
	MasterPublicKey ed25519.PublicKey `json:"masterPublicKey"`
	Capabilities    []string          `json:"capabilities"`
	ExpiresAt       time.Time         `json:"expiresAt"`
	IssuedAt        time.Time         `json:"issuedAt"`
	Signature       []byte            `json:"signature"`
}

// delegationDomain begins every device-key certificate's signed payload, so a
// master key's signature over a certificate can never be read as its
// signature over any other message it signs.
const delegationDomain = "minerva/identity/device-key-certificate/v1"

// delegationSigningPayload builds the bytes a master key signs for a device key
// certificate: the domain, the device and master keys (fixed 32 bytes each),
// the issue and expiry times, then the capability count and each capability
// with its length before it. Every capability keeps its own boundary, so
// {"read,write"} and {"read", "write"} sign different payloads.
func delegationSigningPayload(devicePubKey, masterPubKey ed25519.PublicKey, caps []string, expiresAt, issuedAt time.Time) []byte {
	sorted := make([]string, len(caps))
	copy(sorted, caps)
	sort.Strings(sorted)

	size := len(delegationDomain) + 1 + len(devicePubKey) + len(masterPubKey) + 8 + 8 + 4
	for _, c := range sorted {
		size += 4 + len(c)
	}
	buf := make([]byte, 0, size)
	buf = append(buf, delegationDomain...)
	buf = append(buf, 0)
	buf = append(buf, devicePubKey...)
	buf = append(buf, masterPubKey...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(issuedAt.UnixNano()))
	buf = binary.BigEndian.AppendUint64(buf, uint64(expiresAt.UnixNano()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(sorted)))
	for _, c := range sorted {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(c)))
		buf = append(buf, c...)
	}
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

	payload := delegationSigningPayload(devicePubKey, masterKeypair.PublicKey, caps, expiresAt, now)
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
// against the master public key and the canonical payload, and that the
// certificate is within its validity window now: not expired, and not issued
// later than now by more than the clock drift peers allow (crdt.MaxDrift).
func VerifyDeviceCertificate(cert *DeviceKeyCertificate) bool {
	return verifyDeviceCertificateAt(cert, time.Now())
}

func verifyDeviceCertificateAt(cert *DeviceKeyCertificate, now time.Time) bool {
	if cert == nil {
		return false
	}
	if len(cert.MasterPublicKey) != ed25519.PublicKeySize || len(cert.DevicePublicKey) != ed25519.PublicKeySize {
		return false
	}
	if !now.Before(cert.ExpiresAt) || cert.IssuedAt.After(now.Add(crdt.MaxDrift)) {
		return false
	}
	payload := delegationSigningPayload(cert.DevicePublicKey, cert.MasterPublicKey, cert.Capabilities, cert.ExpiresAt, cert.IssuedAt)
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
