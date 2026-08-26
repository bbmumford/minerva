package identity

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestDelegateDevice(t *testing.T) {
	master, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	device, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := DelegateDevice(master, device.PublicKey, []string{"read", "write", "gossip"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyDeviceCertificate(cert) {
		t.Fatal("certificate should verify")
	}
	if cert.IsExpired() {
		t.Fatal("certificate should not be expired")
	}
	if !cert.HasCapability("read") {
		t.Fatal("should have read capability")
	}
	if !cert.HasCapability("gossip") {
		t.Fatal("should have gossip capability")
	}
	if cert.HasCapability("admin") {
		t.Fatal("should not have admin capability")
	}

	// Capabilities should be sorted.
	if cert.Capabilities[0] != "gossip" || cert.Capabilities[1] != "read" || cert.Capabilities[2] != "write" {
		t.Fatalf("capabilities should be sorted, got %v", cert.Capabilities)
	}
}

func TestDelegateDeviceErrors(t *testing.T) {
	master, _ := Generate()
	device, _ := Generate()

	if _, err := DelegateDevice(nil, device.PublicKey, []string{"read"}, time.Hour); err == nil {
		t.Fatal("expected error for nil master")
	}
	if _, err := DelegateDevice(master, []byte{1, 2, 3}, []string{"read"}, time.Hour); err == nil {
		t.Fatal("expected error for bad device key")
	}
	if _, err := DelegateDevice(master, device.PublicKey, nil, time.Hour); err == nil {
		t.Fatal("expected error for empty caps")
	}
	if _, err := DelegateDevice(master, device.PublicKey, []string{"read"}, -time.Hour); err == nil {
		t.Fatal("expected error for negative ttl")
	}
}

func TestVerifyCertificateTampered(t *testing.T) {
	master, _ := Generate()
	device, _ := Generate()
	cert, _ := DelegateDevice(master, device.PublicKey, []string{"read"}, time.Hour)

	// Tamper with capability.
	cert.Capabilities = []string{"admin"}
	if VerifyDeviceCertificate(cert) {
		t.Fatal("tampered certificate should not verify")
	}
}

func TestVerifyCertificateWrongMaster(t *testing.T) {
	master, _ := Generate()
	other, _ := Generate()
	device, _ := Generate()
	cert, _ := DelegateDevice(master, device.PublicKey, []string{"read"}, time.Hour)

	cert.MasterPublicKey = other.PublicKey
	if VerifyDeviceCertificate(cert) {
		t.Fatal("certificate with wrong master key should not verify")
	}
}

func TestVerifyCertificateNil(t *testing.T) {
	if VerifyDeviceCertificate(nil) {
		t.Fatal("nil certificate should not verify")
	}
}

func TestCertificateExpiry(t *testing.T) {
	master, _ := Generate()
	device, _ := Generate()
	cert, _ := DelegateDevice(master, device.PublicKey, []string{"read"}, time.Nanosecond)

	time.Sleep(time.Millisecond)
	if !cert.IsExpired() {
		t.Fatal("certificate should be expired")
	}
}

func TestCertificateEncodeDecode(t *testing.T) {
	master, _ := Generate()
	device, _ := Generate()
	cert, _ := DelegateDevice(master, device.PublicKey, []string{"write", "read"}, time.Hour)

	data, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeDeviceCertificate(data)
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyDeviceCertificate(decoded) {
		t.Fatal("decoded certificate should verify")
	}
	if !decoded.HasCapability("read") || !decoded.HasCapability("write") {
		t.Fatal("decoded certificate should preserve capabilities")
	}
	if !decoded.DevicePublicKey.Equal(device.PublicKey) {
		t.Fatal("decoded certificate should preserve device key")
	}
}

func TestDecodeDeviceCertificateInvalid(t *testing.T) {
	if _, err := DecodeDeviceCertificate([]byte("not json")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestVerifyCertificateBadKeyLengths(t *testing.T) {
	cert := &DeviceKeyCertificate{
		MasterPublicKey: ed25519.PublicKey(make([]byte, 10)),
		DevicePublicKey: ed25519.PublicKey(make([]byte, 32)),
	}
	if VerifyDeviceCertificate(cert) {
		t.Fatal("bad master key length should not verify")
	}
	cert.MasterPublicKey = ed25519.PublicKey(make([]byte, 32))
	cert.DevicePublicKey = ed25519.PublicKey(make([]byte, 10))
	if VerifyDeviceCertificate(cert) {
		t.Fatal("bad device key length should not verify")
	}
}
