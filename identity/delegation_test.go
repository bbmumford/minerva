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

// A certificate past its expiry no longer verifies: a device key's grant ends
// when the master said it would.
func TestVerifyCertificateRefusesAnExpiredCertificate(t *testing.T) {
	master, _ := Generate()
	device, _ := Generate()
	cert, err := DelegateDevice(master, device.PublicKey, []string{"read"}, time.Millisecond)
	if err != nil {
		t.Fatalf("DelegateDevice: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if VerifyDeviceCertificate(cert) {
		t.Fatal("an expired certificate verified")
	}
}

// Each capability keeps its own boundary in the signed payload: a certificate
// cannot be re-read with its capabilities split or joined differently, whether
// the count changes ({"read,write"} as {"read", "write"}) or not ({"ab", "c"}
// as {"a", "bc"}).
func TestVerifyCertificateRefusesRegroupedCapabilities(t *testing.T) {
	master, _ := Generate()
	device, _ := Generate()
	for _, c := range []struct{ signed, forged []string }{
		{[]string{"read,write"}, []string{"read", "write"}},
		{[]string{"ab", "c"}, []string{"a", "bc"}},
	} {
		cert, err := DelegateDevice(master, device.PublicKey, c.signed, time.Hour)
		if err != nil {
			t.Fatalf("DelegateDevice: %v", err)
		}
		forged := *cert
		forged.Capabilities = c.forged
		if VerifyDeviceCertificate(&forged) {
			t.Errorf("a certificate for %q verified as %q", c.signed, c.forged)
		}
	}
}
