package identity

import (
	"crypto/ed25519"
	"testing"
)

func TestRevokeDeviceAndVerify(t *testing.T) {
	master, _ := Generate()
	device, _ := Generate()

	rec, err := RevokeDevice(master, device.PublicKey, "compromised")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRevocation(rec) {
		t.Fatal("revocation should verify")
	}
	if rec.Reason != "compromised" {
		t.Fatalf("expected reason 'compromised', got %q", rec.Reason)
	}
}

func TestRevokeDeviceErrors(t *testing.T) {
	master, _ := Generate()

	if _, err := RevokeDevice(nil, make([]byte, 32), "x"); err == nil {
		t.Fatal("expected error for nil master")
	}
	if _, err := RevokeDevice(master, []byte{1}, "x"); err == nil {
		t.Fatal("expected error for bad device key")
	}
}

func TestVerifyRevocationTampered(t *testing.T) {
	master, _ := Generate()
	device, _ := Generate()
	rec, _ := RevokeDevice(master, device.PublicKey, "reason")

	rec.Reason = "different"
	if VerifyRevocation(rec) {
		t.Fatal("tampered revocation should not verify")
	}
}

func TestVerifyRevocationNil(t *testing.T) {
	if VerifyRevocation(nil) {
		t.Fatal("nil revocation should not verify")
	}
}

func TestVerifyRevocationBadKeyLengths(t *testing.T) {
	rec := &RevocationRecord{
		RevokerPublicKey: ed25519.PublicKey(make([]byte, 10)),
		RevokedPublicKey: ed25519.PublicKey(make([]byte, 32)),
	}
	if VerifyRevocation(rec) {
		t.Fatal("bad revoker key length should not verify")
	}
}

func TestRevocationRegistry(t *testing.T) {
	master, _ := Generate()
	device1, _ := Generate()
	device2, _ := Generate()

	reg := NewRevocationRegistry()

	rec1, _ := RevokeDevice(master, device1.PublicKey, "lost")
	rec2, _ := RevokeDevice(master, device2.PublicKey, "expired")

	if err := reg.Add(rec1); err != nil {
		t.Fatal(err)
	}
	if err := reg.Add(rec2); err != nil {
		t.Fatal(err)
	}

	if !reg.IsRevoked(device1.PublicKey) {
		t.Fatal("device1 should be revoked")
	}
	if !reg.IsRevoked(device2.PublicKey) {
		t.Fatal("device2 should be revoked")
	}
	if reg.IsRevoked(master.PublicKey) {
		t.Fatal("master should not be revoked")
	}

	all := reg.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 records, got %d", len(all))
	}
}

func TestRevocationRegistryRejectsInvalid(t *testing.T) {
	reg := NewRevocationRegistry()
	rec := &RevocationRecord{
		RevokedPublicKey: ed25519.PublicKey(make([]byte, 32)),
		RevokerPublicKey: ed25519.PublicKey(make([]byte, 32)),
		Signature:        []byte("bad"),
	}
	if err := reg.Add(rec); err == nil {
		t.Fatal("expected error for invalid revocation")
	}
}
