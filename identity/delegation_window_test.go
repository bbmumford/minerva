package identity

import (
	"testing"
	"time"
)

// A certificate issued further in the future than peers' allowed clock drift
// does not verify yet.
func TestVerifyCertificateRefusesACertificateIssuedInTheFuture(t *testing.T) {
	master, _ := Generate()
	device, _ := Generate()
	cert, err := DelegateDevice(master, device.PublicKey, []string{"read"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("DelegateDevice: %v", err)
	}
	if !verifyDeviceCertificateAt(cert, cert.IssuedAt) {
		t.Fatal("a certificate did not verify at its issue time")
	}
	if verifyDeviceCertificateAt(cert, cert.IssuedAt.Add(-2*time.Minute)) {
		t.Fatal("a certificate verified two minutes before it was issued")
	}
}
