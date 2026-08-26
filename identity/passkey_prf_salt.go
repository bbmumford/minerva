//go:build !js

package identity

import "crypto/sha256"

// nativePRFSalt returns the deterministic salt used as input to the WebAuthn
// PRF (hmac-secret) extension's `eval.first` value. Native platforms must use
// the SAME salt formula as the browser (see passkey_browser.go prfSalt) so
// that a credential registered in one environment can be used to unlock the
// wallet in the other.
func nativePRFSalt(rpID string) []byte {
	h := sha256.Sum256([]byte("minerva-prf-salt:" + rpID))
	return h[:]
}
