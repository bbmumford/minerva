/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package messaging

import "crypto/ed25519"

// ed25519VerifyShim is a tiny indirection the test file uses so it does
// not have to import crypto/ed25519 directly.
func ed25519VerifyShim(pub, data, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub), data, sig)
}
