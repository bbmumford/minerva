//go:build darwin && cgo && !js

package identity

/*
#cgo CFLAGS: -x objective-c -fobjc-arc -Wno-deprecated-declarations
#cgo LDFLAGS: -framework AuthenticationServices -framework Foundation -framework AppKit

#include <stdlib.h>
#include <stdint.h>

// Forward declarations implemented in passkey_macos.m.
//
// All strings are UTF-8 C strings. Byte buffers are (ptr,len) pairs.
// Each function writes its result into the provided out_* pointers.
// On failure it returns a non-zero error code and out_err is set to a
// UTF-8 C string (caller must free with free()).
//
// Success: returns 0. Caller must free all returned malloc'd buffers.

int minerva_passkey_available(void);

int minerva_passkey_register(
    const char* rp_id,
    const char* rp_name,
    const uint8_t* user_handle, int user_handle_len,
    const char* user_name,
    const char* user_display_name,
    const uint8_t* challenge, int challenge_len,
    const uint8_t* prf_salt, int prf_salt_len,
    uint8_t** out_credential_id, int* out_credential_id_len,
    uint8_t** out_prf_output,    int* out_prf_output_len,
    char**    out_err
);

int minerva_passkey_assert(
    const char* rp_id,
    const uint8_t* credential_id, int credential_id_len,
    const uint8_t* challenge, int challenge_len,
    const uint8_t* prf_salt, int prf_salt_len,
    uint8_t** out_prf_output, int* out_prf_output_len,
    char**    out_err
);
*/
import "C"

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
	"unsafe"
)

// NativePasskeyProvider implements PasskeyProvider on macOS using
// AuthenticationServices (ASAuthorizationController) — the same system API
// that Safari and Keychain use for platform passkeys. Touch ID / local-user
// auth surfaces automatically when a platform credential is created or used.
//
// PRF support: macOS 14+ implements the WebAuthn PRF extension at the
// platform authenticator layer. On macOS 13 and earlier, PRF returns an
// error and this provider falls back to ErrPasskeyNotAvailable for
// registration.
type NativePasskeyProvider struct{}

// NewNativePasskeyProvider creates a new macOS passkey provider.
func NewNativePasskeyProvider() *NativePasskeyProvider {
	return &NativePasskeyProvider{}
}

// IsAvailable returns true if AuthenticationServices can be used. We
// conservatively return true for any darwin build; actual capability is
// re-checked at registration time (PRF requires macOS 14).
func (p *NativePasskeyProvider) IsAvailable() bool {
	return C.minerva_passkey_available() != 0
}

// Register creates a new platform passkey via ASAuthorizationController and
// returns the credential + 32-byte PRF-derived key.
func (p *NativePasskeyProvider) Register(ctx context.Context, rpID string, userHandle []byte, displayName string) (*PasskeyCredential, []byte, error) {
	if !p.IsAvailable() {
		return nil, nil, ErrPasskeyNotAvailable
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, nil, fmt.Errorf("passkey-macos: challenge: %w", err)
	}
	salt := nativePRFSalt(rpID)

	cRPID := C.CString(rpID)
	defer C.free(unsafe.Pointer(cRPID))
	cRPName := C.CString("Minerva")
	defer C.free(unsafe.Pointer(cRPName))
	cUserName := C.CString(displayName)
	defer C.free(unsafe.Pointer(cUserName))
	cUserDisplay := C.CString(displayName)
	defer C.free(unsafe.Pointer(cUserDisplay))

	var (
		outCredID    *C.uint8_t
		outCredIDLen C.int
		outPRF       *C.uint8_t
		outPRFLen    C.int
		outErr       *C.char
	)

	type result struct {
		cred   *PasskeyCredential
		prfKey []byte
		err    error
	}
	done := make(chan result, 1)

	go func() {
		rc := C.minerva_passkey_register(
			cRPID, cRPName,
			(*C.uint8_t)(unsafe.Pointer(bytesHead(userHandle))), C.int(len(userHandle)),
			cUserName, cUserDisplay,
			(*C.uint8_t)(unsafe.Pointer(&challenge[0])), C.int(len(challenge)),
			(*C.uint8_t)(unsafe.Pointer(&salt[0])), C.int(len(salt)),
			&outCredID, &outCredIDLen,
			&outPRF, &outPRFLen,
			&outErr,
		)
		if rc != 0 {
			msg := "unknown error"
			if outErr != nil {
				msg = C.GoString(outErr)
				C.free(unsafe.Pointer(outErr))
			}
			done <- result{err: fmt.Errorf("passkey-macos: register: %s", msg)}
			return
		}
		credID := C.GoBytes(unsafe.Pointer(outCredID), outCredIDLen)
		prfKey := C.GoBytes(unsafe.Pointer(outPRF), outPRFLen)
		if outCredID != nil {
			C.free(unsafe.Pointer(outCredID))
		}
		if outPRF != nil {
			C.free(unsafe.Pointer(outPRF))
		}
		if len(prfKey) != 32 {
			done <- result{err: fmt.Errorf("passkey-macos: PRF output is %d bytes, expected 32 (macOS 14+ required)", len(prfKey))}
			return
		}
		now := time.Now()
		done <- result{
			cred: &PasskeyCredential{
				CredentialID: credID,
				RPEntityID:   rpID,
				UserHandle:   userHandle,
				CreatedAt:    now,
				LastUsedAt:   now,
				DisplayName:  displayName,
			},
			prfKey: prfKey,
		}
	}()

	select {
	case r := <-done:
		return r.cred, r.prfKey, r.err
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

// Authenticate evaluates PRF on an existing credential and returns the key.
func (p *NativePasskeyProvider) Authenticate(ctx context.Context, credentialID []byte, rpID string) ([]byte, error) {
	if !p.IsAvailable() {
		return nil, ErrPasskeyNotAvailable
	}
	if len(credentialID) == 0 {
		return nil, errors.New("passkey-macos: empty credentialID")
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("passkey-macos: challenge: %w", err)
	}
	salt := nativePRFSalt(rpID)

	cRPID := C.CString(rpID)
	defer C.free(unsafe.Pointer(cRPID))

	var (
		outPRF    *C.uint8_t
		outPRFLen C.int
		outErr    *C.char
	)

	type result struct {
		prfKey []byte
		err    error
	}
	done := make(chan result, 1)

	go func() {
		rc := C.minerva_passkey_assert(
			cRPID,
			(*C.uint8_t)(unsafe.Pointer(&credentialID[0])), C.int(len(credentialID)),
			(*C.uint8_t)(unsafe.Pointer(&challenge[0])), C.int(len(challenge)),
			(*C.uint8_t)(unsafe.Pointer(&salt[0])), C.int(len(salt)),
			&outPRF, &outPRFLen,
			&outErr,
		)
		if rc != 0 {
			msg := "unknown error"
			if outErr != nil {
				msg = C.GoString(outErr)
				C.free(unsafe.Pointer(outErr))
			}
			done <- result{err: fmt.Errorf("passkey-macos: assert: %s", msg)}
			return
		}
		prfKey := C.GoBytes(unsafe.Pointer(outPRF), outPRFLen)
		if outPRF != nil {
			C.free(unsafe.Pointer(outPRF))
		}
		if len(prfKey) != 32 {
			done <- result{err: fmt.Errorf("passkey-macos: PRF output is %d bytes, expected 32", len(prfKey))}
			return
		}
		done <- result{prfKey: prfKey}
	}()

	select {
	case r := <-done:
		return r.prfKey, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// bytesHead returns a pointer to the first element of a byte slice, or nil
// if the slice is empty. Avoids the "index out of range" panic when the
// slice has length zero.
func bytesHead(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}
