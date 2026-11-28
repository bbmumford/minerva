//go:build linux && cgo && !android && !js

package identity

/*
#cgo pkg-config: libfido2
#include <fido.h>
#include <stdlib.h>
#include <string.h>

// ------------------------------------------------------------
// Small C helpers to avoid raw pointer arithmetic from Go.
// ------------------------------------------------------------

// Open the first enumerated FIDO2 device. Returns NULL on failure.
// Caller must fido_dev_close/fido_dev_free to clean up.
static fido_dev_t* minerva_fido_open_first(void) {
    fido_dev_info_t* list = fido_dev_info_new(64);
    if (list == NULL) return NULL;
    size_t olen = 0;
    int rc = fido_dev_info_manifest(list, 64, &olen);
    if (rc != FIDO_OK || olen == 0) {
        fido_dev_info_free(&list, 64);
        return NULL;
    }
    const fido_dev_info_t* di = fido_dev_info_ptr(list, 0);
    const char* path = fido_dev_info_path(di);
    fido_dev_t* dev = fido_dev_new();
    if (dev == NULL) {
        fido_dev_info_free(&list, 64);
        return NULL;
    }
    if (fido_dev_open(dev, path) != FIDO_OK) {
        fido_dev_free(&dev);
        fido_dev_info_free(&list, 64);
        return NULL;
    }
    fido_dev_info_free(&list, 64);
    return dev;
}

static void minerva_fido_close(fido_dev_t* dev) {
    if (dev != NULL) {
        fido_dev_close(dev);
        fido_dev_free(&dev);
    }
}
*/
import "C"

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"
)

// NativePasskeyProvider implements PasskeyProvider on Linux via libfido2.
// It targets FIDO2-capable security keys (YubiKey, Solokey, Nitrokey, etc.)
// exposing the hmac-secret extension. Desktop-platform-authenticator passkeys
// on Linux (e.g. GNOME Online Accounts passkeys) are NOT covered — the
// FIDO device path is the lowest common denominator and works across
// distributions without relying on desktop-environment-specific services.
//
// Status: registration + hmac-secret assertion implemented. A PIN prompt
// handler is NOT yet wired — if the authenticator requires a PIN, the
// operation will fail with FIDO_ERR_PIN_REQUIRED. See TODO list in this
// file's top-comment.
//
// TODO (known gaps):
//   - Interactive PIN entry (pinentry / tty prompt) — currently no-PIN only.
//   - User presence / verification callbacks (touch/led prompts are up to
//     the authenticator's own UX).
//   - Device selection when multiple keys are plugged in (we grab index 0).
//   - Gnome Keyring / desktop platform-authenticator fallback.
type NativePasskeyProvider struct {
	// Serialize FIDO device access; libfido2 is not re-entrant per-dev.
	mu sync.Mutex
}

// NewNativePasskeyProvider constructs a Linux passkey provider.
func NewNativePasskeyProvider() *NativePasskeyProvider {
	return &NativePasskeyProvider{}
}

// IsAvailable returns true if any FIDO device is currently enumerable.
// libfido2 init is cheap; we don't cache the result so hot-plugged keys
// are picked up.
func (p *NativePasskeyProvider) IsAvailable() bool {
	// fido_init is idempotent. Called once per process is sufficient but
	// calling it repeatedly is safe.
	C.fido_init(0)
	dev := C.minerva_fido_open_first()
	if dev == nil {
		return false
	}
	C.minerva_fido_close(dev)
	return true
}

// Register creates a new resident FIDO2 credential with hmac-secret enabled
// and performs an immediate assertion to extract the PRF output.
func (p *NativePasskeyProvider) Register(ctx context.Context, rpID string, userHandle []byte, displayName string) (*PasskeyCredential, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.IsAvailable() {
		return nil, nil, ErrPasskeyNotAvailable
	}

	clientDataHash := sha256.Sum256([]byte(fmt.Sprintf(`{"type":"webauthn.create","rp":"%s"}`, rpID)))

	// Build fido_cred_t.
	cred := C.fido_cred_new()
	if cred == nil {
		return nil, nil, errors.New("passkey-linux: fido_cred_new failed")
	}
	defer C.fido_cred_free(&cred)

	if rc := C.fido_cred_set_type(cred, C.COSE_ES256); rc != C.FIDO_OK {
		return nil, nil, fmt.Errorf("passkey-linux: set_type: %s", fidoErrStr(rc))
	}
	if rc := C.fido_cred_set_clientdata_hash(cred, (*C.uchar)(&clientDataHash[0]), 32); rc != C.FIDO_OK {
		return nil, nil, fmt.Errorf("passkey-linux: set_clientdata_hash: %s", fidoErrStr(rc))
	}
	cRPID := C.CString(rpID)
	cRPName := C.CString("Minerva")
	defer C.free(unsafe.Pointer(cRPID))
	defer C.free(unsafe.Pointer(cRPName))
	if rc := C.fido_cred_set_rp(cred, cRPID, cRPName); rc != C.FIDO_OK {
		return nil, nil, fmt.Errorf("passkey-linux: set_rp: %s", fidoErrStr(rc))
	}

	name := displayName
	if name == "" {
		name = "Minerva User"
	}
	cName := C.CString(name)
	cDisplay := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cDisplay))
	if len(userHandle) == 0 {
		return nil, nil, errors.New("passkey-linux: empty userHandle")
	}
	if rc := C.fido_cred_set_user(cred,
		(*C.uchar)(&userHandle[0]), C.size_t(len(userHandle)),
		cName, cDisplay, nil); rc != C.FIDO_OK {
		return nil, nil, fmt.Errorf("passkey-linux: set_user: %s", fidoErrStr(rc))
	}
	if rc := C.fido_cred_set_extensions(cred, C.FIDO_EXT_HMAC_SECRET); rc != C.FIDO_OK {
		return nil, nil, fmt.Errorf("passkey-linux: set_extensions: %s", fidoErrStr(rc))
	}
	if rc := C.fido_cred_set_rk(cred, C.FIDO_OPT_TRUE); rc != C.FIDO_OK {
		return nil, nil, fmt.Errorf("passkey-linux: set_rk: %s", fidoErrStr(rc))
	}
	// User verification is asked for but not required: not every
	// authenticator supports it, so its result code is not checked.
	_ = C.fido_cred_set_uv(cred, C.FIDO_OPT_TRUE)

	dev := C.minerva_fido_open_first()
	if dev == nil {
		return nil, nil, errors.New("passkey-linux: no FIDO device available")
	}
	defer C.minerva_fido_close(dev)

	// Run in a goroutine so ctx can cancel (libfido2 blocks on touch).
	rcCh := make(chan C.int, 1)
	go func() {
		rcCh <- C.fido_dev_make_cred(dev, cred, nil /* PIN */)
	}()
	select {
	case rc := <-rcCh:
		if rc != C.FIDO_OK {
			return nil, nil, fmt.Errorf("passkey-linux: make_cred: %s", fidoErrStr(rc))
		}
	case <-ctx.Done():
		C.fido_dev_cancel(dev)
		return nil, nil, ctx.Err()
	}

	// Extract credential ID.
	idPtr := C.fido_cred_id_ptr(cred)
	idLen := C.fido_cred_id_len(cred)
	credentialID := C.GoBytes(unsafe.Pointer(idPtr), C.int(idLen))
	if len(credentialID) == 0 {
		return nil, nil, errors.New("passkey-linux: empty credential ID")
	}

	// Now run a hmac-secret assertion to extract the PRF output.
	prfKey, err := p.assertAndGetPRF(ctx, credentialID, rpID)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey-linux: post-register PRF eval: %w", err)
	}

	now := time.Now()
	return &PasskeyCredential{
		CredentialID: credentialID,
		RPEntityID:   rpID,
		UserHandle:   userHandle,
		CreatedAt:    now,
		LastUsedAt:   now,
		DisplayName:  displayName,
	}, prfKey, nil
}

// Authenticate runs an hmac-secret assertion and returns the 32-byte PRF key.
func (p *NativePasskeyProvider) Authenticate(ctx context.Context, credentialID []byte, rpID string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.IsAvailable() {
		return nil, ErrPasskeyNotAvailable
	}
	return p.assertAndGetPRF(ctx, credentialID, rpID)
}

func (p *NativePasskeyProvider) assertAndGetPRF(ctx context.Context, credentialID []byte, rpID string) ([]byte, error) {
	salt := nativePRFSalt(rpID)
	if len(salt) != 32 {
		return nil, errors.New("passkey-linux: salt must be 32 bytes")
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("passkey-linux: challenge: %w", err)
	}
	clientDataHash := sha256.Sum256(challenge)

	assn := C.fido_assert_new()
	if assn == nil {
		return nil, errors.New("passkey-linux: fido_assert_new failed")
	}
	defer C.fido_assert_free(&assn)

	cRPID := C.CString(rpID)
	defer C.free(unsafe.Pointer(cRPID))
	if rc := C.fido_assert_set_rp(assn, cRPID); rc != C.FIDO_OK {
		return nil, fmt.Errorf("passkey-linux: assert_set_rp: %s", fidoErrStr(rc))
	}
	if rc := C.fido_assert_set_clientdata_hash(assn, (*C.uchar)(&clientDataHash[0]), 32); rc != C.FIDO_OK {
		return nil, fmt.Errorf("passkey-linux: assert_set_clientdata_hash: %s", fidoErrStr(rc))
	}
	if rc := C.fido_assert_allow_cred(assn, (*C.uchar)(&credentialID[0]), C.size_t(len(credentialID))); rc != C.FIDO_OK {
		return nil, fmt.Errorf("passkey-linux: assert_allow_cred: %s", fidoErrStr(rc))
	}
	if rc := C.fido_assert_set_extensions(assn, C.FIDO_EXT_HMAC_SECRET); rc != C.FIDO_OK {
		return nil, fmt.Errorf("passkey-linux: assert_set_extensions: %s", fidoErrStr(rc))
	}
	if rc := C.fido_assert_set_hmac_salt(assn, (*C.uchar)(&salt[0]), C.size_t(len(salt))); rc != C.FIDO_OK {
		return nil, fmt.Errorf("passkey-linux: assert_set_hmac_salt: %s", fidoErrStr(rc))
	}
	_ = C.fido_assert_set_uv(assn, C.FIDO_OPT_TRUE)

	dev := C.minerva_fido_open_first()
	if dev == nil {
		return nil, errors.New("passkey-linux: no FIDO device available")
	}
	defer C.minerva_fido_close(dev)

	rcCh := make(chan C.int, 1)
	go func() {
		rcCh <- C.fido_dev_get_assert(dev, assn, nil /* PIN */)
	}()
	select {
	case rc := <-rcCh:
		if rc != C.FIDO_OK {
			return nil, fmt.Errorf("passkey-linux: get_assert: %s", fidoErrStr(rc))
		}
	case <-ctx.Done():
		C.fido_dev_cancel(dev)
		return nil, ctx.Err()
	}

	// Extract hmac-secret from statement index 0.
	if C.fido_assert_count(assn) == 0 {
		return nil, errors.New("passkey-linux: assertion returned no statements")
	}
	hsPtr := C.fido_assert_hmac_secret_ptr(assn, 0)
	hsLen := C.fido_assert_hmac_secret_len(assn, 0)
	if hsPtr == nil || hsLen == 0 {
		return nil, errors.New("passkey-linux: authenticator did not return hmac-secret")
	}
	prfKey := C.GoBytes(unsafe.Pointer(hsPtr), C.int(hsLen))
	if len(prfKey) != 32 {
		return nil, fmt.Errorf("passkey-linux: hmac-secret output is %d bytes, expected 32", len(prfKey))
	}
	return prfKey, nil
}

func fidoErrStr(rc C.int) string {
	return C.GoString(C.fido_strerr(rc))
}
