//go:build js && wasm

package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"syscall/js"
	"time"
)

// BrowserPasskeyProvider implements PasskeyProvider using the Web Authentication API
// with the PRF extension for deterministic key derivation.
type BrowserPasskeyProvider struct{}

// NewBrowserPasskeyProvider creates a new browser-based passkey provider.
func NewBrowserPasskeyProvider() *BrowserPasskeyProvider {
	return &BrowserPasskeyProvider{}
}

// IsAvailable returns true if the browser supports WebAuthn with passkeys.
func (p *BrowserPasskeyProvider) IsAvailable() bool {
	nav := js.Global().Get("navigator")
	if nav.IsUndefined() || nav.IsNull() {
		return false
	}
	creds := nav.Get("credentials")
	if creds.IsUndefined() || creds.IsNull() {
		return false
	}
	pkc := js.Global().Get("PublicKeyCredential")
	return !pkc.IsUndefined() && !pkc.IsNull()
}

// prfSalt returns a deterministic salt for the PRF extension.
// The salt is derived from the RP ID to ensure the same passkey always
// produces the same encryption key for a given application.
func prfSalt(rpID string) []byte {
	h := sha256.Sum256([]byte("minerva-prf-salt:" + rpID))
	return h[:]
}

// Register creates a new passkey credential with the authenticator using
// navigator.credentials.create() with the PRF extension.
func (p *BrowserPasskeyProvider) Register(ctx context.Context, rpID string, userHandle []byte, displayName string) (*PasskeyCredential, []byte, error) {
	if !p.IsAvailable() {
		return nil, nil, ErrPasskeyNotAvailable
	}

	salt := prfSalt(rpID)

	// Build the PRF salt as a JS Uint8Array.
	jsSalt := jsNewUint8Array(salt)

	// Build PublicKeyCredentialCreationOptions.
	rpObj := jsObject(map[string]interface{}{
		"name": "Minerva",
		"id":   rpID,
	})

	userObj := jsObject(map[string]interface{}{
		"name":        displayName,
		"displayName": displayName,
		"id":          jsNewUint8Array(userHandle),
	})

	// ES256 (-7) and EdDSA (-8) as preferred algorithms.
	pubKeyCredParams := js.Global().Get("Array").New()
	pubKeyCredParams.Call("push", jsObject(map[string]interface{}{
		"type": "public-key",
		"alg":  -7,
	}))
	pubKeyCredParams.Call("push", jsObject(map[string]interface{}{
		"type": "public-key",
		"alg":  -8,
	}))

	authenticatorSelection := jsObject(map[string]interface{}{
		"authenticatorAttachment": "platform",
		"residentKey":             "required",
		"userVerification":        "required",
	})

	// Challenge is random — we don't verify attestation (local-only passkey).
	challenge := make([]byte, 32)
	if _, err := readRandom(challenge); err != nil {
		return nil, nil, fmt.Errorf("generate challenge: %w", err)
	}

	extensions := jsObject(map[string]interface{}{
		"prf": jsObject(map[string]interface{}{
			"eval": jsObject(map[string]interface{}{
				"first": jsSalt,
			}),
		}),
	})

	publicKey := jsObject(map[string]interface{}{
		"rp":                     rpObj,
		"user":                   userObj,
		"challenge":              jsNewUint8Array(challenge),
		"pubKeyCredParams":       pubKeyCredParams,
		"timeout":                60000,
		"attestation":            "none",
		"authenticatorSelection": authenticatorSelection,
		"extensions":             extensions,
	})

	opts := jsObject(map[string]interface{}{
		"publicKey": publicKey,
	})

	// Call navigator.credentials.create() and await the Promise.
	type createResult struct {
		cred   *PasskeyCredential
		prfKey []byte
		err    error
	}
	done := make(chan createResult, 1)

	promise := js.Global().Get("navigator").Get("credentials").Call("create", opts)

	var thenCb, catchCb js.Func
	thenCb = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer thenCb.Release()
		defer catchCb.Release()

		credential := args[0]

		// Extract credential ID.
		rawID := credential.Get("rawId")
		credentialID := jsCopyBytes(rawID)

		// Extract PRF result.
		extResults := credential.Call("getClientExtensionResults")
		prfResult := extResults.Get("prf")
		if prfResult.IsUndefined() || prfResult.IsNull() {
			done <- createResult{err: errors.New("identity: PRF extension not supported by authenticator")}
			return nil
		}

		prfResults := prfResult.Get("results")
		if prfResults.IsUndefined() || prfResults.IsNull() {
			done <- createResult{err: errors.New("identity: PRF results not available")}
			return nil
		}

		prfFirst := prfResults.Get("first")
		if prfFirst.IsUndefined() || prfFirst.IsNull() {
			done <- createResult{err: errors.New("identity: PRF first result not available")}
			return nil
		}

		// PRF output is an ArrayBuffer — wrap in Uint8Array to copy.
		prfArray := js.Global().Get("Uint8Array").New(prfFirst)
		prfKey := jsCopyBytes(prfArray)

		if len(prfKey) != 32 {
			done <- createResult{err: fmt.Errorf("identity: PRF output is %d bytes, expected 32", len(prfKey))}
			return nil
		}

		now := time.Now()
		cred := &PasskeyCredential{
			CredentialID: credentialID,
			RPEntityID:   rpID,
			UserHandle:   userHandle,
			CreatedAt:    now,
			LastUsedAt:   now,
			DisplayName:  displayName,
		}

		done <- createResult{cred: cred, prfKey: prfKey}
		return nil
	})

	catchCb = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer thenCb.Release()
		defer catchCb.Release()

		errMsg := "unknown error"
		if len(args) > 0 {
			errVal := args[0]
			if msg := errVal.Get("message"); !msg.IsUndefined() {
				errMsg = msg.String()
			} else {
				errMsg = errVal.String()
			}
		}
		done <- createResult{err: fmt.Errorf("identity: passkey create failed: %s", errMsg)}
		return nil
	})

	promise.Call("then", thenCb).Call("catch", catchCb)

	// Wait for result or context cancellation.
	select {
	case res := <-done:
		return res.cred, res.prfKey, res.err
	case <-ctx.Done():
		thenCb.Release()
		catchCb.Release()
		return nil, nil, ctx.Err()
	}
}

// Authenticate uses an existing credential to derive the encryption key via
// navigator.credentials.get() with the PRF extension.
// The rpID parameter must match the RP ID used during registration to ensure
// consistent PRF salt derivation.
func (p *BrowserPasskeyProvider) Authenticate(ctx context.Context, credentialID []byte, rpID string) ([]byte, error) {
	if !p.IsAvailable() {
		return nil, ErrPasskeyNotAvailable
	}

	salt := prfSalt(rpID)
	jsSalt := jsNewUint8Array(salt)

	// Build allowCredentials with the specific credential ID.
	allowCred := jsObject(map[string]interface{}{
		"type": "public-key",
		"id":   jsNewUint8Array(credentialID),
	})
	allowCredentials := js.Global().Get("Array").New()
	allowCredentials.Call("push", allowCred)

	// Challenge is random — we only care about the PRF output.
	challenge := make([]byte, 32)
	if _, err := readRandom(challenge); err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}

	extensions := jsObject(map[string]interface{}{
		"prf": jsObject(map[string]interface{}{
			"eval": jsObject(map[string]interface{}{
				"first": jsSalt,
			}),
		}),
	})

	publicKey := jsObject(map[string]interface{}{
		"challenge":        jsNewUint8Array(challenge),
		"rpId":             rpID,
		"allowCredentials": allowCredentials,
		"userVerification": "required",
		"timeout":          60000,
		"extensions":       extensions,
	})

	opts := jsObject(map[string]interface{}{
		"publicKey": publicKey,
	})

	type authResult struct {
		prfKey []byte
		err    error
	}
	done := make(chan authResult, 1)

	promise := js.Global().Get("navigator").Get("credentials").Call("get", opts)

	var thenCb, catchCb js.Func
	thenCb = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer thenCb.Release()
		defer catchCb.Release()

		credential := args[0]

		// Extract PRF result.
		extResults := credential.Call("getClientExtensionResults")
		prfResult := extResults.Get("prf")
		if prfResult.IsUndefined() || prfResult.IsNull() {
			done <- authResult{err: errors.New("identity: PRF extension not in authentication response")}
			return nil
		}

		prfResults := prfResult.Get("results")
		if prfResults.IsUndefined() || prfResults.IsNull() {
			done <- authResult{err: errors.New("identity: PRF results not available")}
			return nil
		}

		prfFirst := prfResults.Get("first")
		if prfFirst.IsUndefined() || prfFirst.IsNull() {
			done <- authResult{err: errors.New("identity: PRF first result not available")}
			return nil
		}

		prfArray := js.Global().Get("Uint8Array").New(prfFirst)
		prfKey := jsCopyBytes(prfArray)

		if len(prfKey) != 32 {
			done <- authResult{err: fmt.Errorf("identity: PRF output is %d bytes, expected 32", len(prfKey))}
			return nil
		}

		done <- authResult{prfKey: prfKey}
		return nil
	})

	catchCb = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer thenCb.Release()
		defer catchCb.Release()

		errMsg := "unknown error"
		if len(args) > 0 {
			errVal := args[0]
			if msg := errVal.Get("message"); !msg.IsUndefined() {
				errMsg = msg.String()
			} else {
				errMsg = errVal.String()
			}
		}
		done <- authResult{err: fmt.Errorf("identity: passkey authenticate failed: %s", errMsg)}
		return nil
	})

	promise.Call("then", thenCb).Call("catch", catchCb)

	select {
	case res := <-done:
		return res.prfKey, res.err
	case <-ctx.Done():
		thenCb.Release()
		catchCb.Release()
		return nil, ctx.Err()
	}
}

// --- JS helpers ---------------------------------------------------------------

// jsObject creates a JS object from a Go map.
func jsObject(m map[string]interface{}) js.Value {
	obj := js.Global().Get("Object").New()
	for k, v := range m {
		obj.Set(k, v)
	}
	return obj
}

// jsNewUint8Array creates a new JS Uint8Array from a Go byte slice.
func jsNewUint8Array(data []byte) js.Value {
	arr := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(arr, data)
	return arr
}

// jsCopyBytes copies a JS Uint8Array/ArrayBuffer into a Go byte slice.
func jsCopyBytes(v js.Value) []byte {
	length := v.Get("length").Int()
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, v)
	return buf
}

// readRandom fills buf with cryptographically secure random bytes.
// In WASM, crypto/rand uses crypto.getRandomValues internally.
func readRandom(buf []byte) (int, error) {
	return rand.Read(buf)
}
