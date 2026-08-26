//go:build !js && !windows && !(darwin && cgo) && !(linux && cgo)

package identity

import "context"

// NativePasskeyProvider is the fallback stub for platforms that don't have
// a native passkey implementation (BSD, Solaris, Plan9, etc).
//
// On supported platforms — darwin, windows, linux — the type with the same
// name is provided by passkey_macos.go / passkey_windows.go / passkey_linux.go
// and is fully functional. This file is only compiled when none of those
// platform tags match.
type NativePasskeyProvider struct{}

// NewNativePasskeyProvider creates a stub native passkey provider.
func NewNativePasskeyProvider() *NativePasskeyProvider {
	return &NativePasskeyProvider{}
}

// IsAvailable returns false — native passkey support is not implemented
// for this platform.
func (p *NativePasskeyProvider) IsAvailable() bool {
	return false
}

// Register returns ErrPasskeyNotAvailable.
func (p *NativePasskeyProvider) Register(_ context.Context, _ string, _ []byte, _ string) (*PasskeyCredential, []byte, error) {
	return nil, nil, ErrPasskeyNotAvailable
}

// Authenticate returns ErrPasskeyNotAvailable.
func (p *NativePasskeyProvider) Authenticate(_ context.Context, _ []byte, _ string) ([]byte, error) {
	return nil, ErrPasskeyNotAvailable
}
