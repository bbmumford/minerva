//go:build windows

package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NativePasskeyProvider implements PasskeyProvider on Windows using the
// Windows Hello WebAuthn API exported from webauthn.dll (ships in Windows
// 10 1903+, PRF/hmac-secret extension supported on Windows 11 22H2+).
//
// Public API mirrors BrowserPasskeyProvider exactly: same method signatures,
// same salt formula, same 32-byte PRF output, so a credential minted in the
// browser can be unlocked here and vice versa.
type NativePasskeyProvider struct {
	dll                   *windows.LazyDLL
	procMakeCredential    *windows.LazyProc
	procGetAssertion      *windows.LazyProc
	procFreeAttestation   *windows.LazyProc
	procFreeAssertion     *windows.LazyProc
	procGetErrorName      *windows.LazyProc
	procIsUserVerifying   *windows.LazyProc
	procGetForegroundHWND *windows.LazyProc
}

// NewNativePasskeyProvider loads webauthn.dll lazily and returns a provider.
// The returned provider's IsAvailable() will be false on systems where
// webauthn.dll is missing (pre-1903 Windows).
func NewNativePasskeyProvider() *NativePasskeyProvider {
	dll := windows.NewLazyDLL("webauthn.dll")
	user32 := windows.NewLazyDLL("user32.dll")
	return &NativePasskeyProvider{
		dll:                   dll,
		procMakeCredential:    dll.NewProc("WebAuthNAuthenticatorMakeCredential"),
		procGetAssertion:      dll.NewProc("WebAuthNAuthenticatorGetAssertion"),
		procFreeAttestation:   dll.NewProc("WebAuthNFreeCredentialAttestation"),
		procFreeAssertion:     dll.NewProc("WebAuthNFreeAssertion"),
		procGetErrorName:      dll.NewProc("WebAuthNGetErrorName"),
		procIsUserVerifying:   dll.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable"),
		procGetForegroundHWND: user32.NewProc("GetForegroundWindow"),
	}
}

// IsAvailable returns true if webauthn.dll is present on this system.
func (p *NativePasskeyProvider) IsAvailable() bool {
	if err := p.dll.Load(); err != nil {
		return false
	}
	if err := p.procMakeCredential.Find(); err != nil {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Win32 WEBAUTHN_* struct definitions (matches webauthn.h).
// Fields ordered exactly per Windows SDK header to be ABI-compatible.
// We use the "current" struct versions (v5/v6). The OS downgrades gracefully
// when an older client runtime is detected.
// ---------------------------------------------------------------------------

const (
	webauthnAPIVersion2 uint32 = 2
	webauthnAPIVersion4 uint32 = 4

	rpEntityInfoCurrent   uint32 = 1
	userEntityInfoCurrent uint32 = 1
	credParamsCurrent     uint32 = 1
	clientDataCurrent     uint32 = 1
	makeCredOptsVersion4  uint32 = 4
	getAssertionVersion6  uint32 = 6
	extensionsCurrent     uint32 = 1

	webauthnUserVerificationRequirementRequired uint32 = 1

	webauthnAuthenticatorAttachmentPlatform uint32 = 1

	webauthnAttestationConveyancePreferenceNone uint32 = 1

	webauthnCredentialTypePublicKey = "public-key"
	webauthnHashAlgorithmSHA256     = "SHA-256"

	coseAlgorithmES256 int32 = -7
	coseAlgorithmEdDSA int32 = -8

	webauthnExtensionIDHmacSecret = "hmac-secret"
	webauthnExtensionIDPRF        = "prf"
)

// WEBAUTHN_RP_ENTITY_INFORMATION
type webauthnRPEntity struct {
	Version uint32
	ID      *uint16
	Name    *uint16
	Icon    *uint16
}

// WEBAUTHN_USER_ENTITY_INFORMATION
type webauthnUserEntity struct {
	Version     uint32
	CbID        uint32
	PbID        *byte
	Name        *uint16
	Icon        *uint16
	DisplayName *uint16
}

// WEBAUTHN_COSE_CREDENTIAL_PARAMETER
type webauthnCoseCredParam struct {
	Version        uint32
	CredentialType *uint16
	Alg            int32
}

// WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
type webauthnCoseCredParams struct {
	CCredentialParameters uint32
	PCredentialParameters *webauthnCoseCredParam
}

// WEBAUTHN_CLIENT_DATA
type webauthnClientData struct {
	Version          uint32
	CbClientDataJSON uint32
	PbClientDataJSON *byte
	PwszHashAlgID    *uint16
}

// WEBAUTHN_CREDENTIAL_EX
type webauthnCredentialEx struct {
	Version            uint32
	CbID               uint32
	PbID               *byte
	PwszCredentialType *uint16
	DwTransports       uint32
}

// WEBAUTHN_CREDENTIAL_LIST
type webauthnCredentialList struct {
	CCredentials  uint32
	PpCredentials **webauthnCredentialEx
}

// WEBAUTHN_HMAC_SECRET_SALT
type webauthnHmacSecretSalt struct {
	CbFirst  uint32
	PbFirst  *byte
	CbSecond uint32
	PbSecond *byte
}

// WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT
type webauthnCredWithHmacSecretSalt struct {
	CbCredID        uint32
	PbCredID        *byte
	PHmacSecretSalt *webauthnHmacSecretSalt
}

// WEBAUTHN_HMAC_SECRET_SALT_VALUES
type webauthnHmacSecretSaltValues struct {
	PGlobalHmacSalt             *webauthnHmacSecretSalt
	CCredWithHmacSecretSaltList uint32
	PCredWithHmacSecretSaltList *webauthnCredWithHmacSecretSalt
}

// WEBAUTHN_EXTENSION
type webauthnExtension struct {
	PwszExtensionIdentifier *uint16
	CbExtension             uint32
	PvExtension             unsafe.Pointer
}

// WEBAUTHN_EXTENSIONS
type webauthnExtensions struct {
	CExtensions uint32
	PExtensions *webauthnExtension
}

// WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS (v4)
type webauthnMakeCredOpts struct {
	Version                           uint32
	DwTimeoutMilliseconds             uint32
	CredentialList                    webauthnCredentialList // excluded credentials
	Extensions                        webauthnExtensions
	DwAuthenticatorAttachment         uint32
	BRequireResidentKey               uint32
	DwUserVerificationRequirement     uint32
	DwAttestationConveyancePreference uint32
	DwFlags                           uint32
	PCancellationID                   *windows.GUID
	PExcludeCredentialList            *webauthnCredentialList
	DwEnterpriseAttestation           uint32
	DwLargeBlobSupport                uint32
	BPreferResidentKey                uint32
	BBrowserInPrivateMode             uint32
	BEnablePRF                        uint32
	PLinkedDevice                     unsafe.Pointer
	CbJsonExt                         uint32
	PbJsonExt                         *byte
}

// WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS (v6)
type webauthnGetAssertionOpts struct {
	Version                       uint32
	DwTimeoutMilliseconds         uint32
	CredentialList                webauthnCredentialList
	Extensions                    webauthnExtensions
	DwAuthenticatorAttachment     uint32
	DwUserVerificationRequirement uint32
	DwFlags                       uint32
	PwszU2fAppID                  *uint16
	PbU2fAppID                    *uint32
	PCancellationID               *windows.GUID
	PAllowCredentialList          *webauthnCredentialList
	DwCredLargeBlobOperation      uint32
	CbCredLargeBlob               uint32
	PbCredLargeBlob               *byte
	PHmacSecretSaltValues         *webauthnHmacSecretSaltValues
	BBrowserInPrivateMode         uint32
	PLinkedDevice                 unsafe.Pointer
	BAutoFill                     uint32
	CbJsonExt                     uint32
	PbJsonExt                     *byte
}

// WEBAUTHN_CREDENTIAL_ATTESTATION (returned). We only need credentialID here.
type webauthnCredentialAttestation struct {
	Version                 uint32
	PwszFormatType          *uint16
	CbAuthenticatorData     uint32
	PbAuthenticatorData     *byte
	CbAttestation           uint32
	PbAttestation           *byte
	DwAttestationDecodeType uint32
	PvAttestationDecode     unsafe.Pointer
	CbAttestationObject     uint32
	PbAttestationObject     *byte
	CbCredentialID          uint32
	PbCredentialID          *byte
	Extensions              webauthnExtensions
	DwUsedTransport         uint32
	BEpAtt                  uint32
	BLargeBlobSupported     uint32
	BResidentKey            uint32
	BPRFEnabled             uint32
	// (remainder of struct elided — we never read past this point).
}

// WEBAUTHN_ASSERTION (returned)
type webauthnAssertion struct {
	Version               uint32
	CbAuthenticatorData   uint32
	PbAuthenticatorData   *byte
	CbSignature           uint32
	PbSignature           *byte
	Credential            webauthnCredentialEx
	CbUserID              uint32
	PbUserID              *byte
	Extensions            webauthnExtensions
	CbCredLargeBlob       uint32
	PbCredLargeBlob       *byte
	DwCredLargeBlobStatus uint32
	PHmacSecret           *webauthnHmacSecretSalt
	// remainder elided
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func utf16Ptr(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

func bytesPtr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}

func copyCBytes(ptr *byte, size uint32) []byte {
	if ptr == nil || size == 0 {
		return nil
	}
	out := make([]byte, size)
	src := unsafe.Slice(ptr, size)
	copy(out, src)
	return out
}

// winHWND returns a HWND to anchor the Windows Hello UI to. The WebAuthn API
// requires a foreground-window handle; using the current foreground window
// lets the dialog appear attached to the Wails app.
func (p *NativePasskeyProvider) winHWND() uintptr {
	hwnd, _, _ := p.procGetForegroundHWND.Call()
	return hwnd
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

// Register creates a new platform passkey with hmac-secret (PRF) enabled,
// returning the credential and the 32-byte PRF-derived key.
//
// Windows Hello on 22H2+ surfaces the PRF extension via hmac-secret. The
// *first* evaluation is done automatically at make-credential time when
// BEnablePRF is set; however, for API symmetry with the browser we perform
// the evaluation explicitly during the subsequent GetAssertion call (Windows
// does NOT return hmac-secret output from MakeCredential — only from
// GetAssertion). We therefore register, then do an immediate silent
// assertion to extract the PRF output before handing the credential back.
func (p *NativePasskeyProvider) Register(ctx context.Context, rpID string, userHandle []byte, displayName string) (*PasskeyCredential, []byte, error) {
	if !p.IsAvailable() {
		return nil, nil, ErrPasskeyNotAvailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// --- Build RP/user/cred-params ---
	rp := webauthnRPEntity{
		Version: rpEntityInfoCurrent,
		ID:      utf16Ptr(rpID),
		Name:    utf16Ptr("Minerva"),
	}

	nameUTF := displayName
	if nameUTF == "" {
		nameUTF = "Minerva User"
	}
	user := webauthnUserEntity{
		Version:     userEntityInfoCurrent,
		CbID:        uint32(len(userHandle)),
		PbID:        bytesPtr(userHandle),
		Name:        utf16Ptr(nameUTF),
		DisplayName: utf16Ptr(nameUTF),
	}

	credTypeStr := utf16Ptr(webauthnCredentialTypePublicKey)
	credParamArr := []webauthnCoseCredParam{
		{Version: credParamsCurrent, CredentialType: credTypeStr, Alg: coseAlgorithmES256},
		{Version: credParamsCurrent, CredentialType: credTypeStr, Alg: coseAlgorithmEdDSA},
	}
	credParams := webauthnCoseCredParams{
		CCredentialParameters: uint32(len(credParamArr)),
		PCredentialParameters: &credParamArr[0],
	}

	// Challenge (not verified — local passkey).
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, nil, fmt.Errorf("passkey-win: challenge: %w", err)
	}
	// Minimal clientDataJSON-like blob: webauthn.dll hashes this with SHA-256.
	clientDataJSON := []byte(fmt.Sprintf(`{"type":"webauthn.create","challenge":"%x","origin":"https://%s"}`, challenge, rpID))
	cd := webauthnClientData{
		Version:          clientDataCurrent,
		CbClientDataJSON: uint32(len(clientDataJSON)),
		PbClientDataJSON: bytesPtr(clientDataJSON),
		PwszHashAlgID:    utf16Ptr(webauthnHashAlgorithmSHA256),
	}

	// hmac-secret extension enable. Value is a BOOL (uint32).
	hmacTrue := uint32(1)
	ext := webauthnExtension{
		PwszExtensionIdentifier: utf16Ptr(webauthnExtensionIDHmacSecret),
		CbExtension:             uint32(unsafe.Sizeof(hmacTrue)),
		PvExtension:             unsafe.Pointer(&hmacTrue),
	}
	extArr := []webauthnExtension{ext}

	opts := webauthnMakeCredOpts{
		Version:                           makeCredOptsVersion4,
		DwTimeoutMilliseconds:             60000,
		Extensions:                        webauthnExtensions{CExtensions: 1, PExtensions: &extArr[0]},
		DwAuthenticatorAttachment:         webauthnAuthenticatorAttachmentPlatform,
		BRequireResidentKey:               1,
		DwUserVerificationRequirement:     webauthnUserVerificationRequirementRequired,
		DwAttestationConveyancePreference: webauthnAttestationConveyancePreferenceNone,
		BPreferResidentKey:                1,
		BEnablePRF:                        1,
	}

	var attestationPtr *webauthnCredentialAttestation
	ret, _, _ := p.procMakeCredential.Call(
		p.winHWND(),
		uintptr(unsafe.Pointer(&rp)),
		uintptr(unsafe.Pointer(&user)),
		uintptr(unsafe.Pointer(&credParams)),
		uintptr(unsafe.Pointer(&cd)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&attestationPtr)),
	)
	if ret != 0 {
		return nil, nil, fmt.Errorf("passkey-win: MakeCredential hr=0x%x (%s)", ret, p.errorName(ret))
	}
	if attestationPtr == nil {
		return nil, nil, errors.New("passkey-win: MakeCredential returned null attestation")
	}
	defer p.procFreeAttestation.Call(uintptr(unsafe.Pointer(attestationPtr)))

	credID := copyCBytes(attestationPtr.PbCredentialID, attestationPtr.CbCredentialID)
	if len(credID) == 0 {
		return nil, nil, errors.New("passkey-win: empty credential ID returned")
	}
	if attestationPtr.BPRFEnabled == 0 {
		return nil, nil, errors.New("passkey-win: authenticator did not enable PRF (need Windows 11 22H2+ and a PRF-capable authenticator)")
	}

	// Now run a silent assertion to extract the PRF output for the salt we care about.
	prfKey, err := p.assertAndGetPRF(ctx, credID, rpID)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey-win: post-register PRF eval: %w", err)
	}

	now := time.Now()
	return &PasskeyCredential{
		CredentialID: credID,
		RPEntityID:   rpID,
		UserHandle:   userHandle,
		CreatedAt:    now,
		LastUsedAt:   now,
		DisplayName:  displayName,
	}, prfKey, nil
}

// Authenticate evaluates the hmac-secret PRF for the registered credential
// and returns the 32-byte derived key.
func (p *NativePasskeyProvider) Authenticate(ctx context.Context, credentialID []byte, rpID string) ([]byte, error) {
	if !p.IsAvailable() {
		return nil, ErrPasskeyNotAvailable
	}
	return p.assertAndGetPRF(ctx, credentialID, rpID)
}

func (p *NativePasskeyProvider) assertAndGetPRF(_ context.Context, credentialID []byte, rpID string) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	salt := nativePRFSalt(rpID)
	if len(salt) != 32 {
		return nil, errors.New("passkey-win: salt must be 32 bytes")
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("passkey-win: challenge: %w", err)
	}
	clientDataJSON := []byte(fmt.Sprintf(`{"type":"webauthn.get","challenge":"%x","origin":"https://%s"}`, challenge, rpID))
	cd := webauthnClientData{
		Version:          clientDataCurrent,
		CbClientDataJSON: uint32(len(clientDataJSON)),
		PbClientDataJSON: bytesPtr(clientDataJSON),
		PwszHashAlgID:    utf16Ptr(webauthnHashAlgorithmSHA256),
	}

	// Allow-list containing our credentialID.
	credEx := webauthnCredentialEx{
		Version:            credParamsCurrent,
		CbID:               uint32(len(credentialID)),
		PbID:               bytesPtr(credentialID),
		PwszCredentialType: utf16Ptr(webauthnCredentialTypePublicKey),
	}
	credExPtr := &credEx
	credList := webauthnCredentialList{
		CCredentials:  1,
		PpCredentials: &credExPtr,
	}

	// Global hmac-secret salt values (applies to all credentials in allow-list).
	saltBuf := make([]byte, 32)
	copy(saltBuf, salt)
	hmacSalt := webauthnHmacSecretSalt{
		CbFirst: 32,
		PbFirst: &saltBuf[0],
	}
	hmacValues := webauthnHmacSecretSaltValues{
		PGlobalHmacSalt: &hmacSalt,
	}

	opts := webauthnGetAssertionOpts{
		Version:                       getAssertionVersion6,
		DwTimeoutMilliseconds:         60000,
		CredentialList:                credList,
		DwAuthenticatorAttachment:     webauthnAuthenticatorAttachmentPlatform,
		DwUserVerificationRequirement: webauthnUserVerificationRequirementRequired,
		PHmacSecretSaltValues:         &hmacValues,
	}

	rpIDw := utf16Ptr(rpID)

	var assertionPtr *webauthnAssertion
	ret, _, _ := p.procGetAssertion.Call(
		p.winHWND(),
		uintptr(unsafe.Pointer(rpIDw)),
		uintptr(unsafe.Pointer(&cd)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&assertionPtr)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("passkey-win: GetAssertion hr=0x%x (%s)", ret, p.errorName(ret))
	}
	if assertionPtr == nil {
		return nil, errors.New("passkey-win: GetAssertion returned null")
	}
	defer p.procFreeAssertion.Call(uintptr(unsafe.Pointer(assertionPtr)))

	if assertionPtr.PHmacSecret == nil {
		return nil, errors.New("passkey-win: authenticator did not return hmac-secret output")
	}
	prfKey := copyCBytes(assertionPtr.PHmacSecret.PbFirst, assertionPtr.PHmacSecret.CbFirst)
	if len(prfKey) != 32 {
		return nil, fmt.Errorf("passkey-win: PRF output is %d bytes, expected 32", len(prfKey))
	}
	return prfKey, nil
}

// errorName translates an HRESULT to a short hex string. We intentionally
// do NOT call WebAuthNGetErrorName because translating the returned LPCWSTR
// back into Go string form requires a uintptr→pointer cast that `go vet`
// (correctly) warns about. Hex code + MSDN lookup is sufficient for debug.
func (p *NativePasskeyProvider) errorName(hr uintptr) string {
	return fmt.Sprintf("hr=0x%x", hr)
}
