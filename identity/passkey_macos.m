// passkey_macos.m — Objective-C bridge to AuthenticationServices for the
// Minerva PasskeyProvider.
//
// Build tag is enforced via the matching passkey_macos.go file.

//go:build darwin && !js

#import <Foundation/Foundation.h>
#import <AuthenticationServices/AuthenticationServices.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void set_c_error(char** out_err, NSString* msg) {
    if (out_err == NULL || msg == nil) return;
    const char* src = [msg UTF8String];
    size_t n = strlen(src) + 1;
    char* buf = (char*)malloc(n);
    memcpy(buf, src, n);
    *out_err = buf;
}

static void copy_nsdata(NSData* data, uint8_t** out, int* out_len) {
    if (data == nil) {
        *out = NULL;
        *out_len = 0;
        return;
    }
    NSUInteger len = [data length];
    uint8_t* buf = (uint8_t*)malloc(len);
    memcpy(buf, [data bytes], len);
    *out = buf;
    *out_len = (int)len;
}

// ---------------------------------------------------------------------------
// Delegate that waits synchronously for an ASAuthorizationController result.
//
// The .m file deliberately blocks the calling thread on a dispatch semaphore.
// The Go side invokes this from a goroutine with its own context-based
// timeout, so blocking here is safe.
// ---------------------------------------------------------------------------

API_AVAILABLE(macos(12.0))
@interface MinervaPasskeyDelegate : NSObject <ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding>
@property (nonatomic, strong) id authorization;      // ASAuthorization result
@property (nonatomic, strong) NSError* lastError;
@property (nonatomic) dispatch_semaphore_t sem;
@end

@implementation MinervaPasskeyDelegate

- (instancetype)init {
    if ((self = [super init])) {
        _sem = dispatch_semaphore_create(0);
    }
    return self;
}

- (void)authorizationController:(ASAuthorizationController *)controller
   didCompleteWithAuthorization:(ASAuthorization *)authorization {
    self.authorization = authorization;
    dispatch_semaphore_signal(self.sem);
}

- (void)authorizationController:(ASAuthorizationController *)controller
           didCompleteWithError:(NSError *)error {
    self.lastError = error;
    dispatch_semaphore_signal(self.sem);
}

- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController *)controller
    API_AVAILABLE(macos(10.15)) {
    // Return a key window if we have one. For Wails/command-line binaries
    // that have no NSApplication windows, passing nil is accepted by the
    // system on macOS 14+.
    NSArray* windows = [NSApp windows];
    for (NSWindow* w in windows) {
        if ([w isKeyWindow]) return w;
    }
    if ([windows count] > 0) return [windows firstObject];
    return nil;
}

@end

// ---------------------------------------------------------------------------
// Public C API
// ---------------------------------------------------------------------------

int minerva_passkey_available(void) {
    if (@available(macOS 12.0, *)) {
        return 1;
    }
    return 0;
}

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
) {
    if (@available(macOS 14.0, *)) {
        @autoreleasepool {
            NSString* nsRPID = [NSString stringWithUTF8String:rp_id];
            NSString* nsUserName = [NSString stringWithUTF8String:(user_name ? user_name : "Minerva User")];
            NSData*   nsUserHandle = [NSData dataWithBytes:user_handle length:user_handle_len];
            NSData*   nsChallenge  = [NSData dataWithBytes:challenge length:challenge_len];

            ASAuthorizationPlatformPublicKeyCredentialProvider* provider =
                [[ASAuthorizationPlatformPublicKeyCredentialProvider alloc] initWithRelyingPartyIdentifier:nsRPID];

            ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest* req =
                [provider createCredentialRegistrationRequestWithChallenge:nsChallenge
                                                                      name:nsUserName
                                                                    userID:nsUserHandle];
            req.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreferenceRequired;

            // PRF extension. Apple exposes PRF via
            // ASAuthorizationPublicKeyCredentialPRFRegistrationInput on macOS 14+.
            if (@available(macOS 14.0, *)) {
                NSData* saltData = [NSData dataWithBytes:prf_salt length:prf_salt_len];
                Class prfRegClass = NSClassFromString(@"ASAuthorizationPublicKeyCredentialPRFRegistrationInput");
                if (prfRegClass != nil) {
                    SEL selCheckInputs = NSSelectorFromString(@"checkForSupport");
                    // Apple's header declares `+checkForSupport` and
                    // `+inputValuesWithSaltInput1:saltInput2:`. We bind dynamically to
                    // stay compatible across minor SDK versions that shuffle names.
                    SEL selInputs = NSSelectorFromString(@"inputValuesWithSaltInput1:saltInput2:");
                    id prfInput = nil;
                    if ([prfRegClass respondsToSelector:selInputs]) {
                        NSMethodSignature* sig = [prfRegClass methodSignatureForSelector:selInputs];
                        NSInvocation* inv = [NSInvocation invocationWithMethodSignature:sig];
                        [inv setTarget:prfRegClass];
                        [inv setSelector:selInputs];
                        NSData* s1 = saltData;
                        NSData* s2 = nil;
                        [inv setArgument:&s1 atIndex:2];
                        [inv setArgument:&s2 atIndex:3];
                        [inv invoke];
                        __unsafe_unretained id ret = nil;
                        [inv getReturnValue:&ret];
                        prfInput = ret;
                    }
                    if (prfInput != nil) {
                        // Instantiate PRFRegistrationInput wrapper.
                        id prfReg = [[prfRegClass alloc] init];
                        SEL setShouldCheck = NSSelectorFromString(@"setShouldCheckForSupport:");
                        if ([prfReg respondsToSelector:setShouldCheck]) {
                            BOOL yes = YES;
                            NSMethodSignature* sig2 = [prfReg methodSignatureForSelector:setShouldCheck];
                            NSInvocation* inv2 = [NSInvocation invocationWithMethodSignature:sig2];
                            [inv2 setTarget:prfReg];
                            [inv2 setSelector:setShouldCheck];
                            [inv2 setArgument:&yes atIndex:2];
                            [inv2 invoke];
                        }
                        SEL setInputValues = NSSelectorFromString(@"setInputValues:");
                        if ([prfReg respondsToSelector:setInputValues]) {
                            NSMethodSignature* sig3 = [prfReg methodSignatureForSelector:setInputValues];
                            NSInvocation* inv3 = [NSInvocation invocationWithMethodSignature:sig3];
                            [inv3 setTarget:prfReg];
                            [inv3 setSelector:setInputValues];
                            [inv3 setArgument:&prfInput atIndex:2];
                            [inv3 invoke];
                        }
                        SEL reqSetPRF = NSSelectorFromString(@"setPrf:");
                        if ([req respondsToSelector:reqSetPRF]) {
                            NSMethodSignature* sig4 = [req methodSignatureForSelector:reqSetPRF];
                            NSInvocation* inv4 = [NSInvocation invocationWithMethodSignature:sig4];
                            [inv4 setTarget:req];
                            [inv4 setSelector:reqSetPRF];
                            [inv4 setArgument:&prfReg atIndex:2];
                            [inv4 invoke];
                        }
                    }
                    (void)selCheckInputs;
                }
            }

            MinervaPasskeyDelegate* del = [[MinervaPasskeyDelegate alloc] init];
            ASAuthorizationController* ctl =
                [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[req]];
            ctl.delegate = del;
            ctl.presentationContextProvider = del;

            dispatch_async(dispatch_get_main_queue(), ^{
                [ctl performRequests];
            });

            dispatch_semaphore_wait(del.sem, DISPATCH_TIME_FOREVER);

            if (del.lastError != nil) {
                set_c_error(out_err, [del.lastError localizedDescription]);
                return 1;
            }
            ASAuthorization* auth = del.authorization;
            id credObj = auth.credential;
            if (![credObj isKindOfClass:[ASAuthorizationPlatformPublicKeyCredentialRegistration class]]) {
                set_c_error(out_err, @"unexpected credential type from ASAuthorization");
                return 2;
            }
            ASAuthorizationPlatformPublicKeyCredentialRegistration* reg =
                (ASAuthorizationPlatformPublicKeyCredentialRegistration*)credObj;
            copy_nsdata(reg.credentialID, out_credential_id, out_credential_id_len);

            // Pull PRF output off the registration (macOS 14+).
            NSData* prfOut = nil;
            SEL selPrf = NSSelectorFromString(@"prf");
            if ([reg respondsToSelector:selPrf]) {
                id prfObj = [reg valueForKey:@"prf"];
                if (prfObj != nil) {
                    id first = [prfObj valueForKey:@"first"];
                    if ([first isKindOfClass:[NSData class]]) {
                        prfOut = (NSData*)first;
                    }
                }
            }
            if (prfOut == nil) {
                set_c_error(out_err, @"PRF output unavailable (macOS 14+ and PRF-capable authenticator required)");
                return 3;
            }
            copy_nsdata(prfOut, out_prf_output, out_prf_output_len);
            return 0;
        }
    }
    set_c_error(out_err, @"macOS 14.0+ required for passkey PRF");
    return 10;
}

int minerva_passkey_assert(
    const char* rp_id,
    const uint8_t* credential_id, int credential_id_len,
    const uint8_t* challenge, int challenge_len,
    const uint8_t* prf_salt, int prf_salt_len,
    uint8_t** out_prf_output, int* out_prf_output_len,
    char**    out_err
) {
    if (@available(macOS 14.0, *)) {
        @autoreleasepool {
            NSString* nsRPID = [NSString stringWithUTF8String:rp_id];
            NSData*   nsChallenge = [NSData dataWithBytes:challenge length:challenge_len];
            NSData*   nsCredID    = [NSData dataWithBytes:credential_id length:credential_id_len];

            ASAuthorizationPlatformPublicKeyCredentialProvider* provider =
                [[ASAuthorizationPlatformPublicKeyCredentialProvider alloc] initWithRelyingPartyIdentifier:nsRPID];
            ASAuthorizationPlatformPublicKeyCredentialAssertionRequest* req =
                [provider createCredentialAssertionRequestWithChallenge:nsChallenge];
            req.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreferenceRequired;
            req.allowedCredentials = @[[[ASAuthorizationPlatformPublicKeyCredentialDescriptor alloc]
                                           initWithCredentialID:nsCredID]];

            // Attach PRF assertion input.
            Class prfAssertClass = NSClassFromString(@"ASAuthorizationPublicKeyCredentialPRFAssertionInput");
            if (prfAssertClass != nil) {
                NSData* saltData = [NSData dataWithBytes:prf_salt length:prf_salt_len];
                SEL selInputs = NSSelectorFromString(@"inputValuesWithSaltInput1:saltInput2:");
                id prfInput = nil;
                if ([prfAssertClass respondsToSelector:selInputs]) {
                    NSMethodSignature* sig = [prfAssertClass methodSignatureForSelector:selInputs];
                    NSInvocation* inv = [NSInvocation invocationWithMethodSignature:sig];
                    [inv setTarget:prfAssertClass];
                    [inv setSelector:selInputs];
                    NSData* s1 = saltData;
                    NSData* s2 = nil;
                    [inv setArgument:&s1 atIndex:2];
                    [inv setArgument:&s2 atIndex:3];
                    [inv invoke];
                    __unsafe_unretained id ret = nil;
                    [inv getReturnValue:&ret];
                    prfInput = ret;
                }
                if (prfInput != nil) {
                    id prfAssert = [[prfAssertClass alloc] init];
                    SEL setInputValues = NSSelectorFromString(@"setInputValues:");
                    if ([prfAssert respondsToSelector:setInputValues]) {
                        NSMethodSignature* sig3 = [prfAssert methodSignatureForSelector:setInputValues];
                        NSInvocation* inv3 = [NSInvocation invocationWithMethodSignature:sig3];
                        [inv3 setTarget:prfAssert];
                        [inv3 setSelector:setInputValues];
                        [inv3 setArgument:&prfInput atIndex:2];
                        [inv3 invoke];
                    }
                    SEL reqSetPRF = NSSelectorFromString(@"setPrf:");
                    if ([req respondsToSelector:reqSetPRF]) {
                        NSMethodSignature* sig4 = [req methodSignatureForSelector:reqSetPRF];
                        NSInvocation* inv4 = [NSInvocation invocationWithMethodSignature:sig4];
                        [inv4 setTarget:req];
                        [inv4 setSelector:reqSetPRF];
                        [inv4 setArgument:&prfAssert atIndex:2];
                        [inv4 invoke];
                    }
                }
            }

            MinervaPasskeyDelegate* del = [[MinervaPasskeyDelegate alloc] init];
            ASAuthorizationController* ctl =
                [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[req]];
            ctl.delegate = del;
            ctl.presentationContextProvider = del;

            dispatch_async(dispatch_get_main_queue(), ^{
                [ctl performRequests];
            });

            dispatch_semaphore_wait(del.sem, DISPATCH_TIME_FOREVER);

            if (del.lastError != nil) {
                set_c_error(out_err, [del.lastError localizedDescription]);
                return 1;
            }
            id credObj = del.authorization.credential;
            if (![credObj isKindOfClass:[ASAuthorizationPlatformPublicKeyCredentialAssertion class]]) {
                set_c_error(out_err, @"unexpected assertion credential type");
                return 2;
            }
            ASAuthorizationPlatformPublicKeyCredentialAssertion* assn =
                (ASAuthorizationPlatformPublicKeyCredentialAssertion*)credObj;
            NSData* prfOut = nil;
            SEL selPrf = NSSelectorFromString(@"prf");
            if ([assn respondsToSelector:selPrf]) {
                id prfObj = [assn valueForKey:@"prf"];
                if (prfObj != nil) {
                    id first = [prfObj valueForKey:@"first"];
                    if ([first isKindOfClass:[NSData class]]) {
                        prfOut = (NSData*)first;
                    }
                }
            }
            if (prfOut == nil) {
                set_c_error(out_err, @"PRF output missing from assertion");
                return 3;
            }
            copy_nsdata(prfOut, out_prf_output, out_prf_output_len);
            return 0;
        }
    }
    set_c_error(out_err, @"macOS 14.0+ required for passkey PRF");
    return 10;
}
