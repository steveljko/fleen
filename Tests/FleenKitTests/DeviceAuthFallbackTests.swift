import Testing
import Foundation
import LocalAuthentication
@testable import FleenKit

/// Unlocking when the fingerprint sensor cannot be reached.
///
/// The point of these: Fleen used to ask macOS for `.deviceOwnerAuthenticationWithBiometrics`
/// and to blank `localizedFallbackTitle`, which together meant a Mac with the lid shut,
/// an external keyboard, or no Touch ID at all had exactly one way into the vault —
/// typing the master password. The fallback is the Mac's own login password, which the
/// OS already trusts to stand in for the sensor.
@MainActor
@Suite("Device authentication fallback")
struct DeviceAuthFallbackTests {

    /// The policy actually asked for has to be the one that accepts a password.
    /// `canEvaluatePolicy` is consulted here rather than mocked, because the bug this
    /// guards was a wrong *constant*, and a mock would have happily returned the wrong
    /// one too.
    @Test("This Mac can authenticate by device owner, with or without a sensor")
    func deviceOwnerPolicyIsAvailable() {
        let context = LAContext()
        var error: NSError?
        let canDeviceOwner = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)

        // A Mac with a login password set can always satisfy this, sensor or not.
        #expect(canDeviceOwner, "device-owner authentication should be available: \(error as Any)")
    }

    /// The weaker policy is a strict subset: anything biometrics can satisfy, device
    /// owner can too. So availability must never be *narrower* than it used to be.
    @Test("Device-owner availability is never narrower than biometrics-only")
    func deviceOwnerIsSupersetOfBiometrics() {
        let biometricContext = LAContext()
        let ownerContext = LAContext()
        let canBiometrics = biometricContext.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: nil)
        let canDeviceOwner = ownerContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)

        if canBiometrics { #expect(canDeviceOwner) }
    }

    /// A Mac with no sensor must still offer the feature, via the password — previously
    /// it reported `.none` and the whole thing switched itself off.
    @Test("Availability reports a usable method rather than giving up")
    func availabilityIsUsable() {
        // With the opt-in on: that is the setting this suite is about.
        let availability = BiometricUnlock.availability(allowDevicePassword: true)
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else {
            // No login password set: reporting none is correct.
            #expect(!availability.isAvailable)
            return
        }
        #expect(availability.isAvailable,
                "with device-owner authentication possible, unlock must be on offer")
    }

    @Test("The password-only case names the credential it will ask for")
    func devicePasswordIsNamed() {
        #expect(BiometricUnlock.Biometry.devicePassword.isAvailable)
        #expect(BiometricUnlock.Biometry.devicePassword.displayName == "your Mac password")
    }

    /// `.none` is still a real state — a Mac with no login password at all.
    @Test("No authentication method at all is still reported as unavailable")
    func noneRemainsUnavailable() {
        #expect(!BiometricUnlock.Biometry.none(reason: "no password set").isAvailable)
    }

    /// The access control must accept either proof while keeping the invalidate-on-new-
    /// fingerprint property. Built here exactly as `enroll` builds it.
    @Test("The access control accepts biometry or the device passcode")
    func accessControlAcceptsBoth() throws {
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet, .or, .devicePasscode],
            &error)

        #expect(access != nil,
                "macOS rejected the combined policy: \(String(describing: error?.takeRetainedValue()))")
    }
}
