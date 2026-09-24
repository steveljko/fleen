import Testing
import Foundation
import Security
import LocalAuthentication
@testable import FleenKit
import KdbxCore

/// Guards against a placebo lock.
///
/// The bug these exist for: the legacy macOS keychain accepts
/// `kSecAttrAccessControl` and can then ignore it, so a key written with a
/// `.biometryCurrentSet` gate reads back with **no prompt at all**. The unlock screen
/// showed a Touch ID button, the vault opened instantly, and nothing was actually
/// protecting it.
///
/// A real biometric item cannot be exercised in a test run — it needs user presence —
/// but the *detection* can be, which is the part that has to be right. An unprotected
/// item is written deliberately here and must be recognised as unprotected.
@Suite("Biometric enforcement", .serialized)
struct BiometricEnforcementTests {

    static let account = "enforcement-test"

    static func cleanUp() {
        _ = Keychain.delete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: BiometricUnlock.service,
            kSecAttrAccount as String: Self.account,
        ])
    }

    /// Writes a key with no access control at all — what the broken fallback produced.
    static func writeUnprotectedKey() -> OSStatus {
        cleanUp()
        return Keychain.add([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: BiometricUnlock.service,
            kSecAttrAccount as String: Self.account,
            kSecValueData as String: Data(repeating: 0xAB, count: 32),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ])
    }

    @Test("A key stored without a biometric gate is recognised as unprotected")
    func detectsUnprotectedKey() throws {
        defer { Self.cleanUp() }
        #expect(Self.writeUnprotectedKey() == errSecSuccess)

        #expect(!BiometricUnlock.isProtectionEnforced(account: Self.account),
                "a key that reads back with no prompt must never be treated as protected")
    }

    @Test("Touch ID is only offered where it can actually be delivered")
    func offersTouchIDOnlyWhenDeliverable() throws {
        defer { Self.cleanUp() }
        #expect(Self.writeUnprotectedKey() == errSecSuccess)

        switch BiometricUnlock.availableProtectionLevel {
        case .enforcedByKeychain:
            // A key the Keychain will hand over unprompted must not put a Touch ID
            // button on the unlock screen — that was a placebo lock.
            #expect(!BiometricUnlock.hasEnrolledKey(account: Self.account))
        case .enforcedByApp:
            // Here the item deliberately carries no OS gate, because the OS would
            // ignore one; Fleen supplies the prompt, so an existing key is offerable.
            #expect(BiometricUnlock.hasEnrolledKey(account: Self.account))
        }
    }

    @Test("A stored key is not released when authentication fails")
    func refusesKeyWhenAuthenticationFails() async throws {
        defer { Self.cleanUp(); BiometricUnlock.authenticatorForTesting = nil }
        #expect(Self.writeUnprotectedKey() == errSecSuccess)

        // Stand in for the prompt, so the suite never puts a real Touch ID dialog in
        // front of whoever runs it — and so the result does not depend on a finger.
        BiometricUnlock.authenticatorForTesting = { _ in
            throw BiometricUnlock.Failure.userCancelled
        }

        var released: SecureBytes?
        do {
            released = try await BiometricUnlock.retrieve(account: Self.account,
                                                         reason: "test")
        } catch {
            // Expected.
        }
        #expect(released == nil, "a declined biometric check must yield nothing")
    }

    @Test("A stored key is released only after authentication succeeds")
    func releasesKeyAfterAuthentication() async throws {
        defer { Self.cleanUp(); BiometricUnlock.authenticatorForTesting = nil }

        // Only meaningful in app-enforced mode; otherwise the Keychain owns the prompt.
        guard BiometricUnlock.availableProtectionLevel == .enforcedByApp else { return }
        #expect(Self.writeUnprotectedKey() == errSecSuccess)

        // A reference box: the closure is @Sendable, so a captured `var` cannot be
        // mutated from inside it.
        final class Flag: @unchecked Sendable { var wasAsked = false }
        let flag = Flag()
        BiometricUnlock.authenticatorForTesting = { _ in flag.wasAsked = true }

        let released = try await BiometricUnlock.retrieve(account: Self.account,
                                                         reason: "test")
        #expect(flag.wasAsked, "the key must not be read before the biometric check")
        #expect(released.withUnsafeBytes { [UInt8]($0) } == [UInt8](repeating: 0xAB, count: 32))
    }

    @Test("A missing key is reported as missing, not as unprotected")
    func missingKeyIsNotConfusedWithUnprotected() {
        Self.cleanUp()
        // No item at all: distinct from an item that exists but is unenforced, and the
        // two lead to different messages for the user.
        #expect(!BiometricUnlock.isProtectionEnforced(account: Self.account))
        #expect(!BiometricUnlock.hasEnrolledKey(account: Self.account))
    }

    @Test("Enrolment either binds the key or says it could not")
    func enrolmentIsHonestAboutWhatItDid() throws {
        defer { Self.cleanUp() }

        var thrown: Error?
        do {
            try BiometricUnlock.enroll(
                compositeKey: SecureBytes([UInt8](repeating: 0x11, count: 32)),
                account: Self.account)
        } catch {
            thrown = error
        }

        switch BiometricUnlock.availableProtectionLevel {
        case .enforcedByKeychain:
            if thrown == nil {
                // Success is only legitimate if the gate really is enforced.
                #expect(BiometricUnlock.isProtectionEnforced(account: Self.account),
                        "enrolment reported success for a key it cannot protect")
            } else {
                #expect(!BiometricUnlock.hasEnrolledKey(account: Self.account),
                        "a failed enrolment must not leave a key behind")
            }
        case .enforcedByApp:
            // Storing is expected to work; the protection comes from our own prompt.
            #expect(thrown == nil, "unexpected failure: \(String(describing: thrown))")
            #expect(BiometricUnlock.hasEnrolledKey(account: Self.account))
        }
    }

    @Test("The refusal explains itself without jargon")
    func explainsRefusal() throws {
        let message = try #require(
            BiometricUnlock.Failure.protectionNotEnforced.errorDescription)
        #expect(message.contains("no prompt"))
        #expect(message.contains("Sign the app"))
    }
}
