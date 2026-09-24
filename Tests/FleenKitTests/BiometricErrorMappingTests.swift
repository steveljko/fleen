import Testing
import Foundation
import LocalAuthentication
@testable import FleenKit

/// LocalAuthentication error mapping.
///
/// Worth testing because the distinctions decide what the user is told to do, and
/// getting them wrong means showing "authentication failed" for situations that are
/// not failures at all — a cancelled prompt, or a lockout that needs the master
/// password rather than another finger.
@Suite("Biometric error mapping")
struct BiometricErrorMappingTests {

    static func error(_ code: LAError.Code) -> NSError {
        NSError(domain: LAError.errorDomain, code: code.rawValue)
    }

    @Test("Cancelling is not a failure")
    func cancellationIsNotFailure() {
        for code in [LAError.Code.userCancel, .systemCancel, .appCancel, .userFallback] {
            guard case .userCancelled = BiometricUnlock.failure(for: Self.error(code)) else {
                Issue.record("\(code) should be treated as a cancellation")
                continue
            }
        }
    }

    @Test("A lockout tells the user to use the master password")
    func lockoutIsActionable() throws {
        let failure = BiometricUnlock.failure(for: Self.error(.biometryLockout))
        let message = try #require(failure.errorDescription)
        #expect(message.localizedCaseInsensitiveContains("master password"),
                "another fingerprint will not help once Touch ID is locked out")
    }

    @Test("Not enrolled and not available are reported as unavailable, not failure")
    func unavailabilityIsDistinct() throws {
        for code in [LAError.Code.biometryNotEnrolled, .biometryNotAvailable] {
            guard case .notAvailable = BiometricUnlock.failure(for: Self.error(code)) else {
                Issue.record("\(code) should be .notAvailable")
                continue
            }
        }

        let notEnrolled = BiometricUnlock.failure(for: Self.error(.biometryNotEnrolled))
        #expect(notEnrolled.errorDescription?
            .localizedCaseInsensitiveContains("System Settings") == true,
                "tell the user where to enrol")
    }

    @Test("An actual mismatch suggests retrying or the password")
    func mismatchIsExplained() throws {
        let failure = BiometricUnlock.failure(for: Self.error(.authenticationFailed))
        let message = try #require(failure.errorDescription)
        #expect(message.localizedCaseInsensitiveContains("didn’t recognise")
                || message.localizedCaseInsensitiveContains("did not recognise"))
        #expect(message.localizedCaseInsensitiveContains("master password"))
    }

    @Test("A non-LocalAuthentication error keeps its own description")
    func foreignErrorsPassThrough() throws {
        let foreign = NSError(domain: "com.example.other", code: 42,
                              userInfo: [NSLocalizedDescriptionKey: "Something specific"])
        let message = try #require(BiometricUnlock.failure(for: foreign).errorDescription)
        #expect(message == "Something specific")
    }
}
