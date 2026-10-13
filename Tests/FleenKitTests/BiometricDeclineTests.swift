import Testing
import Foundation
@testable import FleenKit
@testable import KdbxCore

/// Cancelling a Touch ID prompt is an answer, and has to be remembered.
///
/// Uses the debug authenticator seam, so no real prompt appears and the outcome does not
/// depend on anyone touching a sensor.
/// Parent suite for everything that drives `BiometricUnlock.authenticatorForTesting`.
///
/// That hook is a process-global `nonisolated(unsafe) static var`, so two suites using it
/// at the same time overwrite each other's authenticator — which made these tests fail
/// roughly one run in five. `.serialized` on a suite only orders the tests *inside* it,
/// and sibling suites still run in parallel, so the trait has to live on a parent that
/// contains both.
@MainActor
@Suite("Biometrics", .serialized)
struct BiometricSuites {}

extension BiometricSuites {

@MainActor
@Suite("Biometric decline", .serialized)
struct BiometricDeclineTests {

    static let password = "correct horse battery staple"

    static func session() throws -> (URL, VaultSession) {
        guard let source = Bundle.module.url(forResource: "Fixtures/pkp-aes-argon2d.kdbx",
                                             withExtension: nil) else {
            throw Failure.fixtureMissing
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("fleen-decline-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("db.kdbx")
        try FileManager.default.copyItem(at: source, to: url)

        let suite = "com.fleen.tests.\(UUID().uuidString)"
        let session = VaultSession(preferences: Preferences(defaults: UserDefaults(suiteName: suite)!))
        try session.select(url: url)
        return (url, session)
    }

    enum Failure: Error { case fixtureMissing }

    /// Enrols a key so the biometric path is reachable at all.
    static func enrol(for session: VaultSession) throws -> Bool {
        guard let account = session.biometricAccount else { return false }
        var key = CompositeKey()
        key.addPassword(password)
        do {
            try BiometricUnlock.enroll(compositeKey: key.rawKey(), account: account)
            return true
        } catch {
            // Enrolment is impossible in some environments; those tests just skip.
            return false
        }
    }

    @Test("A fresh session has not been declined")
    func startsUndeclined() throws {
        let (url, session) = try Self.session()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        #expect(!session.biometricPromptDeclined)
    }

    @Test("Cancelling the prompt is remembered")
    func cancellingIsRemembered() async throws {
        let (url, session) = try Self.session()
        defer {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
            BiometricUnlock.authenticatorForTesting = nil
            if let account = session.biometricAccount { BiometricUnlock.remove(account: account) }
        }
        guard try Self.enrol(for: session) else { return }

        BiometricUnlock.authenticatorForTesting = { _ in
            throw BiometricUnlock.Failure.userCancelled
        }

        await session.unlockWithBiometrics(userInitiated: false)

        #expect(session.biometricPromptDeclined,
                "the automatic prompt must not be offered again after a cancel")
        #expect(!session.state.isUnlocked)
    }

    @Test("A deliberate tap clears the decline and tries again")
    func userInitiatedAttemptClearsDecline() async throws {
        let (url, session) = try Self.session()
        defer {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
            BiometricUnlock.authenticatorForTesting = nil
            if let account = session.biometricAccount { BiometricUnlock.remove(account: account) }
        }
        guard try Self.enrol(for: session) else { return }

        BiometricUnlock.authenticatorForTesting = { _ in
            throw BiometricUnlock.Failure.userCancelled
        }
        await session.unlockWithBiometrics(userInitiated: false)
        #expect(session.biometricPromptDeclined)

        // Tapping the button is fresh intent: it must attempt regardless.
        BiometricUnlock.authenticatorForTesting = { _ in }
        await session.unlockWithBiometrics(userInitiated: true)

        #expect(!session.biometricPromptDeclined)
        #expect(session.state.isUnlocked, "a successful unlock should follow")
    }

    @Test("Choosing a different database clears the decline")
    func changingDatabaseClearsDecline() async throws {
        let (url, session) = try Self.session()
        defer {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
            BiometricUnlock.authenticatorForTesting = nil
            if let account = session.biometricAccount { BiometricUnlock.remove(account: account) }
        }
        guard try Self.enrol(for: session) else { return }

        BiometricUnlock.authenticatorForTesting = { _ in
            throw BiometricUnlock.Failure.userCancelled
        }
        await session.unlockWithBiometrics(userInitiated: false)
        #expect(session.biometricPromptDeclined)

        // A different database is a different intent.
        try session.select(url: url)
        #expect(!session.biometricPromptDeclined)
    }

    @Test("Unlocking with the password clears the decline for next time")
    func successfulUnlockClearsDecline() async throws {
        let (url, session) = try Self.session()
        defer {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
            BiometricUnlock.authenticatorForTesting = nil
            if let account = session.biometricAccount { BiometricUnlock.remove(account: account) }
        }
        guard try Self.enrol(for: session) else { return }

        BiometricUnlock.authenticatorForTesting = { _ in
            throw BiometricUnlock.Failure.userCancelled
        }
        await session.unlockWithBiometrics(userInitiated: false)
        #expect(session.biometricPromptDeclined)

        await session.unlock(password: Self.password)
        #expect(session.state.isUnlocked)
        #expect(!session.biometricPromptDeclined,
                "the next session should be offered Touch ID again")
    }
}

}
