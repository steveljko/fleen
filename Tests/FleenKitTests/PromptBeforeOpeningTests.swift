import Testing
import Foundation
@testable import FleenKit
@testable import KdbxCore

/// The "ask for Touch ID on click, before the window opens" option.
///
/// Every condition is tested because the failure mode is uniquely bad for a menu bar
/// app: if the rule says yes when biometrics cannot actually serve, the click raises no
/// prompt *and* opens no window, so it looks like the app is broken.
///
/// These deliberately exercise the rule only, never the prompt itself — no test here
/// touches `BiometricUnlock.authenticatorForTesting`, which is process-global and would
/// race the biometric suites.
///
/// One property is covered elsewhere rather than here: a click counts as fresh intent
/// and so must prompt even after an earlier cancel. That falls out of passing
/// `userInitiated: true`, which "A deliberate tap clears the decline and tries again"
/// in `BiometricDeclineTests` already pins; the rule below never consults the decline
/// flag at all.
@MainActor
@Suite("Prompt before opening")
struct PromptBeforeOpeningTests {

    static let password = "correct horse battery staple"

    static func session() throws -> (URL, VaultSession, Preferences) {
        guard let source = Bundle.module.url(forResource: "Fixtures/pkp-aes-argon2d.kdbx",
                                             withExtension: nil) else {
            throw Failure.fixtureMissing
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("fleen-prompt-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("db.kdbx")
        try FileManager.default.copyItem(at: source, to: url)

        let suite = "com.fleen.tests.\(UUID().uuidString)"
        let preferences = Preferences(defaults: UserDefaults(suiteName: suite)!)
        let session = VaultSession(preferences: preferences)
        try session.select(url: url)
        return (url, session, preferences)
    }

    enum Failure: Error { case fixtureMissing }

    static func enrol(for session: VaultSession) throws -> Bool {
        guard let account = session.biometricAccount else { return false }
        var key = CompositeKey()
        key.addPassword(password)
        do {
            try BiometricUnlock.enroll(compositeKey: key.rawKey(), account: account)
            return true
        } catch {
            return false   // enrolment is impossible in some environments; skip
        }
    }

    @Test("Off by default")
    func offByDefault() throws {
        let (url, session, preferences) = try Self.session()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        #expect(!preferences.promptBiometricsOnOpen)
        #expect(!session.shouldPromptBiometricsBeforeOpening)
    }

    /// The important negative case: the option is on, but nothing is enrolled. Returning
    /// true here would swallow the click entirely.
    @Test("Never prompts without an enrolled key, however the option is set")
    func requiresAnEnrolledKey() throws {
        let (url, session, preferences) = try Self.session()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        preferences.promptBiometricsOnOpen = true
        preferences.biometricUnlockEnabled = true

        #expect(!session.canUnlockWithBiometrics)
        #expect(!session.shouldPromptBiometricsBeforeOpening,
                "with no enrolled key the click must fall through to the lock screen")
    }

    @Test("Requires biometric unlock to be enabled too")
    func requiresBiometricUnlockEnabled() throws {
        let (url, session, preferences) = try Self.session()
        defer {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
            if let account = session.biometricAccount { BiometricUnlock.remove(account: account) }
        }
        guard try Self.enrol(for: session) else { return }

        preferences.promptBiometricsOnOpen = true
        preferences.biometricUnlockEnabled = false

        #expect(!session.shouldPromptBiometricsBeforeOpening)
    }

    @Test("Prompts when enabled, enrolled and locked")
    func promptsWhenEverythingIsReady() throws {
        let (url, session, preferences) = try Self.session()
        defer {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
            if let account = session.biometricAccount { BiometricUnlock.remove(account: account) }
        }
        guard try Self.enrol(for: session) else { return }

        preferences.biometricUnlockEnabled = true
        preferences.promptBiometricsOnOpen = true

        #expect(session.shouldPromptBiometricsBeforeOpening)
    }

    /// An unlocked vault must open its window, not ask for a fingerprint it does not
    /// need.
    @Test("Never prompts when the vault is already unlocked")
    func doesNotPromptWhenUnlocked() async throws {
        let (url, session, preferences) = try Self.session()
        defer {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
            if let account = session.biometricAccount { BiometricUnlock.remove(account: account) }
        }
        guard try Self.enrol(for: session) else { return }

        preferences.biometricUnlockEnabled = true
        preferences.promptBiometricsOnOpen = true
        await session.unlock(password: Self.password)
        try #require(session.state.isUnlocked)

        #expect(!session.shouldPromptBiometricsBeforeOpening)

        // ...and it comes back once the vault locks again.
        session.lock()
        #expect(session.shouldPromptBiometricsBeforeOpening)
    }

}
