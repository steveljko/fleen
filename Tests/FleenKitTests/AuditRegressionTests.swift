import Testing
import Foundation
import AppKit
import LocalAuthentication
@testable import FleenKit
@testable import KdbxCore

/// Regression tests for the app-layer findings in SECURITY_AUDIT.md.
@MainActor
@Suite("Security audit regressions (app)")
struct AppAuditRegressionTests {

    static let password = "correct horse battery staple"

    static func fixture(_ name: String) throws -> URL {
        try #require(Bundle.module.url(forResource: "Fixtures/\(name)", withExtension: nil))
    }

    /// Argon2id at 128 MiB × 8, so key derivation takes long enough to interrupt.
    /// Written by `audit/tools/kdbxgen.py` (spec `audit/specs/slow-fixture.json`) and
    /// checked to open in pykeepass.
    static let slowFixture = "audit-slow-argon2id.kdbx"

    static func makeSession() -> VaultSession {
        let suite = "com.fleen.tests.\(UUID().uuidString)"
        return VaultSession(preferences: Preferences(defaults: UserDefaults(suiteName: suite)!))
    }

    /// Starts an unlock and returns once the KDF is running off the main actor.
    static func startUnlock(_ session: VaultSession) async throws -> Task<Void, Never> {
        let task = Task { await session.unlock(password: Self.password) }
        var spins = 0
        while !session.state.isBusy && spins < 10_000 { await Task.yield(); spins += 1 }
        try #require(session.state.isBusy, "the unlock never reached key derivation")
        return task
    }

    // MARK: - F-03

    @Test("F-03: locking while the key is being derived keeps the vault locked")
    func lockDuringUnlockSticks() async throws {
        let session = Self.makeSession()
        try session.select(url: try Self.fixture(Self.slowFixture))

        let unlocking = try await Self.startUnlock(session)
        session.lock(reason: .screenLocked)
        await unlocking.value

        #expect(session.state == .locked)
        #expect(session.database == nil, "the decrypted database was installed after a lock")
    }

    @Test("F-03: choosing another database mid-unlock does not show the first one's contents")
    func switchDuringUnlockDiscardsResult() async throws {
        let session = Self.makeSession()
        try session.select(url: try Self.fixture(Self.slowFixture))

        let unlocking = try await Self.startUnlock(session)
        try session.select(url: try Self.fixture("pkp-recyclebin.kdbx"))
        await unlocking.value

        #expect(session.state == .locked)
        #expect(session.database == nil)
        #expect(session.databaseURL?.lastPathComponent == "pkp-recyclebin.kdbx")
    }

    @Test("F-03: an unlock nobody interrupted still completes")
    func uninterruptedUnlockStillWorks() async throws {
        let session = Self.makeSession()
        try session.select(url: try Self.fixture("pkp-aes-argon2d.kdbx"))
        await session.unlock(password: Self.password)
        #expect(session.state == .unlocked)
        await session.reload()
        #expect(session.state == .unlocked)
    }

    // MARK: - F-05

    @Test("F-05: a copied secret is marked transient as well as concealed")
    func secretCopyCarriesBothMarkers() {
        let board = NSPasteboard(name: NSPasteboard.Name("com.fleen.tests.\(UUID().uuidString)"))
        defer { board.releaseGlobally() }
        let service = ClipboardService(pasteboard: board)
        service.copySecret("s3cret", clearAfter: 30)

        #expect(board.string(forType: .string) == "s3cret")
        #expect(board.data(forType: ClipboardService.concealedType) != nil)
        #expect(board.data(forType: ClipboardService.transientType) != nil)
    }

    // MARK: - F-01

    @Test("F-01: the Mac login password is accepted only when the user opts in")
    func loginPasswordFallbackIsOptIn() {
        #expect(BiometricUnlock.policy(allowDevicePassword: false) == .deviceOwnerAuthenticationWithBiometrics)
        #expect(BiometricUnlock.policy(allowDevicePassword: true) == .deviceOwnerAuthentication)

        let defaults = UserDefaults(suiteName: "com.fleen.tests.\(UUID().uuidString)")!
        #expect(Preferences(defaults: defaults).allowDevicePasswordFallback == false,
                "on by default would let the login password alone open the vault")
    }

    @Test("F-01: the biometrics-only access control is accepted by macOS")
    func biometricsOnlyAccessControl() {
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.biometryCurrentSet], &error)
        #expect(access != nil)
    }

    // MARK: - F-11

    @Test("F-11: switching user is a lock reason the lock screen can explain")
    func userSwitchIsExplained() {
        #expect(!AutoLockController.Reason.userSwitched.explanation.isEmpty)
    }
}
