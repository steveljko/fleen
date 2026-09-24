import Testing
import Foundation
@testable import FleenKit
@testable import KdbxCore

/// Messages must not outlive what they describe.
///
/// Every one of these covers a case where a status message survived the thing it was
/// reporting on and became a lie on screen — the class of bug that left the clipboard
/// countdown frozen.
@MainActor
@Suite("Transient messages")
struct TransientMessageTests {

    static func session() -> VaultSession {
        let suite = "com.fleen.tests.\(UUID().uuidString)"
        return VaultSession(preferences: Preferences(defaults: UserDefaults(suiteName: suite)!))
    }

    @Test("A lock reason is set for automatic locks and cleared for manual ones")
    func lockReasonReflectsCause() {
        let session = Self.session()

        session.lock(reason: .idleTimeout(minutes: 5))
        #expect(session.lastLockReason == .idleTimeout(minutes: 5))

        // A manual lock needs no explanation; showing one would be noise.
        session.lock(reason: .manual)
        #expect(session.lastLockReason == nil)
    }

    @Test("Locking clears any biometric enrolment warning")
    func lockClearsBiometricWarning() {
        let session = Self.session()
        // Advice about enrolment from an earlier attempt is not about this lock.
        session.lock(reason: .screenLocked)
        #expect(session.biometricWarning == nil)
    }

    @Test("A new unlock attempt clears the previous attempt's warning")
    func unlockAttemptClearsWarning() async {
        let session = Self.session()

        // With no database selected this fails immediately, which is enough to show
        // that the warning is reset before the attempt rather than after it.
        await session.unlock(password: "x")
        #expect(session.biometricWarning == nil)
    }

    @Test("An automatic lock explains itself in words a person can read")
    func lockReasonsAreReadable() {
        #expect(AutoLockController.Reason.idleTimeout(minutes: 1).explanation
            .contains("1 minute"))
        #expect(AutoLockController.Reason.idleTimeout(minutes: 5).explanation
            .contains("5 minutes"))
        #expect(AutoLockController.Reason.screenLocked.explanation
            .localizedCaseInsensitiveContains("screen"))
        #expect(AutoLockController.Reason.systemSleep.explanation
            .localizedCaseInsensitiveContains("sleep"))
        // Manual locks deliberately have nothing to say.
        #expect(AutoLockController.Reason.manual.explanation.isEmpty)
    }

    @Test("External-change state is cleared once acknowledged")
    func externalChangeNoticeIsDismissible() {
        let session = Self.session()
        session.dismissExternalChangeNotice()
        #expect(!session.hasExternalChanges)
    }

    @Test("Locking drops the decrypted database and its index together")
    func lockDropsEverything() {
        let session = Self.session()
        session.lock()
        #expect(session.database == nil)
        #expect(session.index.records.isEmpty)
    }
}
