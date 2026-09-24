import Testing
import Foundation
@testable import FleenKit
@testable import KdbxCore

@Suite("Preferences")
struct PreferencesTests {

    /// Each test gets its own defaults domain so they cannot interfere.
    static func isolated() -> Preferences {
        let suite = "com.fleen.tests.\(UUID().uuidString)"
        return Preferences(defaults: UserDefaults(suiteName: suite)!)
    }

    @Test("Defaults are sensible before anything is set")
    func hasSaneDefaults() {
        let preferences = Self.isolated()
        #expect(preferences.clipboardClearSeconds == 30)
        #expect(preferences.idleLockMinutes == 5)
        #expect(preferences.lockOnScreenLock)
        #expect(preferences.lockOnSleep)
        #expect(!preferences.biometricUnlockEnabled, "biometrics must be opt-in")
        #expect(!preferences.showInDock, "this is a menu bar utility by default")
    }

    @Test("Display mode defaults to the outline tree and round-trips")
    func browseModeRoundTrips() {
        let preferences = Self.isolated()
        #expect(preferences.browseMode == .tree)

        preferences.browseMode = .folders
        #expect(preferences.browseMode == .folders)

        // Both modes describe themselves for the settings pane.
        for mode in BrowseMode.allCases {
            #expect(!mode.displayName.isEmpty)
            #expect(!mode.explanation.isEmpty)
        }
    }

    @Test("Negative timeouts are clamped rather than stored")
    func clampsNegativeValues() {
        let preferences = Self.isolated()
        preferences.clipboardClearSeconds = -5
        preferences.idleLockMinutes = -1
        #expect(preferences.clipboardClearSeconds == 0)
        #expect(preferences.idleLockMinutes == 0)
    }

    @Test("Values round-trip")
    func storesValues() {
        let preferences = Self.isolated()
        preferences.clipboardClearSeconds = 15
        preferences.idleLockMinutes = 10
        preferences.lockOnSleep = false
        #expect(preferences.clipboardClearSeconds == 15)
        #expect(preferences.idleLockMinutes == 10)
        #expect(!preferences.lockOnSleep)
    }
}

@Suite("Error presentation")
struct ErrorPresentationTests {

    @Test("Engine errors become messages a person can act on")
    func mapsEngineErrors() {
        #expect(VaultSession.message(for: KdbxError.invalidCredentials)
                    .contains("Incorrect password"))
        #expect(VaultSession.message(for: KdbxError.unsupportedVersion(major: 3, minor: 1))
                    .contains("3.1"))
        #expect(VaultSession.message(for: KdbxError.headerCorrupted)
                    .localizedCaseInsensitiveContains("damaged"))
    }

    @Test("A missing file is explained, not shown as a raw Cocoa error")
    func mapsMissingFile() {
        let error = NSError(domain: NSCocoaErrorDomain,
                            code: NSFileReadNoSuchFileError, userInfo: nil)
        #expect(VaultSession.message(for: error).contains("moved or been deleted"))
    }

    @Test("A wrong password never reveals which check failed")
    func doesNotLeakFailureDetail() {
        // The message must not distinguish "bad password" from "bad key file" or
        // hint at where in the file verification failed.
        let message = VaultSession.message(for: KdbxError.invalidCredentials)
        #expect(!message.localizedCaseInsensitiveContains("hmac"))
        #expect(!message.localizedCaseInsensitiveContains("block"))
        #expect(!message.localizedCaseInsensitiveContains("header"))
    }
}
