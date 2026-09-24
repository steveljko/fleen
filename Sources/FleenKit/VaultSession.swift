import Foundation
import Observation
import KdbxCore

/// The app's single source of truth for the open database.
///
/// **Read-only.** There is no save path: `KdbxCore` cannot write KDBX files, so
/// nothing here can modify the user's database. Reloading re-reads the file; the
/// external-change notice exists so the user can pick up what KeePassXC wrote, not so
/// Fleen can merge into it.
///
/// Invariants this type exists to enforce:
///
/// * Decrypted data lives in exactly one place — `database` — plus a search index
///   that holds no secrets. There is no parallel UI model duplicating passwords.
/// * Locking drops both, along with the cached credentials, in one operation.
/// * The KDF never runs on the main thread. Unlock and save are `async` and hop to a
///   background executor; the UI stays live throughout.
@MainActor
@Observable
public final class VaultSession {

    public enum State: Sendable, Equatable {
        /// No database chosen yet.
        case empty
        /// A database is selected but locked.
        case locked
        /// Key derivation in progress. Carries no fraction: Argon2 reports nothing
        /// while it runs, and the UI shows an indeterminate spinner rather than a
        /// number it would have to invent.
        case unlocking
        case unlocked
        /// The last attempt failed. Carries a message already fit for display.
        case failed(message: String)

        public var isUnlocked: Bool { self == .unlocked }
        public var isBusy: Bool {
            if case .unlocking = self { return true }
            return false
        }
    }

    // MARK: Observable state

    public private(set) var state: State = .empty
    public private(set) var databaseURL: URL?
    public private(set) var keyFileURL: URL?
    public private(set) var info: DatabaseInfo?
    public private(set) var database: Database?
    public private(set) var index = SearchIndex()
    /// Set when the file changed underneath us; the UI offers a reload.
    public private(set) var hasExternalChanges = false
    /// Explains an automatic lock, so the unlock screen can say why it appeared.
    public private(set) var lastLockReason: AutoLockController.Reason?
    /// Set when biometric enrolment did not stick, with an explanation.
    public private(set) var biometricWarning: String?

    /// True once the user has dismissed a biometric prompt.
    ///
    /// Stops the unlock screen offering it again automatically. Cancelling is an answer,
    /// and re-asking on every open would be nagging. Cleared by a deliberate tap on the
    /// Touch ID button, by choosing a different database, or by a successful unlock — all
    /// of which are the user signalling fresh intent.
    public private(set) var biometricPromptDeclined = false

    /// Mirrors `Preferences.showRecycleBin`.
    ///
    /// Held as stored observable state rather than read straight from `UserDefaults`
    /// on each access: defaults are not observable, so a computed property would
    /// leave an open popover showing stale contents after the setting is toggled.
    public private(set) var showsRecycleBin: Bool
    /// Mirrors `Preferences.browseMode`, for the same reason as `showsRecycleBin`:
    /// `UserDefaults` is not observable, so a computed property would leave the open
    /// popover showing the old layout after the setting changed.
    public private(set) var browseMode: BrowseMode

    // MARK: Private

    private let preferences: Preferences
    private var credentials: CompositeKey?
    private var watcher: DatabaseFileWatcher?
    /// Guards against a second biometric prompt while one is already on screen.
    /// LocalAuthentication fails the newer evaluation, which read as a spurious
    /// "authentication failed" when the auto-prompt and a button tap overlapped.
    private var isAuthenticating = false

    private var defaultsObserver: (any NSObjectProtocol)?

    public init(preferences: Preferences = .shared) {
        self.preferences = preferences
        self.showsRecycleBin = preferences.showRecycleBin
        self.browseMode = preferences.browseMode

        defaultsObserver = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                let current = self.preferences.showRecycleBin
                // Assign only on a real change, so unrelated defaults writes do not
                // invalidate every view observing this object.
                if current != self.showsRecycleBin { self.showsRecycleBin = current }
                let mode = self.preferences.browseMode
                if mode != self.browseMode { self.browseMode = mode }

                // Watching is started in `select`, so without this the preference had
                // no effect until the user reopened the database.
                let shouldWatch = self.preferences.watchDatabaseFile
                if shouldWatch != (self.watcher != nil) { self.startWatching() }
            }
        }

        if let remembered = preferences.rememberedDatabase() {
            try? select(url: remembered, keyFile: preferences.rememberedKeyFile())
        }
    }

    // MARK: - Choosing a database

    /// Points the session at a database without unlocking it.
    public func select(url: URL, keyFile: URL? = nil) throws {
        lock(reason: .manual)

        databaseURL = url
        keyFileURL = keyFile
        biometricPromptDeclined = false
        // Read the header now: it needs no password, and knowing the KDF up front is
        // what lets the unlock screen show a cost estimate before the user commits.
        info = try KdbxFile.inspect(url: url)
        state = .locked

        preferences.rememberDatabase(url)
        preferences.rememberKeyFile(keyFile)
        startWatching()
    }

    public func setKeyFile(_ url: URL?) {
        keyFileURL = url
        preferences.rememberKeyFile(url)
    }

    public var biometricAccount: String? {
        databaseURL.map(BiometricUnlock.account(for:))
    }

    /// What biometric protection this build can deliver, for Settings to explain.
    public var biometricProtectionLevel: BiometricUnlock.ProtectionLevel {
        BiometricUnlock.availableProtectionLevel
    }

    public var canUnlockWithBiometrics: Bool {
        guard preferences.biometricUnlockEnabled,
              BiometricUnlock.availability().isAvailable,
              let account = biometricAccount else { return false }
        return BiometricUnlock.hasEnrolledKey(account: account)
    }

    /// Whether clicking the menu bar icon should raise the biometric prompt itself,
    /// before any window is shown.
    ///
    /// Lives here rather than in the app delegate so the rule is testable: getting it
    /// wrong produces a click that does nothing visible at all, which is the hardest
    /// kind of bug to notice in a menu bar app.
    public var shouldPromptBiometricsBeforeOpening: Bool {
        preferences.promptBiometricsOnOpen
            && !state.isUnlocked
            && canUnlockWithBiometrics
    }

    // MARK: - Unlocking

    /// Unlocks with a typed password and/or the configured key file.
    ///
    /// - Parameter enrollBiometrics: on success, store the composite key behind
    ///   Touch ID. What is stored is the composite key, never the password itself.
    public func unlock(password: String?,
                       enrollBiometrics: Bool = false) async {
        guard let url = databaseURL else {
            state = .failed(message: "Choose a database first.")
            return
        }

        // A warning from a previous attempt must not sit on top of this one.
        biometricWarning = nil

        var key = CompositeKey()
        if let password, !password.isEmpty { key.addPassword(password) }
        if let keyFileURL {
            do {
                try key.addKeyFile(url: keyFileURL)
            } catch {
                state = .failed(message: Self.message(for: error))
                return
            }
        }
        guard !key.isEmpty else {
            state = .failed(message: "Enter your master password, or choose a key file.")
            return
        }

        await performUnlock(url: url, key: key, enrollBiometrics: enrollBiometrics)
    }

    /// Unlocks using the composite key stored behind Touch ID.
    ///
    /// Note this still runs the full KDF — biometrics replace *typing* the password,
    /// not the key derivation. Enabling Touch ID does not make the vault cheaper to
    /// attack offline.
    /// - Parameter userInitiated: true when the user tapped the Touch ID button, which
    ///   clears any earlier decline. The automatic prompt passes false.
    public func unlockWithBiometrics(userInitiated: Bool = true) async {
        guard let url = databaseURL, let account = biometricAccount else {
            state = .failed(message: "Choose a database first.")
            return
        }

        if userInitiated { biometricPromptDeclined = false }

        guard !isAuthenticating, !state.isBusy else { return }
        if ProcessInfo.processInfo.environment["FLEEN_DIAG"] == "1" {
            // So "did it prompt when it should not have?" is answerable from a log
            // rather than from whether someone happened to see a dialog.
            NSLog("FLEEN-DIAG: biometric unlock requested")
        }
        isAuthenticating = true
        defer { isAuthenticating = false }

        biometricWarning = nil

        let stored: SecureBytes
        do {
            stored = try await BiometricUnlock.retrieve(
                account: account,
                reason: "unlock your Fleen vault")
        } catch BiometricUnlock.Failure.userCancelled {
            // Not an error; the user backed out. Remember it so the next time they open
            // the popover it waits to be asked rather than asking again.
            biometricPromptDeclined = true
            state = .locked
            return
        } catch {
            state = .failed(message: Self.message(for: error))
            return
        }

        // The stored value IS the finished composite key. Adding it as a component
        // would hash it again and derive a different master key, so unlocking would
        // fail with "incorrect password" no matter what the user did.
        let key = CompositeKey.precomposed(stored)
        await performUnlock(url: url, key: key, enrollBiometrics: false)
    }

    private func performUnlock(url: URL, key: CompositeKey,
                               enrollBiometrics: Bool) async {
        guard let info else {
            state = .failed(message: "Could not read the database header.")
            return
        }

        state = .unlocking

        let opened: Result<Database, Error> = await Task.detached(priority: .userInitiated) {
            // The expensive work, off the main actor. `Database` and `CompositeKey`
            // are both Sendable, so nothing crosses that is not meant to.
            do { return .success(try KdbxFile.open(url: url, credentials: key)) }
            catch { return .failure(error) }
        }.value

        switch opened {
        case .success(let database):
            adopt(database, credentials: key)
            if enrollBiometrics, let account = biometricAccount {
                do {
                    try BiometricUnlock.enroll(compositeKey: key.rawKey(),
                                               account: account)
                    preferences.biometricUnlockEnabled = true

                    // Verify it actually persisted. This check needs no biometric
                    // prompt, and it catches the common unsigned-build case where the
                    // Keychain accepts the write but the item is unreadable later —
                    // which would otherwise surface as Touch ID mysteriously never
                    // appearing, with nothing to explain it.
                    if BiometricUnlock.hasEnrolledKey(account: account) {
                        biometricWarning = nil
                    } else {
                        biometricWarning = "Touch ID could not be saved for this database. Unsigned builds get a new identity each time they are rebuilt, which invalidates Keychain items — sign the app with your Developer ID to keep it."
                    }
                } catch {
                    // Enrolment failing must not undo a successful unlock.
                    biometricWarning = "Touch ID could not be saved: \(error.localizedDescription)"
                    NSLog("Fleen: could not enrol biometric key: \(error.localizedDescription)")
                }
            }
        case .failure(let error):
            state = .failed(message: Self.message(for: error))
        }
    }

    private func adopt(_ database: Database, credentials: CompositeKey) {
        self.database = database
        self.credentials = credentials
        self.index = SearchIndex(database: database)
        self.hasExternalChanges = false
        self.lastLockReason = nil
        self.biometricPromptDeclined = false
        self.state = .unlocked
        watcher?.noteOurOwnWrite()
    }

    // MARK: - Locking

    /// Drops every decrypted byte we hold.
    public func lock(reason: AutoLockController.Reason = .manual) {
        database = nil
        credentials = nil
        index = SearchIndex()
        lastLockReason = reason == .manual ? nil : reason
        // Enrolment advice from an earlier session is not relevant to this lock.
        biometricWarning = nil
        if databaseURL != nil { state = .locked }
        ClipboardService.shared.clearIfStillOurs()
    }

    // MARK: - Searching

    public func search(_ query: String) -> [SearchIndex.Match] {
        index.search(query, includeRecycleBin: showsRecycleBin)
    }

    /// The recycle bin group, when the database has one. `nil` also means "nothing to
    /// hide", so callers need no separate check for databases without a bin.
    public var recycleBinGroupID: UUID? { index.recycleBinGroupID }



    public func entry(withID id: UUID) -> Entry? {
        database?.entry(withID: id)
    }

    // MARK: - Reloading

    /// Re-reads the file with the credentials already in memory.
    public func reload() async {
        guard let url = databaseURL, let credentials else { return }
        guard let info = try? KdbxFile.inspect(url: url) else {
            state = .failed(message: "The database file could not be read.")
            return
        }
        self.info = info

        state = .unlocking

        let opened: Result<Database, Error> = await Task.detached(priority: .userInitiated) {
            do { return .success(try KdbxFile.open(url: url, credentials: credentials)) }
            catch { return .failure(error) }
        }.value

        switch opened {
        case .success(let database): adopt(database, credentials: credentials)
        case .failure(let error): state = .failed(message: Self.message(for: error))
        }
    }

    public func dismissExternalChangeNotice() {
        hasExternalChanges = false
    }

    // MARK: - File watching

    private func startWatching() {
        watcher?.cancel()
        watcher = nil
        guard preferences.watchDatabaseFile, let url = databaseURL else { return }
        let watcher = DatabaseFileWatcher(url: url)
        watcher.start { [weak self] in
            MainActor.assumeIsolated { self?.hasExternalChanges = true }
        }
        self.watcher = watcher
    }

    // MARK: - Error presentation

    /// Maps engine errors to something worth showing a person.
    /// `nonisolated` because it is pure — no state, so no reason to demand the main actor.
    /// Public so the UI can present any error through the same mapping the session
    /// uses, rather than showing a raw `localizedDescription` in some places only.
    public nonisolated static func message(for error: Error) -> String {
        if let kdbx = error as? KdbxError, let description = kdbx.errorDescription {
            return description
        }
        if let biometric = error as? BiometricUnlock.Failure,
           let description = biometric.errorDescription {
            return description
        }
        let nsError = error as NSError
        if nsError.domain == NSCocoaErrorDomain, nsError.code == NSFileReadNoSuchFileError {
            return "The database file has moved or been deleted."
        }
        return error.localizedDescription
    }
}
