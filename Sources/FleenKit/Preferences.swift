import Foundation

/// How the vault presents its folders.
public enum BrowseMode: String, CaseIterable, Sendable {
    /// One expandable outline, the whole hierarchy visible — as KeePassXC's group tree.
    case tree
    /// Drill down one level at a time, with large folder rows and breadcrumbs.
    case folders

    public var displayName: String {
        switch self {
        case .tree: return "Outline tree"
        case .folders: return "Drill down"
        }
    }

    public var explanation: String {
        switch self {
        case .tree:
            return "Shows the whole folder hierarchy at once, expanding in place."
        case .folders:
            return "Shows one folder at a time with large rows; click to go deeper."
        }
    }
}

extension Notification.Name {
}

/// User-visible settings, backed by `UserDefaults`.
///
/// Nothing secret is stored here — `UserDefaults` is a plist on disk in the clear.
/// The database *location* is a bookmark, the database *contents* never are.
public final class Preferences: @unchecked Sendable {
    public static let shared = Preferences()

    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        defaults.register(defaults: [
            Key.clipboardClearSeconds: 30,
            Key.idleLockMinutes: 5,
            Key.lockOnScreenLock: true,
            Key.lockOnSleep: true,
            Key.biometricUnlockEnabled: false,
            // Off by default: a fingerprint prompt appearing from a single click, with
            // no window to explain itself, should be something the user opted into.
            Key.promptBiometricsOnOpen: false,
            // Off by default: with it on, the macOS login password alone opens the vault.
            Key.allowDevicePasswordFallback: false,
            // On by default: it lives on ⌘-click, so it takes nothing away from a
            // plain click and there is no mode to be surprised by.
            Key.quickCopy: true,
            Key.showInDock: false,
            Key.watchDatabaseFile: true,
            // Off by default: deleted entries cluttering search results is the
            // opposite of what someone opening a password manager wants.
            Key.showRecycleBin: false,
            Key.browseMode: BrowseMode.tree.rawValue,
        ])
    }

    enum Key {
        static let clipboardClearSeconds = "clipboardClearSeconds"
        static let idleLockMinutes = "idleLockMinutes"
        static let lockOnScreenLock = "lockOnScreenLock"
        static let lockOnSleep = "lockOnSleep"
        static let biometricUnlockEnabled = "biometricUnlockEnabled"
        static let promptBiometricsOnOpen = "promptBiometricsOnOpen"
        static let allowDevicePasswordFallback = "allowDevicePasswordFallback"
        static let quickCopy = "quickCopy"
        static let showInDock = "showInDock"
        static let watchDatabaseFile = "watchDatabaseFile"
        static let showRecycleBin = "showRecycleBin"
        static let browseMode = "browseMode"
        static let databaseBookmark = "databaseBookmark"
        static let keyFileBookmark = "keyFileBookmark"
    }

    /// Seconds before a copied password is cleared. 0 disables auto-clear.
    public var clipboardClearSeconds: Int {
        get { defaults.integer(forKey: Key.clipboardClearSeconds) }
        set { defaults.set(max(0, newValue), forKey: Key.clipboardClearSeconds) }
    }

    /// Minutes of inactivity before locking. 0 disables idle locking.
    public var idleLockMinutes: Int {
        get { defaults.integer(forKey: Key.idleLockMinutes) }
        set { defaults.set(max(0, newValue), forKey: Key.idleLockMinutes) }
    }

    public var lockOnScreenLock: Bool {
        get { defaults.bool(forKey: Key.lockOnScreenLock) }
        set { defaults.set(newValue, forKey: Key.lockOnScreenLock) }
    }

    public var lockOnSleep: Bool {
        get { defaults.bool(forKey: Key.lockOnSleep) }
        set { defaults.set(newValue, forKey: Key.lockOnSleep) }
    }

    public var biometricUnlockEnabled: Bool {
        get { defaults.bool(forKey: Key.biometricUnlockEnabled) }
        set { defaults.set(newValue, forKey: Key.biometricUnlockEnabled) }
    }

    /// Ask for Touch ID the instant the menu bar icon is clicked, before the popover
    /// is shown, rather than opening the lock screen and prompting from there.
    ///
    /// Only meaningful alongside `biometricUnlockEnabled` and an enrolled key; the
    /// click falls back to the ordinary lock screen whenever biometrics cannot serve.
    public var promptBiometricsOnOpen: Bool {
        get { defaults.bool(forKey: Key.promptBiometricsOnOpen) }
        set { defaults.set(newValue, forKey: Key.promptBiometricsOnOpen) }
    }

    /// Whether the Touch ID prompt also accepts the Mac's login password.
    ///
    /// Baked into the keychain item's access control when it is enrolled, so changing
    /// it means removing the stored keys and enrolling again.
    public var allowDevicePasswordFallback: Bool {
        get { defaults.bool(forKey: Key.allowDevicePasswordFallback) }
        set { defaults.set(newValue, forKey: Key.allowDevicePasswordFallback) }
    }

    /// Whether ⌘-clicking an entry walks its copy sequence — password then one-time
    /// code for a login, number then expiry then security code for a card — instead of
    /// opening it. A plain click always opens the entry, whatever this is set to.
    public var quickCopy: Bool {
        get { defaults.bool(forKey: Key.quickCopy) }
        set { defaults.set(newValue, forKey: Key.quickCopy) }
    }

    /// How long the second click keeps its different meaning.
    ///
    /// Long enough to paste a password and land in the code field, short enough that a
    /// click a minute later is unambiguously a fresh start rather than a second step.
    public static let quickCopyWindow: TimeInterval = 15

    public var showInDock: Bool {
        get { defaults.bool(forKey: Key.showInDock) }
        set { defaults.set(newValue, forKey: Key.showInDock) }
    }

    public var watchDatabaseFile: Bool {
        get { defaults.bool(forKey: Key.watchDatabaseFile) }
        set { defaults.set(newValue, forKey: Key.watchDatabaseFile) }
    }

    /// Whether deleted entries (those in the database's recycle bin) are listed.
    public var showRecycleBin: Bool {
        get { defaults.bool(forKey: Key.showRecycleBin) }
        set { defaults.set(newValue, forKey: Key.showRecycleBin) }
    }

    /// How folders are presented.
    public var browseMode: BrowseMode {
        get {
            defaults.string(forKey: Key.browseMode)
                .flatMap(BrowseMode.init(rawValue:)) ?? .tree
        }
        set { defaults.set(newValue.rawValue, forKey: Key.browseMode) }
    }

    // MARK: - Remembered file locations

    /// Security-scoped bookmarks, so the sandboxed app can reopen the database the
    /// user picked without prompting again on every launch.
    public func rememberDatabase(_ url: URL) {
        defaults.set(Self.bookmark(for: url), forKey: Key.databaseBookmark)
        // The open panel grants access for this launch; starting the scope keeps it
        // usable after the panel goes away.
        if url.startAccessingSecurityScopedResource() { accessedURLs.insert(url) }
    }

    public func rememberKeyFile(_ url: URL?) {
        guard let url else {
            defaults.removeObject(forKey: Key.keyFileBookmark)
            return
        }
        defaults.set(Self.bookmark(for: url), forKey: Key.keyFileBookmark)
        if url.startAccessingSecurityScopedResource() { accessedURLs.insert(url) }
    }

    public func rememberedDatabase() -> URL? {
        resolve(Key.databaseBookmark)
    }

    public func rememberedKeyFile() -> URL? {
        resolve(Key.keyFileBookmark)
    }

    public func forgetDatabase() {
        defaults.removeObject(forKey: Key.databaseBookmark)
        defaults.removeObject(forKey: Key.keyFileBookmark)
    }

    private static func bookmark(for url: URL) -> Data? {
        try? url.bookmarkData(options: [.withSecurityScope],
                              includingResourceValuesForKeys: nil, relativeTo: nil)
    }

    private func resolve(_ key: String) -> URL? {
        guard let data = defaults.data(forKey: key) else { return nil }
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: data,
                                 options: [.withSecurityScope],
                                 relativeTo: nil,
                                 bookmarkDataIsStale: &stale) else { return nil }

        // Resolving a security-scoped bookmark is not enough — access has to be
        // *started*, or reading the file fails with a permission error in a sandboxed
        // build. Without this, a signed Fleen could remember the database's location
        // and then be unable to open it, while the unsigned build worked fine.
        if url.startAccessingSecurityScopedResource() {
            accessedURLs.insert(url)
        }

        // A stale bookmark still resolves; refresh it so it does not decay further.
        if stale { defaults.set(Self.bookmark(for: url), forKey: key) }
        return url
    }

    /// URLs whose security-scoped access we hold, so it can be released.
    ///
    /// Access is intentionally held for the process lifetime: the database is reopened
    /// on every unlock and saved on every edit, so releasing between operations would
    /// only create windows where the file is unreachable.
    private var accessedURLs: Set<URL> = []

    /// Releases every security-scoped resource. Called when the app terminates.
    public func releaseFileAccess() {
        for url in accessedURLs { url.stopAccessingSecurityScopedResource() }
        accessedURLs.removeAll()
    }
}
