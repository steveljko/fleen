import Foundation

/// A field value that may be memory-protected.
///
/// Protected values (typically Password, sometimes TOTP seeds and custom fields)
/// are held in `SecureBytes` and never converted to `String` unless a caller
/// explicitly asks — which is the moment the value escapes into unmanaged memory.
/// That call site is `reveal()`, deliberately named so it stands out in review.
public enum FieldValue: Sendable {
    case plain(String)
    case protected(SecureBytes)

    /// The value as a `String`. For protected fields this copies key material into a
    /// heap `String` we cannot zero — call it as late as possible and drop it fast.
    public func reveal() -> String {
        switch self {
        case .plain(let s): return s
        case .protected(let bytes):
            return bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
        }
    }

    /// Safe for search, logging and display: protected values report their presence
    /// but never their contents.
    public var isProtected: Bool {
        if case .protected = self { return true }
        return false
    }

    public var plainTextIfUnprotected: String? {
        if case .plain(let s) = self { return s }
        return nil
    }

    public var isEmpty: Bool {
        switch self {
        case .plain(let s): return s.isEmpty
        case .protected(let b): return b.count == 0
        }
    }

    public static func makeProtected(_ string: String) -> FieldValue {
        .protected(SecureBytes.fromUTF8(string))
    }
}

/// Creation/modification timestamps and expiry.
public struct TimeInfo: Sendable, Equatable {
    public var creationTime: Date?
    public var lastModificationTime: Date?
    public var lastAccessTime: Date?
    public var expiryTime: Date?
    public var expires: Bool
    public var usageCount: Int
    public var locationChanged: Date?

    public init(creationTime: Date? = nil, lastModificationTime: Date? = nil,
                lastAccessTime: Date? = nil, expiryTime: Date? = nil,
                expires: Bool = false, usageCount: Int = 0, locationChanged: Date? = nil) {
        self.creationTime = creationTime
        self.lastModificationTime = lastModificationTime
        self.lastAccessTime = lastAccessTime
        self.expiryTime = expiryTime
        self.expires = expires
        self.usageCount = usageCount
        self.locationChanged = locationChanged
    }

    public static func now() -> TimeInfo {
        let t = Date()
        return TimeInfo(creationTime: t, lastModificationTime: t, lastAccessTime: t)
    }

    public var isExpired: Bool {
        guard expires, let expiryTime else { return false }
        return expiryTime < Date()
    }
}

/// A file attached to an entry. The bytes live in the database's binary pool; an
/// entry holds only a reference, because KDBX deduplicates identical attachments
/// across entries and copying them per-entry would multiply memory for no reason.
public struct AttachmentRef: Sendable, Equatable {
    public var name: String
    public var poolIndex: Int

    public init(name: String, poolIndex: Int) {
        self.name = name
        self.poolIndex = poolIndex
    }
}

public struct Attachment: Sendable {
    /// Plain `Data`, deliberately noted: attachment bytes are **not** held in
    /// `SecureBytes` and are never zeroed. An attachment can be a key file or a
    /// recovery-code dump, so this is a known gap rather than a safe default —
    /// see the memory-hygiene notes in the README.
    public var data: Data
    /// KDBX's own "protected in memory" flag, carried through for fidelity. It does
    /// *not* change how the bytes above are stored.
    public var isProtected: Bool

    public init(data: Data, isProtected: Bool = false) {
        self.data = data
        self.isProtected = isProtected
    }
}

/// A password entry.
public struct Entry: Sendable, Identifiable {
    public var id: UUID
    public var fields: [String: FieldValue]
    public var times: TimeInfo
    public var iconID: Int
    public var customIconUUID: UUID?
    public var tags: [String]
    public var attachments: [AttachmentRef]
    public var foregroundColor: String?
    public var backgroundColor: String?
    public var overrideURL: String?
    public var history: [Entry]

    /// The five field names KeePass treats as standard; everything else is a custom field.
    public static let titleField = "Title"
    public static let userNameField = "UserName"
    public static let passwordField = "Password"
    public static let urlField = "URL"
    public static let notesField = "Notes"
    public static let standardFields = [titleField, userNameField, passwordField, urlField, notesField]

    public init(id: UUID = UUID(), fields: [String: FieldValue] = [:],
                times: TimeInfo = .now(), iconID: Int = 0, customIconUUID: UUID? = nil,
                tags: [String] = [], attachments: [AttachmentRef] = [],
                foregroundColor: String? = nil, backgroundColor: String? = nil,
                overrideURL: String? = nil, history: [Entry] = []) {
        self.id = id
        self.fields = fields
        self.times = times
        self.iconID = iconID
        self.customIconUUID = customIconUUID
        self.tags = tags
        self.attachments = attachments
        self.foregroundColor = foregroundColor
        self.backgroundColor = backgroundColor
        self.overrideURL = overrideURL
        self.history = history
    }

    // Convenience accessors for the standard fields. Title/username/URL are not
    // protected in any normal database, so exposing them as `String` is fine;
    // `password` deliberately returns the `FieldValue` so callers must opt in to
    // revealing it.
    public var title: String {
        get { fields[Self.titleField]?.plainTextIfUnprotected ?? fields[Self.titleField]?.reveal() ?? "" }
        set { fields[Self.titleField] = .plain(newValue) }
    }

    public var username: String {
        get { fields[Self.userNameField]?.plainTextIfUnprotected ?? fields[Self.userNameField]?.reveal() ?? "" }
        set { fields[Self.userNameField] = .plain(newValue) }
    }

    public var url: String {
        get { fields[Self.urlField]?.plainTextIfUnprotected ?? fields[Self.urlField]?.reveal() ?? "" }
        set { fields[Self.urlField] = .plain(newValue) }
    }

    public var notes: String {
        get { fields[Self.notesField]?.plainTextIfUnprotected ?? fields[Self.notesField]?.reveal() ?? "" }
        set { fields[Self.notesField] = .plain(newValue) }
    }

    public var password: FieldValue? {
        get { fields[Self.passwordField] }
        set { fields[Self.passwordField] = newValue }
    }

    /// Field names that exist only to store TOTP configuration.
    ///
    /// These are custom fields as far as the format is concerned, but they are
    /// plumbing rather than user content — a UI that surfaces a live one-time code
    /// should not also list the raw seed beside it.
    public static let totpFieldKeys: Set<String> = ["otp", "TOTP", "TOTP Seed", "TOTP Settings"]

    /// Custom fields worth showing: neither TOTP plumbing nor empty.
    public var meaningfulCustomFields: [String: FieldValue] {
        fields.filter { name, value in
            !Self.standardFields.contains(name)
                && !Self.totpFieldKeys.contains(name)
                && !value.isEmpty
        }
    }

    /// The TOTP seed, if this entry carries one. KeePassXC stores it either as an
    /// `otp` field holding an otpauth:// URI, or as `TOTP Seed` + `TOTP Settings`.
    public var totpURI: String? {
        if let otp = fields["otp"] { return otp.reveal() }
        guard let seed = fields["TOTP Seed"] else { return nil }
        let settings = fields["TOTP Settings"]?.reveal() ?? "30;6"
        let parts = settings.split(separator: ";")
        let period = parts.first.flatMap { Int($0) } ?? 30
        let digits = parts.count > 1 ? (Int(parts[1]) ?? 6) : 6
        let label = title.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "entry"
        return "otpauth://totp/\(label)?secret=\(seed.reveal())&period=\(period)&digits=\(digits)"
    }
}

/// A folder of entries and subgroups.
public struct Group: Sendable, Identifiable {
    public var id: UUID
    public var name: String
    public var notes: String
    public var iconID: Int
    public var customIconUUID: UUID?
    public var times: TimeInfo
    public var isExpanded: Bool
    public var enableSearching: Bool?
    public var groups: [Group]
    public var entries: [Entry]

    public init(id: UUID = UUID(), name: String = "", notes: String = "",
                iconID: Int = 48, customIconUUID: UUID? = nil, times: TimeInfo = .now(),
                isExpanded: Bool = true, enableSearching: Bool? = nil,
                groups: [Group] = [], entries: [Entry] = []) {
        self.id = id
        self.name = name
        self.notes = notes
        self.iconID = iconID
        self.customIconUUID = customIconUUID
        self.times = times
        self.isExpanded = isExpanded
        self.enableSearching = enableSearching
        self.groups = groups
        self.entries = entries
    }

    /// Depth-first walk over every entry in this subtree.
    public func allEntries() -> [Entry] {
        var result = entries
        for child in groups { result.append(contentsOf: child.allEntries()) }
        return result
    }

    public func allGroups() -> [Group] {
        var result = [self]
        for child in groups { result.append(contentsOf: child.allGroups()) }
        return result
    }
}
