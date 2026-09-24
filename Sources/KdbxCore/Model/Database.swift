import Foundation

/// Database-level metadata from the `<Meta>` element.
public struct DatabaseMeta: Sendable {
    public var generator: String
    public var databaseName: String
    public var databaseNameChanged: Date?
    public var databaseDescription: String
    public var databaseDescriptionChanged: Date?
    public var defaultUserName: String
    public var defaultUserNameChanged: Date?
    public var maintenanceHistoryDays: Int
    public var color: String
    public var masterKeyChanged: Date?
    public var masterKeyChangeRec: Int64
    public var masterKeyChangeForce: Int64
    public var recycleBinEnabled: Bool
    public var recycleBinUUID: UUID?
    public var recycleBinChanged: Date?
    public var entryTemplatesGroup: UUID?
    public var historyMaxItems: Int
    public var historyMaxSize: Int64
    public var customIcons: [UUID: Data]
    public var customData: [String: String]

    public init(generator: String = "Fleen", databaseName: String = "",
                databaseNameChanged: Date? = nil, databaseDescription: String = "",
                databaseDescriptionChanged: Date? = nil, defaultUserName: String = "",
                defaultUserNameChanged: Date? = nil, maintenanceHistoryDays: Int = 365,
                color: String = "", masterKeyChanged: Date? = nil,
                masterKeyChangeRec: Int64 = -1, masterKeyChangeForce: Int64 = -1,
                recycleBinEnabled: Bool = true, recycleBinUUID: UUID? = nil,
                recycleBinChanged: Date? = nil, entryTemplatesGroup: UUID? = nil,
                historyMaxItems: Int = 10, historyMaxSize: Int64 = 6 * 1024 * 1024,
                customIcons: [UUID: Data] = [:], customData: [String: String] = [:]) {
        self.generator = generator
        self.databaseName = databaseName
        self.databaseNameChanged = databaseNameChanged
        self.databaseDescription = databaseDescription
        self.databaseDescriptionChanged = databaseDescriptionChanged
        self.defaultUserName = defaultUserName
        self.defaultUserNameChanged = defaultUserNameChanged
        self.maintenanceHistoryDays = maintenanceHistoryDays
        self.color = color
        self.masterKeyChanged = masterKeyChanged
        self.masterKeyChangeRec = masterKeyChangeRec
        self.masterKeyChangeForce = masterKeyChangeForce
        self.recycleBinEnabled = recycleBinEnabled
        self.recycleBinUUID = recycleBinUUID
        self.recycleBinChanged = recycleBinChanged
        self.entryTemplatesGroup = entryTemplatesGroup
        self.historyMaxItems = historyMaxItems
        self.historyMaxSize = historyMaxSize
        self.customIcons = customIcons
        self.customData = customData
    }
}

/// An unlocked KDBX database: the single canonical in-memory representation.
///
/// Immutable in practice: Fleen reads databases and never writes them, so there are no
/// mutating operations here. Editing is KeePassXC's job.
///
/// There is deliberately no second "UI model" mirroring this tree. The app layer
/// renders `Group`/`Entry` directly and keeps only a lightweight search index of
/// non-secret fields alongside, so decrypted secrets exist in exactly one place and
/// locking has exactly one thing to drop.
public struct Database: Sendable {
    public var meta: DatabaseMeta
    public var rootGroup: Group
    /// Attachment pool, indexed by the reference held on each entry.
    public var binaryPool: [Int: Attachment]
    /// Reproduced on save so a database stays readable by the app that wrote it.
    public var cipher: KdbxCipher
    public var kdf: KdbxKdf
    public var compression: KdbxCompression
    public var deletedObjects: [(uuid: UUID, deletionTime: Date)]

    public init(meta: DatabaseMeta = DatabaseMeta(),
                rootGroup: Group = Group(name: "Root"),
                binaryPool: [Int: Attachment] = [:],
                cipher: KdbxCipher = .aes256CBC,
                kdf: KdbxKdf = .argon2d(memoryKiB: 65536, iterations: 10,
                                        parallelism: 2, version: 0x13),
                compression: KdbxCompression = .gzip,
                deletedObjects: [(uuid: UUID, deletionTime: Date)] = []) {
        self.meta = meta
        self.rootGroup = rootGroup
        self.binaryPool = binaryPool
        self.cipher = cipher
        self.kdf = kdf
        self.compression = compression
        self.deletedObjects = deletedObjects
    }

    public var allEntries: [Entry] { rootGroup.allEntries() }
    public var entryCount: Int { allEntries.count }

    public func attachment(for ref: AttachmentRef) -> Attachment? {
        binaryPool[ref.poolIndex]
    }

    /// Finds an entry anywhere in the tree.
    public func entry(withID id: UUID) -> Entry? {
        func search(_ group: Group) -> Entry? {
            if let hit = group.entries.first(where: { $0.id == id }) { return hit }
            for child in group.groups { if let hit = search(child) { return hit } }
            return nil
        }
        return search(rootGroup)
    }

    /// Finds a group anywhere in the tree.
    public func group(withID id: UUID) -> Group? {
        func search(_ group: Group) -> Group? {
            if group.id == id { return group }
            for child in group.groups { if let hit = search(child) { return hit } }
            return nil
        }
        return search(rootGroup)
    }

    /// The chain of groups from the root down to `id`, for breadcrumbs.
    /// Returns nil when the group is not in this database.
    public func path(toGroup id: UUID) -> [Group]? {
        func search(_ group: Group, _ trail: [Group]) -> [Group]? {
            let trail = trail + [group]
            if group.id == id { return trail }
            for child in group.groups {
                if let hit = search(child, trail) { return hit }
            }
            return nil
        }
        return search(rootGroup, [])
    }

    /// The chain of groups containing an entry, root first.
    ///
    /// Note this returns the entry's *folders*, not the entry — callers that want a
    /// full breadcrumb append the entry's own title themselves, since an entry is not
    /// a `Group` and pretending otherwise would complicate every other caller.
    public func path(toEntry id: UUID) -> [Group]? {
        func search(_ group: Group, _ trail: [Group]) -> [Group]? {
            let trail = trail + [group]
            if group.entries.contains(where: { $0.id == id }) { return trail }
            for child in group.groups {
                if let hit = search(child, trail) { return hit }
            }
            return nil
        }
        return search(rootGroup, [])
    }
}
