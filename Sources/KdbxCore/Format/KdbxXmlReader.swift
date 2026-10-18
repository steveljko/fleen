import Foundation

/// Streaming XML → model parser.
///
/// Event-driven, so no parallel tree of decrypted values ever exists, and fed by
/// `KdbxXmlTokenizer` rather than `XMLParser`: libxml2 kept its own unwipeable copy of
/// the decrypted XML alive after the vault locked (see the tokenizer for details).
final class KdbxXmlReader: KdbxXmlHandler {

    /// Deeper than any real folder tree. `Group`s nest by value and are walked
    /// recursively (search index, tree views, deallocation), so an attacker-supplied
    /// depth in the tens of thousands overflowed the stack and crashed the app.
    static let maximumGroupDepth = 512
    private let innerStream: InnerStreamCipher
    private let binaries: [Attachment]

    private var meta = DatabaseMeta()
    private var rootGroup = Group(name: "Root")
    private var deletedObjects: [(uuid: UUID, deletionTime: Date)] = []

    /// Element path, so handlers can tell `<Times><LastModificationTime>` inside an
    /// entry from the identically-named element inside a group.
    private var path: [String] = []
    private var text = ""

    // Stacks, because groups nest arbitrarily.
    private var groupStack: [Group] = []
    private var entryStack: [Entry] = []
    private var inHistory = 0

    // Scratch for the element currently being assembled.
    private var currentFieldKey: String?
    private var currentFieldValue: FieldValue?
    private var currentFieldProtected = false
    private var currentBinaryKey: String?
    private var currentBinaryRef: Int?
    private var currentCustomDataKey: String?
    private var currentIconUUID: UUID?
    private var currentIconData: Data?
    private var currentDeletedUUID: UUID?
    private var currentDeletedTime: Date?

    init(innerStream: InnerStreamCipher, binaries: [Attachment]) {
        self.innerStream = innerStream
        self.binaries = binaries
    }

    func parse(_ data: Data) throws -> (meta: DatabaseMeta, root: Group,
                                        deleted: [(uuid: UUID, deletionTime: Date)]) {
        try KdbxXmlTokenizer.parse(data, handler: self)
        return (meta, rootGroup, deletedObjects)
    }

    // MARK: - KdbxXmlHandler

    func startElement(_ elementName: String, attributes attributeDict: [String: String]) throws {
        path.append(elementName)
        text = ""

        switch elementName {
        case "Group":
            guard groupStack.count < Self.maximumGroupDepth else {
                throw KdbxError.malformedXML("folders are nested more than \(Self.maximumGroupDepth) deep")
            }
            groupStack.append(Group())
        case "Entry":
            // A history entry is a snapshot and has no history of its own. Nesting them
            // builds an `Entry.history` chain that is released recursively — tens of
            // thousands deep, that overflowed the stack when the vault locked.
            guard entryStack.count < 2 else {
                throw KdbxError.malformedXML("entry history is nested inside entry history")
            }
            entryStack.append(Entry())
        case "History":
            inHistory += 1
        case "String":
            currentFieldKey = nil
            currentFieldValue = nil
        case "Binary" where path.contains("Entry"):
            currentBinaryKey = nil
            currentBinaryRef = nil
        case "Value":
            // A protected value carries Protected="True" and base64 ciphertext;
            // a binary reference carries Ref="<pool index>".
            currentFieldProtected = (attributeDict["Protected"] ?? "False").lowercased() == "true"
            if let ref = attributeDict["Ref"] { currentBinaryRef = Int(ref) }
        case "Icon":
            currentIconData = nil
        case "DeletedObject":
            currentDeletedUUID = nil
            currentDeletedTime = nil
        case "Item" where path.contains("CustomData"):
            currentCustomDataKey = nil
        default:
            break
        }
    }

    func characters(_ string: String) {
        text += string
    }

    func endElement(_ elementName: String) throws {
        defer {
            path.removeLast()
            text = ""
        }
        try handleEndElement(elementName)
    }

    private func handleEndElement(_ elementName: String) throws {
        let value = text
        let inEntry = !entryStack.isEmpty
        let inMeta = path.contains("Meta")

        switch elementName {

        // MARK: Structure

        case "Group":
            guard var finished = groupStack.popLast() else { return }
            // Entries and subgroups were appended to this group as they closed.
            if groupStack.isEmpty {
                finished.name = finished.name.isEmpty ? "Root" : finished.name
                rootGroup = finished
            } else {
                groupStack[groupStack.count - 1].groups.append(finished)
            }
            _ = finished

        case "Entry":
            guard let finished = entryStack.popLast() else { return }
            if inHistory > 0, !entryStack.isEmpty {
                // History entries belong to the entry that contains them, not the group.
                entryStack[entryStack.count - 1].history.append(finished)
            } else if !groupStack.isEmpty {
                groupStack[groupStack.count - 1].entries.append(finished)
            }

        case "History":
            inHistory -= 1

        // MARK: Fields

        case "Key":
            if path.contains("String") { currentFieldKey = value }
            else if path.contains("Binary") && inEntry { currentBinaryKey = value }
            else if path.contains("CustomData") { currentCustomDataKey = value }

        case "Value":
            if path.dropLast().last == "String" {
                currentFieldValue = try decodeFieldValue(value, protected: currentFieldProtected)
            } else if path.dropLast().last == "Binary", inEntry {
                // Value is empty; the Ref attribute already captured the pool index.
                if let key = currentBinaryKey, let ref = currentBinaryRef,
                   binaries.indices.contains(ref) {
                    entryStack[entryStack.count - 1].attachments
                        .append(AttachmentRef(name: key, poolIndex: ref))
                }
            } else if path.contains("CustomData"), let key = currentCustomDataKey {
                if inMeta { meta.customData[key] = value }
            }
            currentFieldProtected = false

        case "String":
            if let key = currentFieldKey, let fieldValue = currentFieldValue, inEntry {
                entryStack[entryStack.count - 1].fields[key] = fieldValue
            }
            currentFieldKey = nil
            currentFieldValue = nil

        // MARK: Identity and appearance

        case "UUID":
            guard let uuid = decodeUUID(value) else { break }
            if path.contains("DeletedObject") { currentDeletedUUID = uuid }
            else if path.contains("CustomIcon") { currentIconUUID = uuid }
            else if elementIsDirectChildOf("Entry"), inEntry { entryStack[entryStack.count - 1].id = uuid }
            else if elementIsDirectChildOf("Group"), !groupStack.isEmpty {
                groupStack[groupStack.count - 1].id = uuid
            }

        case "Name":
            if !groupStack.isEmpty, elementIsDirectChildOf("Group") {
                groupStack[groupStack.count - 1].name = value
            }

        case "Notes":
            if inEntry, elementIsDirectChildOf("Entry") {
                entryStack[entryStack.count - 1].fields[Entry.notesField] = .plain(value)
            } else if !groupStack.isEmpty, elementIsDirectChildOf("Group") {
                groupStack[groupStack.count - 1].notes = value
            }

        case "IconID":
            let id = Int(value) ?? 0
            if inEntry, elementIsDirectChildOf("Entry") { entryStack[entryStack.count - 1].iconID = id }
            else if !groupStack.isEmpty, elementIsDirectChildOf("Group") {
                groupStack[groupStack.count - 1].iconID = id
            }

        case "CustomIconUUID":
            let uuid = decodeUUID(value)
            if inEntry { entryStack[entryStack.count - 1].customIconUUID = uuid }
            else if !groupStack.isEmpty { groupStack[groupStack.count - 1].customIconUUID = uuid }

        case "Tags":
            let tags = value.split(whereSeparator: { $0 == ";" || $0 == "," })
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            if inEntry { entryStack[entryStack.count - 1].tags = tags }

        case "ForegroundColor" where inEntry:
            entryStack[entryStack.count - 1].foregroundColor = value.isEmpty ? nil : value
        case "BackgroundColor" where inEntry:
            entryStack[entryStack.count - 1].backgroundColor = value.isEmpty ? nil : value
        case "OverrideURL" where inEntry:
            entryStack[entryStack.count - 1].overrideURL = value.isEmpty ? nil : value

        case "IsExpanded":
            if !groupStack.isEmpty { groupStack[groupStack.count - 1].isExpanded = parseBool(value) ?? true }

        // MARK: Times

        case "CreationTime", "LastModificationTime", "LastAccessTime",
             "ExpiryTime", "LocationChanged":
            guard let date = decodeDate(value) else { break }
            applyTime(elementName, date)

        case "Expires":
            let expires = parseBool(value) ?? false
            if inEntry, path.contains("Times") { entryStack[entryStack.count - 1].times.expires = expires }
            else if !groupStack.isEmpty, path.contains("Times") {
                groupStack[groupStack.count - 1].times.expires = expires
            }

        case "UsageCount":
            let count = Int(value) ?? 0
            if inEntry, path.contains("Times") { entryStack[entryStack.count - 1].times.usageCount = count }
            else if !groupStack.isEmpty, path.contains("Times") {
                groupStack[groupStack.count - 1].times.usageCount = count
            }

        // Auto-type elements are skipped: Fleen does not synthesise keystrokes, so
        // <AutoType>, its sequences and its window associations are parsed past rather
        // than retained. Nothing reads them, and holding unused entry data has no upside.

        // MARK: Meta

        case "Generator" where inMeta: meta.generator = value
        case "DatabaseName" where inMeta: meta.databaseName = value
        case "DatabaseNameChanged" where inMeta: meta.databaseNameChanged = decodeDate(value)
        case "DatabaseDescription" where inMeta: meta.databaseDescription = value
        case "DatabaseDescriptionChanged" where inMeta: meta.databaseDescriptionChanged = decodeDate(value)
        case "DefaultUserName" where inMeta: meta.defaultUserName = value
        case "DefaultUserNameChanged" where inMeta: meta.defaultUserNameChanged = decodeDate(value)
        case "MaintenanceHistoryDays" where inMeta: meta.maintenanceHistoryDays = Int(value) ?? 365
        case "Color" where inMeta: meta.color = value
        case "MasterKeyChanged" where inMeta: meta.masterKeyChanged = decodeDate(value)
        case "MasterKeyChangeRec" where inMeta: meta.masterKeyChangeRec = Int64(value) ?? -1
        case "MasterKeyChangeForce" where inMeta: meta.masterKeyChangeForce = Int64(value) ?? -1
        case "RecycleBinEnabled" where inMeta: meta.recycleBinEnabled = parseBool(value) ?? true
        case "RecycleBinUUID" where inMeta: meta.recycleBinUUID = decodeUUID(value)
        case "RecycleBinChanged" where inMeta: meta.recycleBinChanged = decodeDate(value)
        case "EntryTemplatesGroup" where inMeta: meta.entryTemplatesGroup = decodeUUID(value)
        case "HistoryMaxItems" where inMeta: meta.historyMaxItems = Int(value) ?? 10
        case "HistoryMaxSize" where inMeta: meta.historyMaxSize = Int64(value) ?? (6 * 1024 * 1024)

        case "Data" where path.contains("CustomIcon"):
            currentIconData = Data(base64Encoded: value.filter { !$0.isWhitespace })
        case "Icon" where path.contains("CustomIcons"):
            if let uuid = currentIconUUID, let data = currentIconData {
                meta.customIcons[uuid] = data
            }
            currentIconUUID = nil
            currentIconData = nil

        // MARK: Deleted objects

        case "DeletionTime":
            currentDeletedTime = decodeDate(value)
        case "DeletedObject":
            if let uuid = currentDeletedUUID {
                deletedObjects.append((uuid: uuid, deletionTime: currentDeletedTime ?? Date()))
            }

        default:
            break
        }
    }

    // MARK: - Helpers

    /// True when the element that just closed sits directly inside `parent`, rather
    /// than deeper in a nested structure that reuses the same tag name.
    private func elementIsDirectChildOf(_ parent: String) -> Bool {
        path.count >= 2 && path[path.count - 2] == parent
    }

    private func applyTime(_ element: String, _ date: Date) {
        func assign(_ times: inout TimeInfo) {
            switch element {
            case "CreationTime": times.creationTime = date
            case "LastModificationTime": times.lastModificationTime = date
            case "LastAccessTime": times.lastAccessTime = date
            case "ExpiryTime": times.expiryTime = date
            case "LocationChanged": times.locationChanged = date
            default: break
            }
        }
        if !entryStack.isEmpty, path.contains("Entry") { assign(&entryStack[entryStack.count - 1].times) }
        else if !groupStack.isEmpty { assign(&groupStack[groupStack.count - 1].times) }
    }

    private func decodeFieldValue(_ raw: String, protected: Bool) throws -> FieldValue {
        guard protected else { return .plain(raw) }
        guard let ciphertext = Data(base64Encoded: raw.filter { !$0.isWhitespace }) else {
            throw KdbxError.malformedXML("a protected value is not valid base64")
        }
        var bytes = [UInt8](ciphertext)
        // Order-sensitive: every protected value must pass through the stream exactly
        // once, in document order.
        innerStream.process(&bytes)
        defer { SecureBytes.wipe(&bytes) }
        return .protected(SecureBytes(bytes))
    }

    private func decodeUUID(_ raw: String) -> UUID? {
        guard let data = Data(base64Encoded: raw.filter { !$0.isWhitespace }), data.count == 16 else {
            return UUID(uuidString: raw)
        }
        return UUID(kdbxBytes: [UInt8](data))
    }

    private func parseBool(_ raw: String) -> Bool? {
        switch raw.lowercased() {
        case "true": return true
        case "false": return false
        case "null", "": return nil
        default: return nil
        }
    }

    private func decodeDate(_ raw: String) -> Date? {
        KdbxDate.decode(raw)
    }
}

/// KDBX4 stores timestamps as base64 of a little-endian Int64 count of seconds since
/// 0001-01-01T00:00:00Z. Older writers used ISO-8601 strings, and some still do, so
/// both are accepted on read; we always write the binary form.
enum KdbxDate {
    /// Seconds from 0001-01-01 to 1970-01-01 (the Unix epoch).
    static let epochOffset: Int64 = 62_135_596_800

    /// Built per call rather than shared: `ISO8601DateFormatter` is not `Sendable`,
    /// and this path only runs for legacy files that still write string timestamps.
    private static func makeISO8601() -> ISO8601DateFormatter {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }

    static func decode(_ raw: String) -> Date? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        if let data = Data(base64Encoded: trimmed), data.count == 8 {
            let seconds = data.withUnsafeBytes {
                Int64(littleEndian: $0.loadUnaligned(as: Int64.self)) }
            return Date(timeIntervalSince1970: TimeInterval(seconds - epochOffset))
        }
        return makeISO8601().date(from: trimmed)
    }

    static func encode(_ date: Date) -> String {
        let seconds = Int64(date.timeIntervalSince1970.rounded()) + epochOffset
        return withUnsafeBytes(of: seconds.littleEndian) { Data($0).base64EncodedString() }
    }
}
