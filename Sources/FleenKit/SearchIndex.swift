import Foundation
import KdbxCore

/// A flat, pre-tokenised index over the searchable (non-secret) fields of a database.
///
/// Two properties drive the design:
///
/// 1. **Passwords are never indexed.** Only title, username, URL, tags and group
///    path go in. A search index is a plaintext copy of whatever it holds, so
///    holding secrets in one would undo the work `SecureBytes` does everywhere else.
///
/// 2. **All the string work happens once, at unlock.** Lowercasing and folding on
///    every keystroke is what makes naive search feel laggy on large databases; here
///    the per-keystroke cost is a scan over pre-folded UTF-8 byte arrays.
public struct SearchIndex: Sendable {

    /// One indexed entry. `id` points back into the canonical `Database`; this struct
    /// deliberately holds no secret material.
    public struct Record: Sendable {
        public let id: UUID
        public let title: String
        public let username: String
        public let url: String
        public let groupPath: String
        public let tags: [String]
        public let hasTOTP: Bool
        public let isExpired: Bool
        public let attachmentCount: Int
        /// True when this entry lives in the database's recycle bin, at any depth.
        public let isInRecycleBin: Bool

        /// Folded haystacks, in priority order: title, username, URL, tags, group.
        let folded: [[UInt8]]

        /// Builds a record and its folded haystacks.
        ///
        /// Public so the browse UI can present a group's entries through the same row
        /// type the search results use, instead of a near-identical parallel model.
        /// Note the parameters are all non-secret by construction — there is no way
        /// to put a password into a `Record`.
        public init(id: UUID, title: String, username: String, url: String,
                    groupPath: String, tags: [String], hasTOTP: Bool,
                    isExpired: Bool, attachmentCount: Int,
                    isInRecycleBin: Bool = false) {
            self.id = id
            self.title = title
            self.username = username
            self.url = url
            self.groupPath = groupPath
            self.tags = tags
            self.hasTOTP = hasTOTP
            self.isExpired = isExpired
            self.attachmentCount = attachmentCount
            self.isInRecycleBin = isInRecycleBin
            self.folded = [
                SearchIndex.fold(title), SearchIndex.fold(username), SearchIndex.fold(url),
                SearchIndex.fold(tags.joined(separator: " ")), SearchIndex.fold(groupPath)
            ]
        }
    }

    public private(set) var records: [Record] = []
    /// The recycle bin group, if this database has one. `nil` when the database has
    /// no bin configured, or names one that no longer exists.
    public private(set) var recycleBinGroupID: UUID?

    public init() {}

    public init(database: Database) {
        var records: [Record] = []
        records.reserveCapacity(database.entryCount)

        // KDBX writes an all-zero UUID to mean "no recycle bin", so that has to be
        // treated as absent rather than as a group to look for.
        let binID = database.meta.recycleBinUUID.flatMap { id -> UUID? in
            id == Self.zeroUUID ? nil : id
        }
        self.recycleBinGroupID = binID.flatMap { database.group(withID: $0) }?.id

        Self.walk(database.rootGroup, path: "", recycleBinID: self.recycleBinGroupID,
                  inRecycleBin: false, isRoot: true, into: &records)
        self.records = records
    }

    static let zeroUUID = UUID(uuid: (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))

    private static func walk(_ group: Group, path: String,
                             recycleBinID: UUID?, inRecycleBin: Bool,
                             isRoot: Bool = false,
                             into records: inout [Record]) {
        // The root group's name is format plumbing — usually "Root" or the file name —
        // so it is left out of the displayed path. Search rows read "Personal › Work"
        // rather than "Root › Personal › Work".
        let groupPath: String
        if isRoot {
            groupPath = ""
        } else {
            groupPath = path.isEmpty ? group.name : "\(path) › \(group.name)"
        }
        // Once inside the bin, everything below it is too.
        let inBin = inRecycleBin || (recycleBinID != nil && group.id == recycleBinID)

        for entry in group.entries {
            // Read the plain fields directly rather than via `reveal()`, so a
            // protected value can never be pulled into the index by accident.
            let title = entry.fields[Entry.titleField]?.plainTextIfUnprotected ?? ""
            let username = entry.fields[Entry.userNameField]?.plainTextIfUnprotected ?? ""
            let url = entry.fields[Entry.urlField]?.plainTextIfUnprotected ?? ""

            records.append(Record(
                id: entry.id,
                title: title, username: username, url: url,
                groupPath: groupPath, tags: entry.tags,
                hasTOTP: entry.totp != nil,
                isExpired: entry.times.isExpired,
                attachmentCount: entry.attachments.count,
                isInRecycleBin: inBin))
        }

        for child in group.groups {
            walk(child, path: groupPath, recycleBinID: recycleBinID,
                 inRecycleBin: inBin, into: &records)
        }
    }

    /// Case- and diacritic-insensitive folding down to UTF-8 bytes.
    ///
    /// Done once per field at index time. Comparing bytes rather than `Character`s
    /// avoids grapheme-breaking work on every keystroke, which is the single biggest
    /// cost in a naive implementation.
    static func fold(_ string: String) -> [UInt8] {
        guard !string.isEmpty else { return [] }
        let folded = string.folding(options: [.caseInsensitive, .diacriticInsensitive],
                                    locale: nil)
        return Array(folded.utf8)
    }

    // MARK: - Querying

    public struct Match: Sendable, Identifiable {
        public let record: Record
        public let score: Int
        public var id: UUID { record.id }
    }

    /// Ranked search. An empty query returns everything, title-sorted.
    ///
    /// Scoring, highest first: exact field match, prefix match, contiguous substring,
    /// then a subsequence ("fuzzy") match. Earlier fields outrank later ones, so a
    /// title hit always beats a group-path hit.
    /// - Parameter includeRecycleBin: when false, deleted entries are filtered out.
    ///   Filtering happens here rather than at index time so that flipping the
    ///   setting takes effect immediately, with no reindex and no reason for the
    ///   index to be rebuilt while the vault is unlocked.
    public func search(_ query: String, limit: Int = 500,
                       includeRecycleBin: Bool = true) -> [Match] {
        let candidates = includeRecycleBin ? records : records.filter { !$0.isInRecycleBin }
        let needle = Self.fold(query.trimmingCharacters(in: .whitespaces))
        guard !needle.isEmpty else {
            return candidates
                .sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
                .prefix(limit)
                .map { Match(record: $0, score: 0) }
        }

        var matches: [Match] = []
        matches.reserveCapacity(min(candidates.count, limit))

        for record in candidates {
            var best = 0
            for (fieldIndex, haystack) in record.folded.enumerated() {
                guard !haystack.isEmpty else { continue }
                let fieldScore = Self.score(needle: needle, haystack: haystack)
                guard fieldScore > 0 else { continue }
                // Field weighting: title 5×, username 4×, URL 3×, tags 2×, group 1×.
                let weighted = fieldScore * (5 - fieldIndex)
                best = max(best, weighted)
            }
            if best > 0 { matches.append(Match(record: record, score: best)) }
        }

        matches.sort {
            $0.score != $1.score
                ? $0.score > $1.score
                : $0.record.title.localizedStandardCompare($1.record.title) == .orderedAscending
        }
        return Array(matches.prefix(limit))
    }

    /// 0 means no match. Larger is better.
    static func score(needle: [UInt8], haystack: [UInt8]) -> Int {
        guard !needle.isEmpty, needle.count <= haystack.count else {
            return needle.isEmpty ? 1 : 0
        }

        if needle.count == haystack.count, needle == haystack { return 1000 }
        if haystack.starts(with: needle) { return 500 }
        if let _ = firstIndex(of: needle, in: haystack) { return 250 }

        // Subsequence match: every needle byte appears in order, not necessarily
        // adjacent. Scored below any contiguous hit, and bonused for how tightly the
        // characters cluster so "ghb" ranks github.com above a scattered accident.
        var needleIndex = 0
        var lastHit = -1
        var gapPenalty = 0
        for (position, byte) in haystack.enumerated() {
            guard needleIndex < needle.count else { break }
            if byte == needle[needleIndex] {
                if lastHit >= 0 { gapPenalty += position - lastHit - 1 }
                lastHit = position
                needleIndex += 1
            }
        }
        guard needleIndex == needle.count else { return 0 }
        return max(1, 100 - min(gapPenalty, 99))
    }

    /// Byte-wise substring search.
    static func firstIndex(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard !needle.isEmpty, needle.count <= haystack.count else { return nil }
        let last = haystack.count - needle.count
        outer: for start in 0...last {
            for offset in 0..<needle.count where haystack[start + offset] != needle[offset] {
                continue outer
            }
            return start
        }
        return nil
    }
}
