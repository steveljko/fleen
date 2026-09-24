import Testing
import Foundation
import CryptoKit
@testable import FleenKit
@testable import KdbxCore

/// Proves Fleen never modifies the database file.
///
/// The claim "Fleen is read-only" is only worth as much as something that checks it, so
/// this drives a full session — select, unlock, search, browse, read attachments,
/// reveal passwords, reload, lock — against a real file and then asserts the bytes and
/// the modification date are unchanged. If a write path is ever reintroduced, this goes
/// red regardless of which layer added it.
@MainActor
@Suite("File immutability")
struct FileImmutabilityTests {

    static let password = "correct horse battery staple"

    static func digest(of url: URL) throws -> String {
        SHA256.hash(data: try Data(contentsOf: url))
            .map { String(format: "%02x", $0) }.joined()
    }

    static func modificationDate(of url: URL) throws -> Date? {
        try FileManager.default.attributesOfItem(atPath: url.path)[.modificationDate] as? Date
    }

    /// A writable copy of a fixture, so the fixture itself is never at risk.
    static func temporaryCopy(of fixture: String) throws -> URL {
        guard let source = Bundle.module.url(forResource: "Fixtures/\(fixture)",
                                             withExtension: nil) else {
            throw Failure.fixtureMissing(fixture)
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("fleen-immutable-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let destination = directory.appendingPathComponent(fixture)
        try FileManager.default.copyItem(at: source, to: destination)
        return destination
    }

    enum Failure: Error { case fixtureMissing(String) }

    static func makeSession() -> VaultSession {
        let suite = "com.fleen.tests.\(UUID().uuidString)"
        return VaultSession(preferences: Preferences(defaults: UserDefaults(suiteName: suite)!))
    }

    @Test("A full session leaves the file byte-identical")
    func fullSessionDoesNotTouchTheFile() async throws {
        let url = try Self.temporaryCopy(of: "pkp-recyclebin.kdbx")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let before = try Self.digest(of: url)
        let beforeDate = try Self.modificationDate(of: url)

        let session = Self.makeSession()
        try session.select(url: url)
        await session.unlock(password: Self.password)
        try #require(session.state.isUnlocked)

        // Exercise every read the app performs.
        _ = session.search("")
        _ = session.search("Keeper")
        _ = session.index.records.map(\.title)
        for entry in session.database?.allEntries ?? [] {
            _ = entry.password?.reveal()
            _ = entry.totp?.code()
            for reference in entry.attachments {
                _ = session.database?.attachment(for: reference)?.data
            }
        }
        if let root = session.database?.rootGroup {
            _ = VaultTree.flatten(root: root,
                                  expanded: VaultTree.allGroupIDs(root: root),
                                  recycleBinID: session.recycleBinGroupID,
                                  showsRecycleBin: true)
        }

        await session.reload()
        session.lock()

        #expect(try Self.digest(of: url) == before,
                "opening a database must never rewrite it")
        #expect(try Self.modificationDate(of: url) == beforeDate,
                "even the modification date must be untouched")
    }

    @Test("Repeated unlock and lock cycles leave the file alone")
    func repeatedCyclesDoNotTouchTheFile() async throws {
        let url = try Self.temporaryCopy(of: "pkp-aes-argon2d.kdbx")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let before = try Self.digest(of: url)
        let session = Self.makeSession()
        try session.select(url: url)

        for _ in 0..<3 {
            await session.unlock(password: Self.password)
            #expect(session.state.isUnlocked)
            session.lock()
        }

        #expect(try Self.digest(of: url) == before)
    }

    @Test("A failed unlock does not touch the file either")
    func failedUnlockDoesNotTouchTheFile() async throws {
        let url = try Self.temporaryCopy(of: "pkp-aes-argon2d.kdbx")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let before = try Self.digest(of: url)
        let session = Self.makeSession()
        try session.select(url: url)
        await session.unlock(password: "wrong password")

        #expect(!session.state.isUnlocked)
        #expect(try Self.digest(of: url) == before)
    }

    @Test("The database is never deleted or moved")
    func fileIsNeverRemoved() async throws {
        let url = try Self.temporaryCopy(of: "pkp-aes-argon2d.kdbx")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let session = Self.makeSession()
        try session.select(url: url)
        await session.unlock(password: Self.password)
        session.lock()

        // `forgetDatabase` forgets the *location*; it must not remove the file.
        #expect(FileManager.default.fileExists(atPath: url.path))
    }

    @Test("Deleted entries stay deleted — the recycle bin is only ever read")
    func recycleBinIsReadOnly() async throws {
        let url = try Self.temporaryCopy(of: "pkp-recyclebin.kdbx")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let session = Self.makeSession()
        try session.select(url: url)
        await session.unlock(password: Self.password)

        // Fleen can show or hide the bin, and that is the whole extent of its
        // involvement: there is no API to empty it, restore from it, or add to it.
        let hidden = session.search("Deleted")
        #expect(hidden.isEmpty, "hidden by default")

        let database = try #require(session.database)
        let binID = try #require(session.recycleBinGroupID)
        let bin = try #require(database.group(withID: binID))
        #expect(bin.entries.count == 2, "the bin's contents are untouched")
    }
}
