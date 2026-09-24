import Testing
import Foundation
@testable import FleenKit
@testable import KdbxCore

/// The "Show Recycle Bin" setting, end to end over a real database whose bin was
/// populated by another implementation.
@Suite("Recycle bin")
struct RecycleBinTests {

    static func fixture() throws -> Database {
        guard let url = Bundle.module.url(forResource: "Fixtures/pkp-recyclebin.kdbx",
                                          withExtension: nil) else {
            throw FixtureMissing()
        }
        var key = CompositeKey()
        key.addPassword("correct horse battery staple")
        return try KdbxFile.open(url: url, credentials: key)
    }

    struct FixtureMissing: Error {}

    @Test("The recycle bin group is located from database metadata")
    func findsRecycleBin() throws {
        let index = SearchIndex(database: try Self.fixture())
        let binID = try #require(index.recycleBinGroupID,
                                 "the fixture's Meta names a recycle bin; it must be found")

        let database = try Self.fixture()
        #expect(database.group(withID: binID)?.name == "Recycle Bin")
    }

    @Test("Deleted entries are marked, live ones are not")
    func marksDeletedEntries() throws {
        let index = SearchIndex(database: try Self.fixture())

        let keeper = try #require(index.records.first { $0.title == "Keeper" })
        #expect(!keeper.isInRecycleBin)

        let deleted = index.records.filter { $0.isInRecycleBin }
        #expect(Set(deleted.map(\.title)) == ["Deleted Entry", "Also Deleted"])
    }

    @Test("Hiding the bin removes deleted entries from search")
    func filtersSearchWhenHidden() throws {
        let index = SearchIndex(database: try Self.fixture())

        let hidden = index.search("Deleted", includeRecycleBin: false)
        #expect(hidden.isEmpty, "a deleted entry must not surface when the bin is hidden")

        let shown = index.search("Deleted", includeRecycleBin: true)
        #expect(shown.count == 2)
    }

    @Test("Hiding the bin does not hide live entries")
    func keepsLiveEntriesWhenHidden() throws {
        let index = SearchIndex(database: try Self.fixture())
        let results = index.search("Keeper", includeRecycleBin: false)
        #expect(results.count == 1)
        #expect(results.first?.record.title == "Keeper")
    }

    @Test("An empty query also respects the setting")
    func filtersBrowseListingWhenHidden() throws {
        let index = SearchIndex(database: try Self.fixture())
        // The empty-query path takes a different branch through search(); it has to
        // filter too, or the browse listing would leak what search hides.
        #expect(index.search("", includeRecycleBin: false).count == 1)
        #expect(index.search("", includeRecycleBin: true).count == 3)
    }

    @Test("A database with no recycle bin is unaffected")
    func noRecycleBinIsHarmless() throws {
        var key = CompositeKey()
        key.addPassword("correct horse battery staple")
        guard let url = Bundle.module.url(forResource: "Fixtures/pkp-aes-argon2d.kdbx",
                                          withExtension: nil) else { throw FixtureMissing() }
        let database = try KdbxFile.open(url: url, credentials: key)
        let index = SearchIndex(database: database)

        #expect(index.recycleBinGroupID == nil,
                "this fixture never had anything deleted, so there is no bin group")
        #expect(index.records.allSatisfy { !$0.isInRecycleBin })
        // Hiding the bin must not hide anything when there is no bin.
        #expect(index.search("", includeRecycleBin: false).count == index.records.count)
    }

    @Test("An all-zero recycle bin UUID means 'no bin', not a group to find")
    func treatsZeroUUIDAsAbsent() throws {
        // KDBX writes a zero UUID rather than omitting the field, so a naive lookup
        // would go hunting for a group that cannot exist.
        var database = try Self.fixture()
        database.meta.recycleBinUUID = SearchIndex.zeroUUID

        let index = SearchIndex(database: database)
        #expect(index.recycleBinGroupID == nil)
        #expect(index.records.allSatisfy { !$0.isInRecycleBin })
    }

    @Test("The preference defaults to hiding deleted entries")
    func defaultsToHidden() {
        let suite = "com.fleen.tests.\(UUID().uuidString)"
        let preferences = Preferences(defaults: UserDefaults(suiteName: suite)!)
        #expect(!preferences.showRecycleBin)

        preferences.showRecycleBin = true
        #expect(preferences.showRecycleBin)
    }
}
