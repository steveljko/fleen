import Testing
import Foundation
@testable import FleenKit
@testable import KdbxCore

/// The tree flattening is pure logic, so it is tested directly rather than through the
/// view. These pin the shape KeePassXC users expect: folders before entries, children
/// only when open, and indentation that matches real depth.
@Suite("Vault tree")
struct VaultTreeShapeTests {

    /// Root
    ///   Personal            (2 entries, 1 subgroup)
    ///     Nested           (1 entry)
    ///   Work               (1 entry)
    ///   Loose Entry        (directly in root)
    static func database() -> Database {
        func entry(_ title: String) -> Entry {
            var e = Entry(); e.title = title; e.password = .makeProtected("p"); return e
        }

        var nested = Group(name: "Nested")
        nested.entries = [entry("Nested Entry")]

        var personal = Group(name: "Personal")
        personal.groups = [nested]
        personal.entries = [entry("Bank"), entry("Airline")]

        var work = Group(name: "Work")
        work.entries = [entry("Intranet")]

        var root = Group(name: "Root")
        root.groups = [personal, work]
        root.entries = [entry("Loose Entry")]
        return Database(rootGroup: root)
    }

    static func titles(_ nodes: [VaultTree.Node]) -> [String] {
        nodes.map(\.title)
    }

    /// Flattens a whole database, the way the view does.
    static func flatten(_ database: Database, expanded: Set<UUID>,
                        showsRecycleBin: Bool = false) -> [VaultTree.Node] {
        let binID = database.meta.recycleBinUUID.flatMap { id -> UUID? in
            id == SearchIndex.zeroUUID ? nil : id
        }
        return VaultTree.flatten(root: database.rootGroup, expanded: expanded,
                                 recycleBinID: binID, showsRecycleBin: showsRecycleBin)
    }

    @Test("Collapsed, only the top level shows")
    func collapsedShowsTopLevelOnly() {
        let nodes = Self.flatten(Self.database(), expanded: [])
        // Folders first, alphabetical, then the root's own entries.
        #expect(Self.titles(nodes) == ["Personal", "Work", "Loose Entry"])
        #expect(nodes.allSatisfy { $0.depth == 0 })
    }

    @Test("Expanding a folder reveals its subfolders and entries, indented")
    func expandingRevealsChildren() throws {
        let database = Self.database()
        let personal = try #require(database.rootGroup.groups.first { $0.name == "Personal" })

        let nodes = Self.flatten(database, expanded: [personal.id])
        // "Bank" before "Airline": the database's own order, not alphabetical. That
        // order is the user's arrangement in KeePassXC and must survive.
        #expect(Self.titles(nodes) == ["Personal", "Nested", "Bank", "Airline",
                                       "Work", "Loose Entry"])

        // Children sit one level in; siblings of Personal stay at the top level.
        let byTitle = Dictionary(uniqueKeysWithValues: nodes.map { ($0.title, $0.depth) })
        #expect(byTitle["Personal"] == 0)
        #expect(byTitle["Nested"] == 1)
        #expect(byTitle["Airline"] == 1)
        #expect(byTitle["Work"] == 0)
    }

    @Test("Nesting continues to depth, one level at a time")
    func nestsDeeply() throws {
        let database = Self.database()
        let personal = try #require(database.rootGroup.groups.first { $0.name == "Personal" })
        let nested = try #require(personal.groups.first)

        let nodes = Self.flatten(database, expanded: [personal.id, nested.id])
        let byTitle = Dictionary(uniqueKeysWithValues: nodes.map { ($0.title, $0.depth) })
        #expect(byTitle["Nested"] == 1)
        #expect(byTitle["Nested Entry"] == 2)
    }

    @Test("A collapsed parent hides its whole subtree, even if the child is expanded")
    func collapsedParentHidesExpandedChild() throws {
        let database = Self.database()
        let personal = try #require(database.rootGroup.groups.first { $0.name == "Personal" })
        let nested = try #require(personal.groups.first)

        // Nested is marked open but Personal is not: nothing under Personal shows.
        let nodes = Self.flatten(database, expanded: [nested.id])
        #expect(!Self.titles(nodes).contains("Nested"))
        #expect(!Self.titles(nodes).contains("Nested Entry"))
    }

    @Test("Every node knows its parent, for collapse-and-go-up navigation")
    func recordsParents() throws {
        let database = Self.database()
        let personal = try #require(database.rootGroup.groups.first { $0.name == "Personal" })

        let nodes = Self.flatten(database, expanded: [personal.id])
        let bank = try #require(nodes.first { $0.title == "Bank" })
        #expect(bank.parentID == personal.id)

        let top = try #require(nodes.first { $0.title == "Personal" })
        #expect(top.parentID == database.rootGroup.id)
    }

    @Test("Initial expansion follows the database's own IsExpanded flags")
    func seedsFromDatabaseFlags() throws {
        var nested = Group(name: "Nested")
        nested.isExpanded = false
        var personal = Group(name: "Personal")
        personal.isExpanded = true
        personal.groups = [nested]
        var root = Group(name: "Root")
        root.groups = [personal]

        // KeePassXC writes this flag when the user expands a group, so honouring it
        // means the tree opens the way they left it there.
        let expanded = VaultTree.initiallyExpanded(root: root)
        #expect(expanded.contains(personal.id))
        #expect(!expanded.contains(nested.id))
    }

    @Test("The recycle bin is hidden from the tree unless shown")
    func hidesRecycleBin() throws {
        var bin = Group(name: "Recycle Bin")
        bin.entries = [{ var e = Entry(); e.title = "Deleted"; return e }()]
        var root = Group(name: "Root")
        root.groups = [bin]

        var meta = DatabaseMeta()
        meta.recycleBinUUID = bin.id
        let database = Database(meta: meta, rootGroup: root)

        let hidden = Self.flatten(database, expanded: [bin.id], showsRecycleBin: false)
        #expect(!Self.titles(hidden).contains("Recycle Bin"))

        let shown = Self.flatten(database, expanded: [bin.id], showsRecycleBin: true)
        #expect(Self.titles(shown).contains("Recycle Bin"))
        #expect(Self.titles(shown).contains("Deleted"))
    }

    @Test("Folder and entry order follows the file, not the alphabet")
    func preservesStoredOrder() throws {
        func entry(_ title: String) -> Entry {
            var e = Entry(); e.title = title; return e
        }
        // Deliberately reverse-alphabetical in the file.
        var zebra = Group(name: "Zebra")
        var apple = Group(name: "Apple")
        zebra.entries = [entry("Zulu"), entry("Alpha")]
        apple.entries = [entry("Yankee")]

        var root = Group(name: "Root")
        root.groups = [zebra, apple]
        root.entries = [entry("Zeta"), entry("Beta")]

        let nodes = Self.flatten(Database(rootGroup: root),
                                 expanded: [zebra.id, apple.id])
        #expect(Self.titles(nodes) == ["Zebra", "Zulu", "Alpha",
                                       "Apple", "Yankee",
                                       "Zeta", "Beta"])
    }

    @Test("Drill-down lists one level, folders first, in file order")
    func childrenListsOneLevel() throws {
        let database = Self.database()
        let nodes = VaultTree.children(of: database.rootGroup,
                                       recycleBinID: nil, showsRecycleBin: false)

        // Only the immediate contents — nothing from inside Personal.
        #expect(Self.titles(nodes) == ["Personal", "Work", "Loose Entry"])
        #expect(nodes.allSatisfy { $0.depth == 0 })
        #expect(nodes.allSatisfy { $0.parentID == database.rootGroup.id })
    }

    @Test("Drill-down hides the recycle bin unless shown")
    func childrenRespectsRecycleBin() throws {
        var bin = Group(name: "Recycle Bin")
        bin.entries = [{ var e = Entry(); e.title = "Deleted"; return e }()]
        var root = Group(name: "Root")
        root.groups = [bin]

        let hidden = VaultTree.children(of: root, recycleBinID: bin.id,
                                        showsRecycleBin: false)
        #expect(Self.titles(hidden).isEmpty)

        let shown = VaultTree.children(of: root, recycleBinID: bin.id,
                                       showsRecycleBin: true)
        #expect(Self.titles(shown) == ["Recycle Bin"])
    }

    @Test("A real database flattens without losing entries")
    func flattensRealFixture() throws {
        guard let url = Bundle.module.url(forResource: "Fixtures/pkp-aes-argon2d.kdbx",
                                          withExtension: nil) else { return }
        var key = CompositeKey()
        key.addPassword("correct horse battery staple")
        let database = try KdbxFile.open(url: url, credentials: key)

        let allGroups = Set(database.rootGroup.allGroups().map(\.id))
            .subtracting([database.rootGroup.id])
        let nodes = Self.flatten(database, expanded: allGroups)

        // Fully expanded, every entry and every folder is present exactly once.
        let entryCount = nodes.filter { !$0.isGroup }.count
        #expect(entryCount == database.entryCount)
        #expect(nodes.filter(\.isGroup).count == allGroups.count)
    }
}
