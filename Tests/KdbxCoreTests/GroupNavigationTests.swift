import Testing
import Foundation
@testable import KdbxCore

/// Covers the tree lookups the browse UI navigates with.
@Suite("Group navigation")
struct GroupNavigationTests {

    static func tree() -> Database {
        var deep = Group(name: "Deep")
        deep.entries = [{ var e = Entry(); e.title = "Buried"; return e }()]

        var nested = Group(name: "Nested")
        nested.groups = [deep]

        var personal = Group(name: "Personal")
        personal.groups = [nested]
        personal.entries = [{ var e = Entry(); e.title = "Top"; return e }()]

        var work = Group(name: "Work")

        var root = Group(name: "Root")
        root.groups = [personal, work]
        return Database(rootGroup: root)
    }

    @Test("A group is found anywhere in the tree")
    func findsGroupAtAnyDepth() throws {
        let database = Self.tree()
        let deep = try #require(database.rootGroup.groups[0].groups[0].groups.first)

        let found = try #require(database.group(withID: deep.id))
        #expect(found.name == "Deep")

        // The root finds itself.
        #expect(database.group(withID: database.rootGroup.id)?.name == "Root")
    }

    @Test("An unknown identifier finds nothing")
    func missingGroupReturnsNil() {
        #expect(Self.tree().group(withID: UUID()) == nil)
    }

    @Test("The path to a group runs root-first and includes the group itself")
    func buildsBreadcrumbTrail() throws {
        let database = Self.tree()
        let deep = try #require(database.rootGroup.groups[0].groups[0].groups.first)

        let trail = try #require(database.path(toGroup: deep.id))
        #expect(trail.map(\.name) == ["Root", "Personal", "Nested", "Deep"])
    }

    @Test("The path to the root is just the root")
    func rootTrailIsSingleElement() throws {
        let database = Self.tree()
        let trail = try #require(database.path(toGroup: database.rootGroup.id))
        #expect(trail.map(\.name) == ["Root"])
    }

    @Test("The path to an unknown group is nil, not an empty array")
    func missingPathReturnsNil() {
        // Nil and [] would mean different things to the breadcrumb bar; make sure the
        // "not in this database" case is distinguishable from "at the root".
        #expect(Self.tree().path(toGroup: UUID()) == nil)
    }

    @Test("Navigating up from each level reaches the root without looping")
    func walksUpToRoot() throws {
        let database = Self.tree()
        let deep = try #require(database.rootGroup.groups[0].groups[0].groups.first)

        var current = deep.id
        var visited: [String] = []
        var guardCount = 0

        while let trail = database.path(toGroup: current), trail.count > 1, guardCount < 10 {
            visited.append(trail.last!.name)
            current = trail[trail.count - 2].id
            guardCount += 1
        }

        #expect(visited == ["Deep", "Nested", "Personal"])
        #expect(current == database.rootGroup.id)
    }

    @Test("The path to an entry names its enclosing folders, root first")
    func buildsTrailToEntry() throws {
        let database = Self.tree()
        let buried = try #require(database.allEntries.first { $0.title == "Buried" })

        let trail = try #require(database.path(toEntry: buried.id))
        #expect(trail.map(\.name) == ["Root", "Personal", "Nested", "Deep"])
    }

    @Test("An entry directly in a group returns just that chain")
    func buildsShallowEntryTrail() throws {
        let database = Self.tree()
        let top = try #require(database.allEntries.first { $0.title == "Top" })
        #expect(database.path(toEntry: top.id)?.map(\.name) == ["Root", "Personal"])
    }

    @Test("The path to an unknown entry is nil")
    func missingEntryPathReturnsNil() {
        #expect(Self.tree().path(toEntry: UUID()) == nil)
    }

    @Test("Group lookups work on a real database from disk")
    func worksOnRealFixture() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")
        let personal = try #require(database.rootGroup.groups.first { $0.name == "Personal" })
        let nested = try #require(personal.groups.first)

        let trail = try #require(database.path(toGroup: nested.id))
        #expect(trail.count == 3)
        #expect(trail[1].name == "Personal")
        #expect(trail.last?.name == nested.name)
    }
}
