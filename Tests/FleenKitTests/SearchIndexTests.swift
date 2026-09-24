import Testing
import Foundation
@testable import FleenKit
@testable import KdbxCore

@Suite("Search index")
struct SearchIndexTests {

    static func entry(_ title: String, username: String = "", url: String = "",
                      tags: [String] = [], password: String = "secret") -> Entry {
        var entry = Entry()
        entry.title = title
        entry.username = username
        entry.url = url
        entry.tags = tags
        entry.password = .makeProtected(password)
        return entry
    }

    static func database(_ entries: [Entry]) -> Database {
        var work = Group(name: "Work")
        work.entries = entries
        var root = Group(name: "Root")
        root.groups = [work]
        return Database(rootGroup: root)
    }

    static let sample = database([
        entry("GitHub", username: "octocat", url: "https://github.com", tags: ["dev"]),
        entry("GitLab", username: "fox", url: "https://gitlab.com", tags: ["dev"]),
        entry("Bank of Example", username: "alice", url: "https://bank.example.com"),
        entry("Émile's Café", username: "emile"),
        entry("Expired Thing", username: "old"),
    ])

    @Test("Secrets are never placed in the index")
    func indexHoldsNoSecrets() throws {
        let index = SearchIndex(database: Self.sample)

        // A protected password must not be reachable through any indexed haystack.
        for record in index.records {
            for haystack in record.folded {
                let text = String(decoding: haystack, as: UTF8.self)
                #expect(!text.contains("secret"),
                        "the index leaked a password into field text: \(text)")
            }
        }

        // And searching for the password must find nothing.
        #expect(index.search("secret").isEmpty)
    }

    @Test("Exact, prefix and substring matches rank above fuzzy ones")
    func ranksMatchQuality() throws {
        let index = SearchIndex(database: Self.sample)

        let exact = try #require(index.search("GitHub").first)
        #expect(exact.record.title == "GitHub")

        // "git" prefixes both GitHub and GitLab; both should appear.
        let prefix = index.search("git")
        #expect(prefix.count >= 2)
        #expect(prefix.allSatisfy { $0.record.title.hasPrefix("Git") })

        // A subsequence match still finds it, but scores below a prefix match.
        let fuzzy = try #require(index.search("gthb").first)
        #expect(fuzzy.record.title == "GitHub")
        #expect(fuzzy.score < exact.score)
    }

    @Test("Title matches outrank group and URL matches")
    func weightsFieldsByImportance() throws {
        let index = SearchIndex(database: Self.sample)
        let results = index.search("bank")
        let first = try #require(results.first)
        #expect(first.record.title == "Bank of Example",
                "a title hit must outrank a URL hit for the same term")
    }

    @Test("Search is case- and diacritic-insensitive")
    func foldsCaseAndDiacritics() throws {
        let index = SearchIndex(database: Self.sample)
        #expect(index.search("github").first?.record.title == "GitHub")
        #expect(index.search("GITHUB").first?.record.title == "GitHub")
        #expect(index.search("emile").first?.record.title == "Émile's Café")
        #expect(index.search("cafe").first?.record.title == "Émile's Café")
    }

    @Test("Username, URL, tag and group all match")
    func searchesEveryIndexedField() throws {
        let index = SearchIndex(database: Self.sample)
        #expect(index.search("octocat").first?.record.title == "GitHub")
        #expect(index.search("gitlab.com").first?.record.title == "GitLab")
        #expect(index.search("dev").count >= 2)
        #expect(index.search("Work").count == 5, "the group name should match every entry in it")
        #expect(index.search("Root").isEmpty,
                "the root group's name is not part of any entry's path")
    }

    @Test("An empty query returns everything, sorted by title")
    func emptyQueryListsAll() throws {
        let index = SearchIndex(database: Self.sample)
        let all = index.search("   ")
        #expect(all.count == 5)
        #expect(all.map(\.record.title) == all.map(\.record.title)
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending })
    }

    @Test("A query matching nothing returns nothing")
    func noMatches() throws {
        let index = SearchIndex(database: Self.sample)
        #expect(index.search("zzzzzzqqqq").isEmpty)
    }

    @Test("Group path is recorded for nested groups")
    func recordsGroupPath() throws {
        var inner = Group(name: "Inner")
        inner.entries = [Self.entry("Nested Entry")]
        var outer = Group(name: "Outer")
        outer.groups = [inner]
        var root = Group(name: "Root")
        root.groups = [outer]

        let index = SearchIndex(database: Database(rootGroup: root))
        let record = try #require(index.records.first)
        // The root group is excluded: its name is plumbing, not somewhere the user
        // filed anything.
        #expect(record.groupPath == "Outer › Inner")
    }

    @Test("Searching 10,000 entries stays interactive")
    func scalesToLargeDatabases() throws {
        var group = Group(name: "Bulk")
        group.entries = (0..<10_000).map {
            Self.entry("Entry \($0)", username: "user\($0)@example.com",
                       url: "https://site\($0 % 500).example.com")
        }
        var root = Group(name: "Root")
        root.groups = [group]

        let buildStart = ContinuousClock.now
        let index = SearchIndex(database: Database(rootGroup: root))
        let buildTime = ContinuousClock.now - buildStart
        #expect(index.records.count == 10_000)

        // The per-keystroke cost is what has to stay small. Simulate typing.
        let searchStart = ContinuousClock.now
        for query in ["e", "en", "ent", "entr", "entry", "entry 1", "entry 12", "entry 123"] {
            _ = index.search(query)
        }
        let searchTime = ContinuousClock.now - searchStart

        // Generous thresholds: these catch an algorithmic regression, not a slow CI box.
        #expect(buildTime < .seconds(3), "index build took \(buildTime)")
        #expect(searchTime < .seconds(2), "8 keystrokes over 10k entries took \(searchTime)")
    }
}
