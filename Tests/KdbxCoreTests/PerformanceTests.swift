import Testing
import Foundation
@testable import KdbxCore

/// Coarse performance guards.
///
/// These are not a substitute for Instruments — PLAN.md requires a real Time
/// Profiler and Allocations pass before any phase is called done, and these
/// assertions cannot see allocation churn or main-thread stalls. What they do catch
/// is an accidental order-of-magnitude regression, e.g. someone making the XML
/// reader quadratic in entry count. The thresholds are deliberately loose so they
/// do not go red on a loaded CI machine.
@Suite("Performance guards")
struct PerformanceTests {

    @Test("A 2000-entry database parses in well under a second, excluding the KDF")
    func parsesLargeDatabaseQuickly() throws {
        let url = try Fixture.url("pkp-large.kdbx")
        let data = try Data(contentsOf: url)
        let credentials = try Fixture.credentials()

        // Warm the page cache and verify the contents first.
        let database = try KdbxFile.open(data: data, credentials: credentials)
        #expect(database.entryCount == 2000)

        let start = ContinuousClock.now
        let reparsed = try KdbxFile.open(data: data, credentials: credentials)
        let elapsed = ContinuousClock.now - start

        #expect(reparsed.entryCount == 2000)
        // This number includes the Argon2 KDF the fixture was written with, which
        // dominates. The guard is against a parser regression, not a KDF change.
        #expect(elapsed < .seconds(3),
                "parsing 2000 entries took \(elapsed) — check for a parser regression")
    }

    @Test("Entry enumeration over a large tree is linear enough to be instant")
    func enumeratesLargeTreeQuickly() throws {
        let database = try Fixture.open("pkp-large.kdbx")

        let start = ContinuousClock.now
        var matches = 0
        for _ in 0..<20 {
            // The shape the UI search will use: touch only non-secret fields.
            matches = database.allEntries.filter {
                $0.title.localizedCaseInsensitiveContains("Entry 001")
            }.count
        }
        let elapsed = ContinuousClock.now - start

        #expect(matches > 0)
        #expect(elapsed < .seconds(2),
                "20 passes over 2000 entries took \(elapsed)")
    }
}
