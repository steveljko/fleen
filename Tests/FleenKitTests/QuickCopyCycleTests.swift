import Testing
import Foundation
@testable import FleenKit

/// Which click copies what, when quick copy is on.
///
/// Time is injected rather than slept through: a test that waits 15 seconds to prove an
/// expiry is a test nobody runs.
@Suite("Quick copy")
struct QuickCopyCycleTests {

    let entry = UUID()
    let other = UUID()
    let start = Date(timeIntervalSince1970: 1_000_000)

    @Test("The first click copies the password")
    func firstClickCopiesPassword() {
        var cycle = QuickCopyCycle()
        #expect(cycle.next(for: entry, hasOneTimeCode: true, now: start) == .password)
    }

    @Test("A second click on the same entry copies the one-time code")
    func secondClickCopiesCode() {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, hasOneTimeCode: true, now: start)
        #expect(cycle.next(for: entry, hasOneTimeCode: true,
                           now: start.addingTimeInterval(3)) == .oneTimeCode)
    }

    /// The cycle is spent once the code is taken, so the next click starts over.
    @Test("A third click starts again with the password")
    func thirdClickStartsOver() {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, hasOneTimeCode: true, now: start)
        _ = cycle.next(for: entry, hasOneTimeCode: true, now: start.addingTimeInterval(1))
        #expect(cycle.next(for: entry, hasOneTimeCode: true,
                           now: start.addingTimeInterval(2)) == .password)
    }

    @Test("After the window, a click is a fresh start", arguments: [15.0, 15.1, 60.0])
    func windowExpires(delay: TimeInterval) {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, hasOneTimeCode: true, now: start)
        #expect(cycle.next(for: entry, hasOneTimeCode: true,
                           now: start.addingTimeInterval(delay)) == .password)
    }

    @Test("Just inside the window still offers the code")
    func justInsideWindow() {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, hasOneTimeCode: true, now: start)
        #expect(cycle.next(for: entry, hasOneTimeCode: true,
                           now: start.addingTimeInterval(14.9)) == .oneTimeCode)
    }

    /// Without a code, a second click must still do something visible.
    @Test("An entry with no code copies the password every time")
    func noCodeRepeatsPassword() {
        var cycle = QuickCopyCycle()
        #expect(cycle.next(for: entry, hasOneTimeCode: false, now: start) == .password)
        #expect(cycle.next(for: entry, hasOneTimeCode: false,
                           now: start.addingTimeInterval(1)) == .password)
    }

    /// Moving to another entry mid-cycle must not hand over the first entry's turn.
    @Test("Clicking a different entry starts that entry's own cycle")
    func switchingEntriesResets() {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, hasOneTimeCode: true, now: start)
        #expect(cycle.next(for: other, hasOneTimeCode: true,
                           now: start.addingTimeInterval(1)) == .password)
        // ...and the first entry has lost its turn, rather than resuming.
        #expect(cycle.next(for: entry, hasOneTimeCode: true,
                           now: start.addingTimeInterval(2)) == .password)
    }

    @Test("Resetting forgets the armed entry")
    func resetClearsState() {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, hasOneTimeCode: true, now: start)
        cycle.reset()
        #expect(cycle.next(for: entry, hasOneTimeCode: true,
                           now: start.addingTimeInterval(1)) == .password)
    }

    @Test("It can say whether the next click would copy the code")
    func reportsNextStep() {
        var cycle = QuickCopyCycle()
        #expect(!cycle.offersCodeNext(for: entry, now: start))
        _ = cycle.next(for: entry, hasOneTimeCode: true, now: start)
        #expect(cycle.offersCodeNext(for: entry, now: start.addingTimeInterval(5)))
        #expect(!cycle.offersCodeNext(for: other, now: start.addingTimeInterval(5)))
        #expect(!cycle.offersCodeNext(for: entry, now: start.addingTimeInterval(20)))
    }
}
