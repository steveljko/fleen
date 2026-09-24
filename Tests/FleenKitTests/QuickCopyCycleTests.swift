import Testing
import Foundation
@testable import FleenKit
@testable import KdbxCore

/// Which click copies what, when quick copy is on.
///
/// Time is injected rather than slept through: a test that waits 15 seconds to prove an
/// expiry is a test nobody runs.
@Suite("Quick copy")
struct QuickCopyCycleTests {

    let entry = UUID()
    let other = UUID()
    let start = Date(timeIntervalSince1970: 1_000_000)

    static let login: [QuickCopyStep] = [.password, .oneTimeCode]
    static let card: [QuickCopyStep] = [.cardNumber, .cardExpiry, .cardSecurityCode]

    // MARK: - Walking a sequence

    @Test("Clicks walk the sequence in order")
    func walksInOrder() {
        var cycle = QuickCopyCycle()
        #expect(cycle.next(for: entry, steps: Self.card, now: start) == .cardNumber)
        #expect(cycle.next(for: entry, steps: Self.card,
                           now: start.addingTimeInterval(1)) == .cardExpiry)
        #expect(cycle.next(for: entry, steps: Self.card,
                           now: start.addingTimeInterval(2)) == .cardSecurityCode)
    }

    /// Past the end it starts over rather than repeating the last step — a stray click
    /// must not leave the clipboard stuck on a security code.
    @Test("Past the end, the sequence starts again")
    func wrapsAround() {
        var cycle = QuickCopyCycle()
        for _ in Self.card { _ = cycle.next(for: entry, steps: Self.card, now: start) }
        #expect(cycle.next(for: entry, steps: Self.card,
                           now: start.addingTimeInterval(1)) == .cardNumber)
    }

    @Test("A login goes password then one-time code")
    func loginOrder() {
        var cycle = QuickCopyCycle()
        #expect(cycle.next(for: entry, steps: Self.login, now: start) == .password)
        #expect(cycle.next(for: entry, steps: Self.login,
                           now: start.addingTimeInterval(1)) == .oneTimeCode)
    }

    /// A single-step entry repeats that step, rather than a second click doing nothing.
    @Test("One step means every click copies it")
    func singleStepRepeats() {
        var cycle = QuickCopyCycle()
        #expect(cycle.next(for: entry, steps: [.password], now: start) == .password)
        #expect(cycle.next(for: entry, steps: [.password],
                           now: start.addingTimeInterval(1)) == .password)
    }

    @Test("An entry with nothing to copy reports nothing")
    func emptySequence() {
        var cycle = QuickCopyCycle()
        #expect(cycle.next(for: entry, steps: [], now: start) == nil)
    }

    // MARK: - The window

    @Test("After the window, a click restarts the sequence", arguments: [15.0, 15.1, 60.0])
    func windowExpires(delay: TimeInterval) {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, steps: Self.card, now: start)
        #expect(cycle.next(for: entry, steps: Self.card,
                           now: start.addingTimeInterval(delay)) == .cardNumber)
    }

    @Test("Just inside the window still advances")
    func justInsideWindow() {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, steps: Self.card, now: start)
        #expect(cycle.next(for: entry, steps: Self.card,
                           now: start.addingTimeInterval(14.9)) == .cardExpiry)
    }

    /// Each click extends the window, so a three-step card does not expire mid-sequence
    /// while the user is pasting.
    @Test("Each step renews the window")
    func windowRenews() {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, steps: Self.card, now: start)
        _ = cycle.next(for: entry, steps: Self.card, now: start.addingTimeInterval(14))
        #expect(cycle.next(for: entry, steps: Self.card,
                           now: start.addingTimeInterval(27)) == .cardSecurityCode)
    }

    // MARK: - Moving between entries

    @Test("Clicking a different entry starts that entry's own sequence")
    func switchingEntriesResets() {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, steps: Self.card, now: start)
        #expect(cycle.next(for: other, steps: Self.login,
                           now: start.addingTimeInterval(1)) == .password)
        #expect(cycle.next(for: entry, steps: Self.card,
                           now: start.addingTimeInterval(2)) == .cardNumber,
                "the first entry lost its turn rather than resuming")
    }

    @Test("Resetting forgets the armed entry")
    func resetClearsState() {
        var cycle = QuickCopyCycle()
        _ = cycle.next(for: entry, steps: Self.card, now: start)
        cycle.reset()
        #expect(cycle.next(for: entry, steps: Self.card,
                           now: start.addingTimeInterval(1)) == .cardNumber)
    }

    @Test("It can say what the next click will copy")
    func reportsUpcoming() {
        var cycle = QuickCopyCycle()
        #expect(cycle.upcomingStep(for: entry, steps: Self.card, now: start) == nil)
        _ = cycle.next(for: entry, steps: Self.card, now: start)
        #expect(cycle.upcomingStep(for: entry, steps: Self.card,
                                   now: start.addingTimeInterval(1)) == .cardExpiry)
        _ = cycle.next(for: entry, steps: Self.card, now: start.addingTimeInterval(1))
        _ = cycle.next(for: entry, steps: Self.card, now: start.addingTimeInterval(2))
        #expect(cycle.upcomingStep(for: entry, steps: Self.card,
                                   now: start.addingTimeInterval(3)) == nil,
                "nothing follows the last step")
    }

    // MARK: - Building the sequence from an entry

    static func makeEntry(_ fields: [String: String], password: String? = nil) -> Entry {
        var values: [String: FieldValue] = [Entry.titleField: .plain("Thing")]
        if let password { values[Entry.passwordField] = .makeProtected(password) }
        for (k, v) in fields { values[k] = FieldValue.makeProtected(v) }
        return Entry(fields: values)
    }

    @Test("A login's sequence is password then code")
    func loginSequence() {
        let entry = Self.makeEntry(["otp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"],
                                   password: "hunter2")
        #expect(QuickCopyStep.sequence(for: entry) == [.password, .oneTimeCode])
    }

    @Test("A login with no code offers only the password")
    func loginWithoutCode() {
        let entry = Self.makeEntry([:], password: "hunter2")
        #expect(QuickCopyStep.sequence(for: entry) == [.password])
    }

    @Test("A card marked with a type field offers number, expiry, then code")
    func cardSequence() {
        let entry = Self.makeEntry([
            "Type": "card",
            "Card Number": "4111111111111111",
            "Expiry": "09/28",
            "CVV": "123",
        ])
        #expect(entry.kind == .card)
        #expect(QuickCopyStep.sequence(for: entry)
                == [.cardNumber, .cardExpiry, .cardSecurityCode])
    }

    @Test("Card type is recognised however it is written", arguments: [
        ("Type", "card"), ("type", "Card"), ("Category", "Credit Card"),
        ("Kind", "debit card"), ("Type", "payment card"),
    ])
    func cardTypeVariants(label: String, value: String) {
        let entry = Self.makeEntry([label: value, "Card Number": "4111111111111111"])
        #expect(entry.kind == .card, "\(label): \(value) should mark a card")
    }

    /// The marker wins even over a password, because the user said what it is.
    @Test("A declared card with a password is still a card")
    func declaredCardBeatsPassword() {
        let entry = Self.makeEntry(["Type": "card", "Card Number": "4111111111111111"],
                                   password: "hunter2")
        #expect(entry.kind == .card)
        #expect(QuickCopyStep.sequence(for: entry) == [.cardNumber])
    }

    /// Without a marker, a card number and no password is treated as a card — the login
    /// behaviour would otherwise try to copy a password that does not exist.
    @Test("An unmarked card with no password is still treated as a card")
    func unmarkedCardFallback() {
        let entry = Self.makeEntry(["Card Number": "4111111111111111", "CVV": "123"])
        #expect(entry.kind == .card)
        #expect(QuickCopyStep.sequence(for: entry) == [.cardNumber, .cardSecurityCode],
                "the missing expiry is skipped rather than producing a dead click")
    }

    /// The important negative: an ordinary login must not become a card.
    @Test("A login is not reclassified as a card")
    func loginStaysLogin() {
        let entry = Self.makeEntry(["Recovery code": "abcd"], password: "hunter2")
        #expect(entry.kind == .login)
    }

    @Test("A type field naming something else leaves it a login")
    func otherDeclaredTypesAreLogins() {
        let entry = Self.makeEntry(["Type": "server"], password: "hunter2")
        #expect(entry.kind == .login)
    }

    @Test("An entry with nothing copyable yields an empty sequence")
    func nothingCopyable() {
        let entry = Self.makeEntry(["Note": "just a note"])
        #expect(QuickCopyStep.sequence(for: entry).isEmpty)
    }
}
