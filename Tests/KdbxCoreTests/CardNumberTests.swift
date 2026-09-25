import Testing
import Foundation
@testable import KdbxCore

/// Recognising a card number in a custom field, so it can be masked and grouped.
///
/// The negative cases matter most: masking a field that is *not* a card number hides a
/// value the user needs to read, and there is nothing on screen to explain why.
@Suite("Card numbers")
struct CardNumberTests {

    /// Numbers published by the networks as test data — none is a real account.
    static func detect(_ label: String, _ number: String) -> CardNumber? {
        CardNumber.detect(label: label, value: .makeProtected(number))
    }

    // MARK: - Masking, which is the whole point

    @Test("A hidden card number reads as **** **** **** 1234")
    func maskedForm() throws {
        let card = try #require(Self.detect("Card Number", "4111111111111111"))
        #expect(card.masked == "**** **** **** 1111")
        #expect(card.grouped == "4111 1111 1111 1111")
        #expect(card.digits == "4111111111111111")
    }

    @Test("Spaces already in the stored value do not disturb the grouping")
    func toleratesStoredFormatting() throws {
        let card = try #require(Self.detect("Card Number", "4111 1111 1111 1111"))
        #expect(card.masked == "**** **** **** 1111")
        #expect(card.digits == "4111111111111111", "copying gives bare digits")
    }

    /// Amex is 15 digits printed 4-6-5, so forcing 4-4-4-4 on it would look wrong.
    @Test("Amex keeps its own 4-6-5 grouping")
    func amexGrouping() throws {
        let card = try #require(Self.detect("Card Number", "378282246310005"))
        #expect(card.grouped == "3782 822463 10005")
        #expect(card.masked == "**** ****** *0005")
    }

    @Test("Masked and revealed forms are the same length, so revealing does not reflow")
    func maskPreservesLayout() throws {
        for number in ["4111111111111111", "378282246310005", "36227206271667"] {
            let card = try #require(Self.detect("Card Number", number))
            #expect(card.masked.count == card.grouped.count, "\(number)")
        }
    }

    @Test("Only the last four survive masking")
    func onlyLastFourVisible() throws {
        let card = try #require(Self.detect("Card Number", "4111111111119999"))
        #expect(card.masked.filter(\.isNumber) == "9999")
        #expect(card.last4 == "9999")
    }

    // MARK: - Detection

    @Test("Label spelling and punctuation do not matter", arguments: [
        "Card Number", "card_number", "CARDNUMBER", "cardNumber", "Card No", "PAN", "CC Number",
    ])
    func labelVariants(label: String) {
        #expect(Self.detect(label, "4111111111111111") != nil, "\(label) should match")
    }

    @Test("Brands are read from the prefix for grouping", arguments: [
        ("4111111111111111", CardNumber.Brand.visa),
        ("5555555555554444", .mastercard),
        ("2223003122003222", .mastercard),
        ("378282246310005", .amex),
        ("6011111111111117", .discover),
        ("3530111333300000", .jcb),
        ("36227206271667", .dinersClub),
        ("6200000000000005", .unionPay),
        ("9999999999999999", .unknown),
    ])
    func brandDetection(number: String, expected: CardNumber.Brand) {
        #expect(CardNumber.Brand.detect(digits: number) == expected)
    }

    /// The important negative: an unrelated field must never be masked as a card.
    @Test("Unrelated fields are not card numbers", arguments: [
        ("Recovery code", "4111111111111111"),
        ("Account ID", "4111111111111111"),
        ("Phone", "4111111111111111"),
        ("Notes", "4111111111111111"),
    ])
    func unrelatedLabelsIgnored(label: String, number: String) {
        #expect(Self.detect(label, number) == nil,
                "\(label) is not a card number field, whatever it contains")
    }

    /// A vague label needs the value to look like a card; "card" in the label does not.
    @Test("A vague label needs a plausible number")
    func vagueLabelNeedsCorroboration() {
        // No brand, fails Luhn, label says only "Number".
        #expect(Self.detect("Number", "9999999999999999") == nil)
        // Same label, but a real card number.
        #expect(Self.detect("Number", "4111111111111111") != nil)
        // An explicit label is enough on its own, even for a number with a typo.
        #expect(Self.detect("Card Number", "9999999999999999") != nil)
    }

    @Test("Implausible lengths are not card numbers", arguments: [
        "41111", "411111111111", "41111111111111111111",
    ])
    func implausibleLengths(number: String) {
        let expected = (12...19).contains(number.count)
        #expect((Self.detect("Card Number", number) != nil) == expected)
    }

    @Test("Luhn accepts the networks' test numbers and rejects a transposition")
    func luhn() {
        #expect(CardNumber.passesLuhn("4111111111111111"))
        #expect(CardNumber.passesLuhn("378282246310005"))
        #expect(!CardNumber.passesLuhn("4111111111111112"))
    }

    /// An unusual length must not silently lose digits.
    @Test("Grouping keeps every digit")
    func groupingKeepsEverything() {
        let digits = "12345678901234567"       // 17, longer than 4×4
        let grouped = CardNumber.group(digits, brand: .visa)
        #expect(grouped.filter(\.isNumber) == digits)
    }
}

/// How a card's fields are ordered for display.
///
/// A card is read in a fixed order — number, expiry, security code, PIN — the same order
/// it is printed on the plastic and asked for at a checkout. Sorting by name would put
/// CVV above the number.
@Suite("Card field order")
struct CardFieldOrderTests {

    static func card(_ fields: [String: String]) -> Entry {
        var values: [String: FieldValue] = [Entry.titleField: .plain("Card")]
        for (k, v) in fields { values[k] = FieldValue.makeProtected(v) }
        return Entry(fields: values)
    }

    @Test("A card lists number, valid, CVV, then PIN")
    func cardOrder() {
        let entry = Self.card([
            "Type": "card",
            "CVV": "123",
            "PIN": "4321",
            "Card Number": "4111111111111111",
            "Valid": "09/28",
        ])
        let names = entry.orderedCustomFields().map(\.name)

        #expect(names.prefix(4).elementsEqual(["Card Number", "Valid", "CVV", "PIN"]))
    }

    /// Alphabetically these would come out CVV, Card Number, PIN, Valid — which is the
    /// order this exists to prevent.
    @Test("The order is not alphabetical")
    func notAlphabetical() {
        let entry = Self.card([
            "Type": "card",
            "CVV": "123",
            "Card Number": "4111111111111111",
        ])
        let names = entry.orderedCustomFields().map(\.name)
        #expect(names.firstIndex(of: "Card Number")! < names.firstIndex(of: "CVV")!)
    }

    @Test("Missing card fields are simply absent")
    func missingFieldsSkipped() {
        let entry = Self.card(["Type": "card", "Card Number": "4111111111111111", "CVV": "123"])
        let names = entry.orderedCustomFields().map(\.name)
        #expect(names.prefix(2).elementsEqual(["Card Number", "CVV"]))
    }

    /// Anything that is not a known card field keeps its alphabetical place, after them.
    @Test("Other fields follow, in name order")
    func othersFollowAlphabetically() {
        let entry = Self.card([
            "Type": "card",
            "Card Number": "4111111111111111",
            "Valid": "09/28",
            "Zebra": "z",
            "Bank": "Example Bank",
        ])
        let names = entry.orderedCustomFields().map(\.name)

        #expect(names.prefix(2).elementsEqual(["Card Number", "Valid"]))
        #expect(names.suffix(3).elementsEqual(["Bank", "Type", "Zebra"]),
                "the leftovers stay alphabetical")
    }

    @Test("Expiry and PIN labels are matched by their common spellings", arguments: [
        ("Valid", "PIN"), ("Valid Thru", "PIN Code"), ("Expiry", "Pin"),
        ("Expiration Date", "ATM PIN"),
    ])
    func labelVariants(expiryLabel: String, pinLabel: String) {
        let entry = Self.card([
            "Type": "card",
            "Card Number": "4111111111111111",
            expiryLabel: "09/28",
            "CVV": "123",
            pinLabel: "4321",
        ])
        let names = entry.orderedCustomFields().map(\.name)
        #expect(names.prefix(4).elementsEqual(["Card Number", expiryLabel, "CVV", pinLabel]),
                "\(expiryLabel) / \(pinLabel)")
    }

    /// A login must keep plain alphabetical order.
    @Test("A login is still listed alphabetically")
    func loginStaysAlphabetical() {
        let entry = Entry(fields: [
            Entry.titleField: .plain("Login"),
            Entry.passwordField: .makeProtected("hunter2"),
            "Zebra": .plain("z"),
            "Alpha": .plain("a"),
        ])
        #expect(entry.orderedCustomFields().map(\.name) == ["Alpha", "Zebra"])
    }
}
