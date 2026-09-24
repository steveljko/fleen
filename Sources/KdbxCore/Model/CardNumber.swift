import Foundation

/// A card number recognised in a custom field, so it can be masked and grouped the way
/// a card number should be rather than shown as an undifferentiated string of digits.
///
/// This is the whole of Fleen's card handling: there is no card type, no card layout
/// and no special detail screen. A card entry is an ordinary entry — the only thing
/// done differently is that a field holding a card number hides as
/// `**** **** **** 1234` instead of a generic run of dots, and reads back in the
/// issuer's own grouping when revealed.
public struct CardNumber: Sendable {

    /// The card network, inferred from the number's prefix.
    ///
    /// Used only to group the digits — Amex prints 4-6-5, everyone else 4-4-4-4 — so an
    /// unrecognised prefix degrades to `.unknown` and the default grouping rather than
    /// failing.
    public enum Brand: String, Sendable {
        case visa, mastercard, amex, discover, jcb, dinersClub, unionPay, maestro, unknown

        public var grouping: [Int] {
            switch self {
            case .amex: return [4, 6, 5]
            case .dinersClub: return [4, 6, 4]
            default: return [4, 4, 4, 4]
            }
        }

        /// Longest-prefix-wins, so Mastercard's 2-series does not shadow Diners' 2xx.
        static func detect(digits: String) -> Brand {
            func hasPrefix(_ prefixes: [String]) -> Bool {
                prefixes.contains { digits.hasPrefix($0) }
            }
            func inRange(_ length: Int, _ range: ClosedRange<Int>) -> Bool {
                guard digits.count >= length,
                      let value = Int(digits.prefix(length)) else { return false }
                return range.contains(value)
            }

            if hasPrefix(["4"]) { return .visa }
            if hasPrefix(["34", "37"]) { return .amex }
            if inRange(2, 51...55) || inRange(4, 2221...2720) { return .mastercard }
            if hasPrefix(["6011", "65"]) || inRange(3, 644...649) { return .discover }
            if inRange(4, 3528...3589) { return .jcb }
            if hasPrefix(["36", "38", "39"]) || inRange(3, 300...305) { return .dinersClub }
            if hasPrefix(["5018", "5020", "5038", "6304", "6759", "6761", "6763"]) {
                return .maestro
            }
            if hasPrefix(["62"]) { return .unionPay }
            return .unknown
        }
    }

    public let brand: Brand
    public let last4: String

    /// The digits only — what belongs on the clipboard, since a payment form rejects
    /// the spaces.
    public let digits: String

    /// Grouped as the issuer prints it, e.g. "4111 1111 1111 1111".
    public var grouped: String { Self.group(digits, brand: brand) }

    /// Hidden: everything but the last four replaced by an asterisk, in the same
    /// grouping, e.g. "**** **** **** 1111".
    public var masked: String {
        let hidden = String(repeating: "*", count: max(digits.count - 4, 0))
        return Self.group(hidden + last4, brand: brand)
    }

    // MARK: - Detection

    /// Whether this field holds a card number.
    ///
    /// The bar is a card-shaped number *plus* corroboration, because a bare `Number`
    /// field holding twelve digits could be an account number, a licence key or a phone
    /// number — and masking one of those as a card would hide a field the user needs to
    /// read.
    public static func detect(label: String, value: FieldValue) -> CardNumber? {
        guard labelLooksLikeCardNumber(label) else { return nil }

        // Reading the value makes a `String` that cannot be zeroed. It happens once, to
        // learn the brand and the last four; the caller keeps the `FieldValue` and
        // reveals it only when asked.
        let digits = value.reveal().filter(\.isNumber)
        guard (12...19).contains(digits.count) else { return nil }

        let brand = Brand.detect(digits: digits)
        // A label that says "card" is explicit enough on its own; anything vaguer has to
        // look like a real card number.
        let corroborated = normalise(label).contains("card")
            || brand != .unknown
            || passesLuhn(digits)
        guard corroborated else { return nil }

        return CardNumber(brand: brand, last4: String(digits.suffix(4)), digits: digits)
    }

    // MARK: - Internals

    static func group(_ characters: String, brand: Brand) -> String {
        var remaining = Substring(characters)
        var groups: [String] = []
        for size in brand.grouping {
            guard !remaining.isEmpty else { break }
            groups.append(String(remaining.prefix(size)))
            remaining = remaining.dropFirst(size)
        }
        // Anything left over (an unusual length) is appended rather than dropped —
        // silently truncating someone's card number would be worse than odd spacing.
        if !remaining.isEmpty { groups.append(String(remaining)) }
        return groups.joined(separator: " ")
    }

    /// The Luhn checksum every card number carries.
    static func passesLuhn(_ digits: String) -> Bool {
        guard digits.count >= 2 else { return false }
        var sum = 0
        for (offset, character) in digits.reversed().enumerated() {
            guard let digit = character.wholeNumberValue else { return false }
            if offset.isMultiple(of: 2) {
                sum += digit
            } else {
                let doubled = digit * 2
                sum += doubled > 9 ? doubled - 9 : doubled
            }
        }
        return sum.isMultiple(of: 10)
    }

    /// Labels are normalised — lowercased, with everything but letters and digits
    /// removed — so "Card Number", "card_number" and "CardNumber" all match.
    static func normalise(_ label: String) -> String {
        label.lowercased().filter { $0.isLetter || $0.isNumber }
    }

    static func labelLooksLikeCardNumber(_ label: String) -> Bool {
        numberLabels.contains(normalise(label))
    }

    static let numberLabels: Set<String> = [
        "cardnumber", "creditcardnumber", "debitcardnumber", "cardno", "cardnr",
        "ccnumber", "ccnum", "pan", "number", "card",
    ]
}
