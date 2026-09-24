import Foundation

/// What kind of thing an entry describes, so callers can treat a card differently from
/// a login.
///
/// KeePass has no type system, so this reads one out of the entry's own fields: an
/// explicit marker the user writes (`Type: card`), with a narrow fallback for the case
/// where guessing is safe.
public enum EntryKind: Sendable, Equatable {
    case login
    case card
}

extension Entry {

    /// Labels under which a user might declare what an entry is.
    static let typeLabels: Set<String> = ["type", "category", "kind"]

    /// Values that mean "this is a payment card".
    static let cardTypeValues: Set<String> = [
        "card", "creditcard", "debitcard", "paymentcard", "bankcard", "bank",
    ]

    /// The type the user declared, if any — normalised, so `Type: Credit Card` and
    /// `type: creditcard` are the same answer.
    public var declaredType: String? {
        for (name, value) in fields where Self.typeLabels.contains(CardNumber.normalise(name)) {
            let declared = CardNumber.normalise(value.reveal())
            if !declared.isEmpty { return declared }
        }
        return nil
    }

    /// What this entry is.
    ///
    /// An explicit `Type: card` field decides it. Failing that, an entry that carries a
    /// card number and *no* password is treated as a card too — not to be clever, but
    /// because the alternative is worse: the login behaviour would try to copy a
    /// password that does not exist, and the click would appear to do nothing.
    /// Anything else is a login, which is the safe default.
    public var kind: EntryKind {
        if let declaredType {
            return Self.cardTypeValues.contains(declaredType) ? .card : .login
        }
        let hasPassword = !(password?.isEmpty ?? true)
        return cardNumberField != nil && !hasPassword ? .card : .login
    }

    // MARK: - Card fields

    /// The field holding the card number, with the number parsed.
    public var cardNumberField: (name: String, card: CardNumber)? {
        for (name, value) in fields.sorted(by: { $0.key < $1.key }) {
            if let card = CardNumber.detect(label: name, value: value) {
                return (name, card)
            }
        }
        return nil
    }

    public var cardExpiryField: (name: String, value: FieldValue)? {
        field(matching: Self.expiryLabels)
    }

    public var cardSecurityCodeField: (name: String, value: FieldValue)? {
        field(matching: Self.securityCodeLabels)
    }

    private func field(matching labels: [String]) -> (name: String, value: FieldValue)? {
        let normalised = Dictionary(fields.keys.map { (CardNumber.normalise($0), $0) },
                                    uniquingKeysWith: { first, _ in first })
        for label in labels {
            if let key = normalised[label], let value = fields[key], !value.isEmpty {
                return (key, value)
            }
        }
        return nil
    }

    /// Ordered most specific first.
    static let expiryLabels = [
        "expirydate", "expirationdate", "expiry", "expiration", "expires", "expireson",
        "validthru", "validuntil", "validto", "exp", "expdate", "mmyy", "valid",
    ]
    static let securityCodeLabels = [
        "cvv2", "cvc2", "cvv", "cvc", "csc", "cid", "cardsecuritycode", "securitycode",
        "cardverificationvalue", "cardverificationcode",
    ]
}
