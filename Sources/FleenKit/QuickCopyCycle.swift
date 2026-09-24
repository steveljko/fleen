import Foundation
import KdbxCore

/// What repeated clicks on the same entry copy, in order.
///
/// The sequence depends on what the entry *is*. A login gives up its password and then
/// its one-time code — the order a login form asks for them. A card gives up its number,
/// then the expiry, then the security code — the order a checkout page asks for them.
/// Steps the entry does not have are left out, so a click never appears to do nothing.
///
/// Kept out of the view because this is the part that can actually be wrong: which click
/// means what, when it expires, and what happens when the user moves to another entry
/// mid-cycle.
public enum QuickCopyStep: Equatable, Sendable {
    case password
    case oneTimeCode
    case cardNumber
    case cardExpiry
    case cardSecurityCode

    /// What the toast calls it.
    public var label: String {
        switch self {
        case .password: return "Password"
        case .oneTimeCode: return "One-time code"
        case .cardNumber: return "Card number"
        case .cardExpiry: return "Expiry"
        case .cardSecurityCode: return "Security code"
        }
    }

    /// How the *next* step is named in "click again for …".
    public var nextHint: String {
        switch self {
        case .password: return "the password"
        case .oneTimeCode: return "the code"
        case .cardNumber: return "the number"
        case .cardExpiry: return "the expiry"
        case .cardSecurityCode: return "the security code"
        }
    }

    /// The steps `entry` can actually offer, in order.
    public static func sequence(for entry: Entry) -> [QuickCopyStep] {
        switch entry.kind {
        case .card:
            var steps: [QuickCopyStep] = []
            if entry.cardNumberField != nil { steps.append(.cardNumber) }
            if entry.cardExpiryField != nil { steps.append(.cardExpiry) }
            if entry.cardSecurityCodeField != nil { steps.append(.cardSecurityCode) }
            return steps
        case .login:
            var steps: [QuickCopyStep] = []
            if !(entry.password?.isEmpty ?? true) { steps.append(.password) }
            if entry.totp != nil { steps.append(.oneTimeCode) }
            return steps
        }
    }
}

public struct QuickCopyCycle: Sendable {
    private var armedEntry: UUID?
    private var armedUntil: Date?
    private var position = 0

    public init() {}

    /// Advances the cycle for `entryID` and reports what to copy, or `nil` when the
    /// entry has nothing to offer.
    public mutating func next(for entryID: UUID,
                              steps: [QuickCopyStep],
                              now: Date = Date()) -> QuickCopyStep? {
        guard !steps.isEmpty else {
            reset()
            return nil
        }

        let isRepeat = armedEntry == entryID && (armedUntil.map { now < $0 } ?? false)
        let index = isRepeat ? position + 1 : 0

        guard index < steps.count else {
            // The sequence is spent: start it again rather than repeating the last step,
            // so a stray click cannot leave the clipboard stuck on a security code.
            reset()
            return next(for: entryID, steps: steps, now: now)
        }

        armedEntry = entryID
        armedUntil = now.addingTimeInterval(Preferences.quickCopyWindow)
        position = index
        return steps[index]
    }

    /// The step a further click would copy, if any — so the user can be told what the
    /// next click does rather than discovering it.
    public func upcomingStep(for entryID: UUID,
                             steps: [QuickCopyStep],
                             now: Date = Date()) -> QuickCopyStep? {
        guard armedEntry == entryID, armedUntil.map({ now < $0 }) ?? false else { return nil }
        let next = position + 1
        return next < steps.count ? steps[next] : nil
    }

    /// Forgets any armed entry, so a cycle cannot carry across a lock.
    ///
    /// Note what this deliberately does *not* cover: closing the popover and reopening
    /// it within the window leaves the cycle intact, because copying a password,
    /// switching to the browser and coming back for the code is the whole point.
    public mutating func reset() {
        armedEntry = nil
        armedUntil = nil
        position = 0
    }
}
