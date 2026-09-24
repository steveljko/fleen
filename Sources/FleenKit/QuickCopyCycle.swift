import Foundation

/// What a click on an entry copies, when quick copy is on.
///
/// The rule is "password, then one-time code": the first click copies the password, and
/// clicking the *same* entry again within the window copies its code — the order a login
/// form asks for them. The window exists so that a click a minute later is unambiguously
/// a fresh start rather than an accidental second step.
///
/// Kept out of the view because it is the part that can actually be wrong: which click
/// means what, when it expires, and what happens when the user moves to another entry
/// mid-cycle.
public struct QuickCopyCycle: Sendable {
    public enum Step: Equatable, Sendable {
        case password
        case oneTimeCode
    }

    private var armedEntry: UUID?
    private var armedUntil: Date?

    public init() {}

    /// Advances the cycle for `entryID` and reports what to copy.
    ///
    /// - Parameter hasOneTimeCode: whether this entry has a code at all. Without one the
    ///   second click repeats the password rather than doing nothing — a click that
    ///   silently does nothing reads as a broken click.
    public mutating func next(for entryID: UUID,
                              hasOneTimeCode: Bool,
                              now: Date = Date()) -> Step {
        let isRepeat = armedEntry == entryID
            && (armedUntil.map { now < $0 } ?? false)

        if isRepeat && hasOneTimeCode {
            // The cycle is spent: a third click starts again with the password, rather
            // than copying the same code a second time.
            reset()
            return .oneTimeCode
        }

        armedEntry = entryID
        armedUntil = now.addingTimeInterval(Preferences.quickCopyWindow)
        return .password
    }

    /// Whether a further click on `entryID` would copy the code rather than the
    /// password. Used to tell the user what the next click will do.
    public func offersCodeNext(for entryID: UUID, now: Date = Date()) -> Bool {
        armedEntry == entryID && (armedUntil.map { now < $0 } ?? false)
    }

    /// Forgets any armed entry, so a cycle cannot carry across a lock.
    ///
    /// Note what this deliberately does *not* cover: closing the popover and reopening
    /// it within the window leaves the cycle intact, because copying a password,
    /// switching to the browser and coming back for the code is the whole point.
    public mutating func reset() {
        armedEntry = nil
        armedUntil = nil
    }
}
