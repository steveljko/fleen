import Foundation
import Observation
import AppKit

/// Copies secrets to the pasteboard and takes them back again.
///
/// Two things matter here beyond "call setString":
///
/// * **Clipboard managers.** Most of them archive everything that crosses the
///   pasteboard, which would turn a password copy into a plaintext password on disk,
///   outside our control and past any lock timeout. Declaring
///   `org.nspasteboard.ConcealedType` is the community convention that tells them to
///   skip the item, and it is honoured by the major ones.
///
/// * **Clearing safely.** The auto-clear must not wipe something the user copied
///   afterwards. `changeCount` is checked before clearing, so we only ever remove our
///   own item.
@MainActor
@Observable
public final class ClipboardService {
    public static let shared = ClipboardService()

    /// UTI understood by clipboard managers as "do not record this".
    static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    /// "Do not keep a history of this" — the companion marker clipboard tools check.
    static let transientType = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    /// Not observed: only `secondsRemaining` drives the UI, and marking the rest
    /// observable would invalidate views on every internal bookkeeping change.
    @ObservationIgnored private let pasteboard: NSPasteboard
    @ObservationIgnored private var clearTask: Task<Void, Never>?
    @ObservationIgnored private var ownedChangeCount: Int?

    /// Seconds remaining before the clipboard is cleared, for the UI to show.
    ///
    /// Observable, and it has to be: a plain property here left the countdown frozen
    /// at whatever value the view happened to render with, because nothing told
    /// SwiftUI to draw again as it ticked down.
    public private(set) var secondsRemaining: Int = 0

    public init(pasteboard: NSPasteboard = .general) {
        self.pasteboard = pasteboard
    }

    /// Copies a secret, concealed from clipboard managers, and schedules its removal.
    ///
    /// - Parameter clearAfter: seconds; 0 or negative disables auto-clear.
    public func copySecret(_ value: String, clearAfter seconds: Int) {
        clearTask?.cancel()

        // `.currentHostOnly` keeps the secret off Universal Clipboard. Without it a copied
        // password lands on the user's iPhone or iPad too, where the auto-clear below
        // never reaches and any app can read it.
        pasteboard.prepareForNewContents(with: .currentHostOnly)
        // The markers must be declared alongside the string, not instead of it, or
        // nothing can paste the value at all.
        pasteboard.setString(value, forType: .string)
        pasteboard.setData(Data(), forType: Self.concealedType)
        pasteboard.setData(Data(), forType: Self.transientType)
        ownedChangeCount = pasteboard.changeCount

        guard seconds > 0 else {
            secondsRemaining = 0
            return
        }

        secondsRemaining = seconds
        clearTask = Task { [weak self] in
            for remaining in stride(from: seconds - 1, through: 0, by: -1) {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled, let self else { return }

                // If the pasteboard no longer holds our item, the user copied
                // something else; stop counting down to an event that will not happen.
                guard let owned = self.ownedChangeCount,
                      self.pasteboard.changeCount == owned else {
                    self.secondsRemaining = 0
                    self.ownedChangeCount = nil
                    return
                }
                self.secondsRemaining = remaining
            }
            self?.clearIfStillOurs()
        }
    }

    /// Copies something non-secret (a username, a URL) with no concealment and no timer.
    public func copyPlain(_ value: String) {
        clearTask?.cancel()
        secondsRemaining = 0
        ownedChangeCount = nil
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
    }

    /// Clears the pasteboard, but only if it still holds what we put there.
    public func clearIfStillOurs() {
        defer {
            secondsRemaining = 0
            ownedChangeCount = nil
            clearTask?.cancel()
            clearTask = nil
        }
        guard let owned = ownedChangeCount, pasteboard.changeCount == owned else {
            // The user copied something else in the meantime; leave it alone.
            return
        }
        pasteboard.clearContents()
    }
}
