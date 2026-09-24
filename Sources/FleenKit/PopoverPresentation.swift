import Foundation
import Observation

/// Whether the menu bar popover is currently on screen.
///
/// The views need this because the popover's content is built once at launch and reused,
/// so a view "appearing" says nothing about whether the user can see it. Without that
/// distinction an automatic Touch ID prompt fired the moment the vault auto-locked —
/// throwing a system modal onto the screen out of nowhere, while the popover was shut.
@MainActor
@Observable
public final class PopoverPresentation {
    public private(set) var isOpen = false

    /// Whether a biometric prompt has already been offered for this presentation.
    ///
    /// Lives here rather than in the view because the unlock screen is *recreated* when
    /// the vault locks — its own `@State` would start fresh and prompt again, which is
    /// how locking the vault produced an immediate "touch to unlock" panel.
    public private(set) var hasOfferedBiometricPrompt = false

    public init() {}

    public func opened() {
        isOpen = true
        hasOfferedBiometricPrompt = false
    }

    public func closed() { isOpen = false }

    public func markBiometricPromptOffered() { hasOfferedBiometricPrompt = true }

    /// Called when the vault locks: suppresses any prompt for the rest of this
    /// presentation. Locking is a deliberate act, and answering it by immediately
    /// asking the user to unlock again is absurd.
    public func suppressBiometricPrompt() { hasOfferedBiometricPrompt = true }
}
