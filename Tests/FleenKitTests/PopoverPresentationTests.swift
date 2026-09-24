import Testing
@testable import FleenKit

/// When the unlock screen may offer a biometric prompt.
///
/// This state lives outside the view on purpose. The unlock screen is *recreated* when
/// the vault locks, so a flag held in its own `@State` starts fresh and prompts again —
/// which is how locking the vault produced an immediate "touch to unlock" panel instead
/// of simply closing.
@MainActor
@Suite("Popover presentation")
struct PopoverPresentationTests {

    @Test("Closed and unprompted to begin with")
    func startsClosed() {
        let presentation = PopoverPresentation()
        #expect(!presentation.isOpen)
        #expect(!presentation.hasOfferedBiometricPrompt)
    }

    @Test("Opening arms the prompt; offering it disarms it")
    func openingArmsThePrompt() {
        let presentation = PopoverPresentation()
        presentation.opened()
        #expect(presentation.isOpen)
        #expect(!presentation.hasOfferedBiometricPrompt, "a fresh open should prompt")

        presentation.markBiometricPromptOffered()
        #expect(presentation.hasOfferedBiometricPrompt, "and only once per open")
    }

    @Test("Reopening arms it again")
    func reopeningRearms() {
        let presentation = PopoverPresentation()
        presentation.opened()
        presentation.markBiometricPromptOffered()
        presentation.closed()
        presentation.opened()
        #expect(!presentation.hasOfferedBiometricPrompt)
    }

    @Test("Locking suppresses the prompt for the rest of this presentation")
    func lockingSuppressesThePrompt() {
        let presentation = PopoverPresentation()
        presentation.opened()

        // The user asked to lock. Answering that by asking them to unlock again is
        // exactly the behaviour being prevented.
        presentation.suppressBiometricPrompt()
        #expect(presentation.hasOfferedBiometricPrompt,
                "locking must not be followed by a Touch ID panel")
    }

    @Test("A suppressed prompt stays suppressed until the popover is reopened")
    func suppressionSurvivesUntilReopen() {
        let presentation = PopoverPresentation()
        presentation.opened()
        presentation.suppressBiometricPrompt()
        presentation.closed()
        #expect(presentation.hasOfferedBiometricPrompt)

        // Only a deliberate reopen re-arms it.
        presentation.opened()
        #expect(!presentation.hasOfferedBiometricPrompt)
    }
}
