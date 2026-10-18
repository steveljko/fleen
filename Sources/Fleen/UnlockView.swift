import SwiftUI
import FleenKit
import KdbxCore

/// The lock screen.
///
/// Two shapes, because the two situations want different things:
///
/// * **Enrolled** — a single large Touch ID button and nothing else. The password field
///   would be clutter for someone who is going to touch the sensor, so it is one link
///   away rather than on screen.
/// * **Not enrolled** — password field, one full-width Unlock button, and a checkbox to
///   remember. Deliberately *one* button: an "Unlock" and a separate "Unlock and save
///   Touch ID" are the same action with a setting attached, and presenting them as two
///   choices makes the user decide something they should not have to.
struct UnlockView: View {
    @Bindable var session: VaultSession
    let preferences: Preferences
    let presentation: PopoverPresentation

    @State private var password = ""
    @State private var enrollBiometrics = false
    /// Set when the user chooses the password over Touch ID for this attempt.
    @State private var preferPassword = false

    /// How long the popover gets to appear before the biometric prompt is offered.
    /// Long enough to see the window, short enough not to feel like waiting.
    private static let biometricPromptDelay = 450

    private enum Field: Hashable { case password, unlock }
    @FocusState private var focus: Field?

    private var biometry: BiometricUnlock.Biometry {
        BiometricUnlock.availability(allowDevicePassword: preferences.allowDevicePasswordFallback)
    }

    private var databaseName: String {
        session.databaseURL?.deletingPathExtension().lastPathComponent ?? "Fleen"
    }

    /// The streamlined path: a key is saved for *this* database and the user has not
    /// asked for the password field.
    private var showsBiometricOnly: Bool {
        session.canUnlockWithBiometrics && !preferPassword
    }

    var body: some View {
        VStack(spacing: 0) {
            if session.state.isBusy {
                unlockingState
            } else if showsBiometricOnly {
                biometricState
            } else {
                passwordState
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .frame(width: Design.Metrics.popoverWidth, height: Design.Metrics.popoverHeight)
        .onChange(of: session.databaseURL) { _, _ in
            // A different database has a different key; start from a clean slate rather
            // than carrying the previous one's choices over.
            preferPassword = false
            password = ""
            enrollBiometrics = false
        }
    }

    // MARK: - Waiting

    private var unlockingState: some View {
        VStack(spacing: 20) {
            Spacer()
            ProgressView()
                .progressViewStyle(.circular)
                .controlSize(.large)
                .accessibilityHidden(true)
            Text("Unlocking…")
                .font(.title3.weight(.medium))
            Spacer()
        }
        .padding(Design.Metrics.screenPadding)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Unlocking your vault")
    }

    // MARK: - Touch ID only

    private var biometricState: some View {
        VStack(spacing: 0) {
            Spacer()

            VStack(spacing: Design.Metrics.spacing) {
                Text(databaseName)
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)

                Button(action: unlockWithBiometrics) {
                    Image(systemName: biometry == .opticID ? "opticid" : "touchid")
                        .font(.system(size: 52, weight: .light))
                        .foregroundStyle(Design.Palette.accent)
                        .frame(width: 96, height: 96)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .hoverHighlight(cornerRadius: 20)
                .keyboardShortcut(.defaultAction)
                .help("Unlock with \(biometry.displayName)")
                .accessibilityLabel("Unlock with \(biometry.displayName)")

                Text(session.biometricPromptDeclined
                     ? "Tap to Unlock"
                     : (biometry == .devicePassword ? "Unlock" : "Touch to Unlock"))
                    .font(.headline)
                    .foregroundStyle(Design.Palette.secondaryText)

                if case .failed(let message) = session.state {
                    errorBanner(message)
                } else if let reason = session.lastLockReason, !reason.explanation.isEmpty {
                    Text(reason.explanation)
                        .font(.caption)
                        .foregroundStyle(Design.Palette.secondaryText)
                        .multilineTextAlignment(.center)
                }
            }

            Spacer()

            VStack(spacing: Design.Metrics.tightSpacing) {
                Button("Use master password instead") {
                    preferPassword = true
                    focus = .password
                }
                .buttonStyle(.link)
                .font(.caption)

                footer
            }
        }
        .padding(.horizontal, Design.Metrics.screenPadding)
        .padding(.vertical, Design.Metrics.spacing)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // Prompt when the user opens the popover — never merely because the vault
        // locked. An idle or screen lock happens while they are away from the Mac, and
        // putting a Touch ID modal on screen at that moment is startling and useless.
        // Let the popover draw and settle before the system modal arrives. Prompting on
        // the same frame the popover opens means the Touch ID panel lands on top of a
        // window the user has not seen yet, which reads as the app grabbing at them
        // rather than responding.
        //
        // The id includes `preferPassword` so choosing the password route cancels a
        // pending prompt, and `isOpen` so closing the popover does too.
        .task(id: AnyHashable([presentation.isOpen, preferPassword])) {
            guard presentation.isOpen, !preferPassword,
                  // Cancelled once means "wait to be asked".
                  !session.biometricPromptDeclined,
                  !presentation.hasOfferedBiometricPrompt else { return }

            try? await Task.sleep(for: .milliseconds(Self.biometricPromptDelay))

            // Re-check everything: the user may have closed the popover, switched to the
            // password field, or unlocked another way while we waited.
            guard !Task.isCancelled, presentation.isOpen, !preferPassword,
                  !presentation.hasOfferedBiometricPrompt,
                  !session.state.isUnlocked else { return }

            // Marked only now, so an abandoned attempt does not consume the one offer.
            presentation.markBiometricPromptOffered()
            // Not user-initiated: must not clear an earlier decline.
            Task { await session.unlockWithBiometrics(userInitiated: false) }
        }
    }

    // MARK: - Password

    private var passwordState: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 8)

            VStack(spacing: 8) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 36, weight: .light))
                    .foregroundStyle(Design.Palette.accent)
                    .accessibilityHidden(true)

                Text(databaseName)
                    .font(.title2.weight(.semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)

                Text("Enter your master password")
                    .font(.subheadline)
                    .foregroundStyle(Design.Palette.secondaryText)
            }
            .accessibilityElement(children: .combine)

            Spacer(minLength: 14)

            VStack(spacing: 12) {
                passwordField

                if case .failed(let message) = session.state {
                    errorBanner(message)
                } else if let warning = session.biometricWarning {
                    warningBanner(warning)
                } else if let reason = session.lastLockReason, !reason.explanation.isEmpty {
                    Text(reason.explanation)
                        .font(.caption)
                        .foregroundStyle(Design.Palette.secondaryText)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                unlockButton

                // A checkbox, not a second button: remembering is a property of this
                // unlock, not a different way to unlock.
                if biometry.isAvailable, !session.canUnlockWithBiometrics {
                    Toggle("Remember with \(biometry.displayName)", isOn: $enrollBiometrics)
                        .toggleStyle(.checkbox)
                        .font(.caption)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                if session.canUnlockWithBiometrics {
                    Button("Unlock with \(biometry.displayName) instead") {
                        preferPassword = false
                        unlockWithBiometrics()
                    }
                    .buttonStyle(.link)
                    .font(.caption)
                }

                keyFileRow
            }

            Spacer(minLength: 8)
            footer
        }
        .padding(.horizontal, Design.Metrics.screenPadding)
        .padding(.vertical, Design.Metrics.spacing)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { focus = .password }
    }

    private var passwordField: some View {
        SecureField("Master password", text: $password)
            .textFieldStyle(.plain)
            .font(.system(size: 15))
            .lineLimit(1)
            .padding(.horizontal, Design.Metrics.spacing + 2)
            .frame(height: Design.Metrics.largeFieldHeight)
            .background(
                RoundedRectangle(cornerRadius: Design.Metrics.fieldCornerRadius,
                                 style: .continuous)
                    .fill(Color(nsColor: .textBackgroundColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: Design.Metrics.fieldCornerRadius,
                                 style: .continuous)
                    .strokeBorder(
                        focus == .password ? Design.Palette.accent : Design.Palette.separator,
                        lineWidth: focus == .password ? 2 : 1)
            )
            .focused($focus, equals: .password)
            .onSubmit(attemptUnlock)
            .frame(maxWidth: .infinity)
            .accessibilityLabel("Master password")
    }

    private var unlockButton: some View {
        Button(action: attemptUnlock) {
            Text("Unlock")
                .font(.body.weight(.semibold))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .keyboardShortcut(.defaultAction)
        .focused($focus, equals: .unlock)
        .disabled(password.isEmpty && session.keyFileURL == nil)
    }

    private var keyFileRow: some View {
        HStack(spacing: 6) {
            Spacer()
            if let keyFile = session.keyFileURL {
                Image(systemName: "key.fill")
                    .font(.caption2)
                    .foregroundStyle(Design.Palette.secondaryText)
                Text(keyFile.lastPathComponent)
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Button("Remove") { session.setKeyFile(nil) }
                    .buttonStyle(.link)
                    .font(.caption)
            } else {
                Button("Use a key file…", action: chooseKeyFile)
                    .buttonStyle(.link)
                    .font(.caption)
            }
            Spacer()
        }
        .onDrop(of: [.fileURL], isTargeted: nil) { providers in
            guard let provider = providers.first else { return false }
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                DispatchQueue.main.async { session.setKeyFile(url) }
            }
            return true
        }
    }

    private func errorBanner(_ message: String) -> some View {
        Text(message)
            .font(.caption)
            .foregroundStyle(Design.Palette.danger)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Design.Metrics.gutter)
            .padding(.vertical, Design.Metrics.tightSpacing + 1)
            .background(
                RoundedRectangle(cornerRadius: Design.Metrics.controlCornerRadius + 1,
                                 style: .continuous)
                    .fill(Design.Palette.danger.opacity(0.12)))
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityAddTraits(.isStaticText)
    }

    private func warningBanner(_ message: String) -> some View {
        Text(message)
            .font(.caption)
            .foregroundStyle(Design.Palette.warning)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Design.Metrics.gutter)
            .padding(.vertical, Design.Metrics.tightSpacing + 1)
            .background(
                RoundedRectangle(cornerRadius: Design.Metrics.controlCornerRadius + 1,
                                 style: .continuous)
                    .fill(Design.Palette.warning.opacity(0.12)))
            .fixedSize(horizontal: false, vertical: true)
    }

    private var footer: some View {
        HStack(spacing: Design.Metrics.tightSpacing) {
            Button("Open Database…", action: chooseDatabase)
            Spacer()
            Button("Quit") { NSApp.terminate(nil) }
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
    }

    // MARK: - Actions

    private func unlockWithBiometrics() {
        Task { await session.unlockWithBiometrics() }
    }

    private func attemptUnlock() {
        let entered = password
        // Drop our copy immediately: it is a `String` we cannot zero, so not holding it
        // is the only mitigation available.
        password = ""
        Task {
            await session.unlock(password: entered, enrollBiometrics: enrollBiometrics)
        }
    }

    private func chooseDatabase() {
        let panel = NSOpenPanel()
        panel.allowsOtherFileTypes = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Choose a KeePass database (.kdbx)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try session.select(url: url) }
        catch { NSAlert(error: error).runModal() }
    }

    private func chooseKeyFile() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Choose a key file"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        session.setKeyFile(url)
    }
}
