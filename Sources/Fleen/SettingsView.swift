import SwiftUI
import AppKit
import Combine
import FleenKit

/// A proper settings window (⌘,) rather than a sheet hung off the popover.
///
/// The popover dismisses whenever focus leaves it, which makes it a hostile place to
/// put settings — every click into another app would throw the panel away. A real
/// window also gets the standard tabbed-preferences look people expect.
@MainActor
final class SettingsWindowController: NSObject, NSWindowDelegate {
    static let shared = SettingsWindowController()

    private var window: NSWindow?

    /// Lets the app delegate tell "the user opened Settings" apart from "the user
    /// switched to another app" when deciding whether to close the popover.
    var isVisible: Bool { window?.isVisible ?? false }

    func show(preferences: Preferences) {
        if let window {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let hosting = NSHostingController(rootView: SettingsView(preferences: preferences))
        let window = NSWindow(contentViewController: hosting)
        window.title = "Fleen Settings"
        window.styleMask = [.titled, .closable]
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()
        self.window = window

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowWillClose(_ notification: Notification) {
        window = nil
    }
}

struct SettingsView: View {
    let preferences: Preferences

    @State private var clipboardSeconds: Int
    @State private var idleMinutes: Int
    @State private var lockOnScreenLock: Bool
    @State private var lockOnSleep: Bool
    @State private var watchFile: Bool
    @State private var biometricEnabled: Bool
    @State private var promptOnOpen: Bool
    @State private var showRecycleBin: Bool
    @State private var browseMode: BrowseMode

    init(preferences: Preferences) {
        self.preferences = preferences
        _clipboardSeconds = State(initialValue: preferences.clipboardClearSeconds)
        _idleMinutes = State(initialValue: preferences.idleLockMinutes)
        _lockOnScreenLock = State(initialValue: preferences.lockOnScreenLock)
        _lockOnSleep = State(initialValue: preferences.lockOnSleep)
        _watchFile = State(initialValue: preferences.watchDatabaseFile)
        _biometricEnabled = State(initialValue: preferences.biometricUnlockEnabled)
        _promptOnOpen = State(initialValue: preferences.promptBiometricsOnOpen)
        _showRecycleBin = State(initialValue: preferences.showRecycleBin)
        _browseMode = State(initialValue: preferences.browseMode)
    }

    private var biometry: BiometricUnlock.Biometry { BiometricUnlock.availability() }

    var body: some View {
        TabView {
            securityTab
                .tabItem { Label("Security", systemImage: "lock.shield") }
            generalTab
                .tabItem { Label("General", systemImage: "gearshape") }
        }
        .frame(width: 440, height: 340)
        .padding(.top, 8)

    }

    private var securityTab: some View {
        Form {
            Section {
                Picker("Lock after inactivity:", selection: $idleMinutes) {
                    Text("Never").tag(0)
                    Text("1 minute").tag(1)
                    Text("5 minutes").tag(5)
                    Text("15 minutes").tag(15)
                    Text("30 minutes").tag(30)
                    Text("1 hour").tag(60)
                }
                .onChange(of: idleMinutes) { _, value in preferences.idleLockMinutes = value }

                Toggle("Lock when the screen locks", isOn: $lockOnScreenLock)
                    .onChange(of: lockOnScreenLock) { _, value in preferences.lockOnScreenLock = value }

                Toggle("Lock when the Mac sleeps", isOn: $lockOnSleep)
                    .onChange(of: lockOnSleep) { _, value in preferences.lockOnSleep = value }
            } header: {
                Text("Auto-lock")
            }

            Section {
                Picker("Clear clipboard after:", selection: $clipboardSeconds) {
                    Text("Never").tag(0)
                    Text("10 seconds").tag(10)
                    Text("30 seconds").tag(30)
                    Text("1 minute").tag(60)
                    Text("2 minutes").tag(120)
                }
                .onChange(of: clipboardSeconds) { _, value in preferences.clipboardClearSeconds = value }

                Text("Copied passwords are marked so clipboard managers skip them.")
                    .font(.caption)
                    .foregroundStyle(Design.Palette.secondaryText)
            } header: {
                Text("Clipboard")
            }

            Section {
                if biometry.isAvailable {
                    Toggle("Unlock with \(biometry.displayName)", isOn: $biometricEnabled)
                        .onChange(of: biometricEnabled) { _, value in
                            preferences.biometricUnlockEnabled = value
                        }
                    Text("Stores the derived key in the Keychain — never your master password. Unlocking still runs the full key derivation.")
                        .font(.caption)
                        .foregroundStyle(Design.Palette.secondaryText)

                    Toggle("Ask on click, before the window opens", isOn: $promptOnOpen)
                        .onChange(of: promptOnOpen) { _, value in
                            preferences.promptBiometricsOnOpen = value
                        }
                        .disabled(!biometricEnabled)
                    Text(biometricEnabled
                         ? "Clicking the menu bar icon asks for \(biometry.displayName) straight away. The vault opens already unlocked; cancelling opens the lock screen instead."
                         : "Turn on \(biometry.displayName) unlock first.")
                        .font(.caption)
                        .foregroundStyle(Design.Palette.secondaryText)

                    Label(BiometricUnlock.availableProtectionLevel.isCryptographicallyBound
                          ? "Enforced by the Keychain"
                          : "Enforced by Fleen, not by macOS",
                          systemImage: BiometricUnlock.availableProtectionLevel
                              .isCryptographicallyBound
                              ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(BiometricUnlock.availableProtectionLevel
                            .isCryptographicallyBound
                            ? Design.Palette.success : Design.Palette.warning)

                    Text(BiometricUnlock.availableProtectionLevel.explanation)
                        .font(.caption)
                        .foregroundStyle(Design.Palette.secondaryText)
                } else if case .none(let reason) = biometry {
                    Label(reason, systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(Design.Palette.secondaryText)
                }
            } header: {
                Text("Biometrics")
            }
        }
        .formStyle(.grouped)
    }

    private var generalTab: some View {
        Form {
            Section {
                Picker("Folders:", selection: $browseMode) {
                    ForEach(BrowseMode.allCases, id: \.self) { mode in
                        Text(mode.displayName).tag(mode)
                    }
                }
                .onChange(of: browseMode) { _, value in preferences.browseMode = value }

                Text(browseMode.explanation)
                    .font(.caption)
                    .foregroundStyle(Design.Palette.secondaryText)
            } header: {
                Text("Display")
            }

            Section {
                Toggle("Show Recycle Bin", isOn: $showRecycleBin)
                    .onChange(of: showRecycleBin) { _, value in
                        preferences.showRecycleBin = value
                    }
                Text("Lists deleted entries when browsing and searching. They appear with a trash icon. Databases without a recycle bin are unaffected.")
                    .font(.caption)
                    .foregroundStyle(Design.Palette.secondaryText)

                Toggle("Watch the database file for external changes", isOn: $watchFile)
                    .onChange(of: watchFile) { _, value in preferences.watchDatabaseFile = value }
                Text("Detects edits made by KeePassXC or a sync client and offers to reload.")
                    .font(.caption)
                    .foregroundStyle(Design.Palette.secondaryText)
            } header: {
                Text("Database")
            }

            Section {
                Text("Fleen reads and writes KeePass KDBX 4 databases entirely on this Mac. It makes no network connections.")
                    .font(.caption)
                    .foregroundStyle(Design.Palette.secondaryText)
            } header: {
                Text("About")
            }
        }
        .formStyle(.grouped)
    }
}
