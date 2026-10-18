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
        window.sharingType = .none
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
    @State private var allowLoginPassword: Bool
    @State private var quickCopy: Bool
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
        _allowLoginPassword = State(initialValue: preferences.allowDevicePasswordFallback)
        _quickCopy = State(initialValue: preferences.quickCopy)
        _showRecycleBin = State(initialValue: preferences.showRecycleBin)
        _browseMode = State(initialValue: preferences.browseMode)
    }

    private var biometry: BiometricUnlock.Biometry {
        BiometricUnlock.availability(allowDevicePassword: allowLoginPassword)
    }

    var body: some View {
        TabView {
            securityTab
                .tabItem { Label("Security", systemImage: "lock.shield") }
            generalTab
                .tabItem { Label("General", systemImage: "gearshape") }
        }
        .frame(width: 420)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var securityTab: some View {
        Form {
            Section("Lock") {
                Picker("Lock after inactivity", selection: $idleMinutes) {
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
            }

            Section("Clipboard") {
                Picker("Clear copied passwords after", selection: $clipboardSeconds) {
                    Text("Never").tag(0)
                    Text("10 seconds").tag(10)
                    Text("30 seconds").tag(30)
                    Text("1 minute").tag(60)
                    Text("2 minutes").tag(120)
                }
                .onChange(of: clipboardSeconds) { _, value in preferences.clipboardClearSeconds = value }
            }

            biometricSection
        }
        .formStyle(.grouped)
    }

    @ViewBuilder
    private var biometricSection: some View {
        if biometry.isAvailable {
            Section {
                Toggle("Unlock with \(biometry.displayName)", isOn: $biometricEnabled)
                    .onChange(of: biometricEnabled) { _, value in
                        preferences.biometricUnlockEnabled = value
                        // Off means off: a key left in the Keychain still opens the vault.
                        if !value { BiometricUnlock.removeAll() }
                    }

                if biometricEnabled {
                    Toggle("Ask when the menu bar icon is clicked", isOn: $promptOnOpen)
                        .onChange(of: promptOnOpen) { _, value in
                            preferences.promptBiometricsOnOpen = value
                        }

                    Toggle("Also accept Mac login password", isOn: $allowLoginPassword)
                        .onChange(of: allowLoginPassword) { _, value in
                            preferences.allowDevicePasswordFallback = value
                            // Part of the stored key's access control, so the key has to
                            // go; the next master-password unlock saves it again.
                            BiometricUnlock.removeAll()
                        }
                        .help("Changing this removes the saved key.")
                }
            } header: {
                Text(biometry.displayName)
            } footer: {
                if biometricEnabled && allowLoginPassword {
                    Text("Anyone who knows your Mac password can unlock the vault.")
                        .foregroundStyle(Design.Palette.warning)
                } else if !BiometricUnlock.availableProtectionLevel.isCryptographicallyBound {
                    Text("Development build: the saved key is not protected by the Keychain.")
                        .foregroundStyle(Design.Palette.warning)
                }
            }
        } else if case .none(let reason) = biometry {
            Section("Touch ID") {
                Text(reason)
                    .foregroundStyle(Design.Palette.secondaryText)
            }
        }
    }

    private var generalTab: some View {
        Form {
            Section("Browsing") {
                Picker("Folders", selection: $browseMode) {
                    ForEach(BrowseMode.allCases, id: \.self) { mode in
                        Text(mode.displayName).tag(mode)
                    }
                }
                .onChange(of: browseMode) { _, value in preferences.browseMode = value }

                Toggle("Show Recycle Bin", isOn: $showRecycleBin)
                    .onChange(of: showRecycleBin) { _, value in preferences.showRecycleBin = value }
            }

            Section("Behavior") {
                Toggle("⌘-click an entry to copy", isOn: $quickCopy)
                    .onChange(of: quickCopy) { _, value in preferences.quickCopy = value }
                    .help("Copies the password, then the one-time code. For cards: number, expiry, security code.")

                Toggle("Offer to reload when the file changes", isOn: $watchFile)
                    .onChange(of: watchFile) { _, value in preferences.watchDatabaseFile = value }
            }
        }
        .formStyle(.grouped)
    }
}
