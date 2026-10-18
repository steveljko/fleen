import SwiftUI
import AppKit
import FleenKit

/// Menu bar lifecycle.
///
/// The popover's content view is built **once**, at launch, and reused. PLAN.md asks
/// for the menu bar item to open instantly, and the usual cause of a stutter on first
/// click is SwiftUI constructing and laying out the hierarchy at that moment. Building
/// it up front moves that cost to launch, where nobody is waiting on it.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {

    private let preferences = Preferences.shared
    private let session = VaultSession()
    private let autoLock = AutoLockController()
    private let presentation = PopoverPresentation()

    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var resignObserver: (any NSObjectProtocol)?
    private var becomeActiveObserver: (any NSObjectProtocol)?
    /// Watches for clicks anywhere outside the popover while it is open.
    private var outsideClickMonitor: Any?
    private var settingsObservers: [any NSObjectProtocol] = []

    /// Set FLEEN_DIAG=1 to log launch state. A menu bar app that fails to show its
    /// icon looks identical to one that never launched, so there has to be some way
    /// to tell the two apart without a debugger.
    private func diag(_ message: String) {
        Diagnostics.log(message, category: "app")
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        diag("didFinishLaunching entered; log at \(Diagnostics.fileURL?.path ?? "?")")
        // Earlier builds could leave the composite key in the legacy keychain with no
        // OS-level gate. A release build never reads such an item; remove it.
        BiometricUnlock.purgeUnprotectedKeys()
        // Menu bar utility: no Dock icon, no menu bar app menu, unless asked for.
        enforceActivationPolicy(reason: "launch")

        // Installs the Edit menu that makes ⌘A/⌘C/⌘V/⌘X/⌘Z work in text fields, and
        // the Vault menu whose shortcuts fire regardless of the responder chain.
        MainMenu.install(target: self, settingsAction: #selector(showSettings))

        setUpStatusItem()
        prewarmPopover()

        // Open the popover on first launch. Without this, starting a menu bar app
        // with no Dock icon and no window produces no visible feedback at all — the
        // user is left hunting the menu bar for an icon they have never seen before.
        if preferences.rememberedDatabase() == nil {
            DispatchQueue.main.async { [weak self] in self?.openPopover() }
        }

        // If anything puts the app back into `.regular`, take it out again at the next
        // activation — that is the moment a Dock tile would become visible.
        becomeActiveObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.enforceActivationPolicy(reason: "didBecomeActive") }
        }

        // Close the popover as soon as the app loses focus.
        //
        // `.transient` closes on a click *outside* the popover, but it does not cover
        // switching away with ⌘-Tab, Mission Control, or another app stealing focus —
        // which would leave an unlocked vault open on screen behind whatever the user
        // moved to. This closes it on any loss of activation.
        resignObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didResignActiveNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let popover = self.popover, popover.isShown else { return }
                // Settings is a real window belonging to this app; opening it must not
                // be treated as walking away.
                guard !SettingsWindowController.shared.isVisible else { return }
                popover.performClose(nil)
            }
        }

        settingsObservers.append(NotificationCenter.default.addObserver(
            forName: .fleenLockVault, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.lockVault() }
        })

        autoLock.start { [weak self] reason in
            // Also while unlocking: the session discards a KDF result that finishes
            // after a lock, so locking mid-unlock is what keeps the vault shut.
            guard let self, self.session.state.isUnlocked || self.session.state.isBusy
            else { return }
            self.presentation.suppressBiometricPrompt()
            self.session.lock(reason: reason)
            self.popover?.performClose(nil)
            self.presentation.closed()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Leaving a password on the clipboard after quitting would outlive every
        // other protection in the app.
        ClipboardService.shared.clearIfStillOurs()
        session.lock()
        autoLock.stop()
        stopWatchingForOutsideClicks()
        if let resignObserver { NotificationCenter.default.removeObserver(resignObserver) }
        for observer in settingsObservers { NotificationCenter.default.removeObserver(observer) }
        preferences.releaseFileAccess()
    }

    /// Self-test: asks the main menu to handle each shortcut and reports whether it
    /// matched and whether the command reached a receiver.
    ///
    /// Run with FLEEN_SELFTEST=1. Exists because "the shortcut does not work" has two
    /// very different causes — the menu not matching the key equivalent, or the
    /// notification not reaching the view — and they need different fixes.
    private func runShortcutSelfTest() {
        let cases: [(String, String, NSEvent.ModifierFlags, UInt16, Notification.Name)] = [
            ("Copy Password", "c", [.command, .option], 8, .fleenCopyPassword),
            ("Copy Username", "b", [.command, .option], 11, .fleenCopyUsername),
            ("Copy Address",  "u", [.command, .option], 32, .fleenCopyURL),
            ("Copy TOTP",     "t", [.command, .option], 17, .fleenCopyTOTP),
            ("Focus Search",  "f", [.command], 3, .fleenFocusSearch),
            ("Lock Vault",    "l", [.command], 37, .fleenLockVault),
        ]

        for (name, key, modifiers, keyCode, notification) in cases {
            var received = false
            let token = NotificationCenter.default.addObserver(
                forName: notification, object: nil, queue: nil
            ) { _ in received = true }

            let shifted = modifiers.contains(.shift) ? key.uppercased() : key
            guard let event = NSEvent.keyEvent(
                with: .keyDown, location: .zero, modifierFlags: modifiers,
                timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: 0,
                context: nil, characters: shifted,
                charactersIgnoringModifiers: key, isARepeat: false, keyCode: keyCode
            ) else {
                NSLog("FLEEN-DIAG: selftest %@: could not build event", name)
                NotificationCenter.default.removeObserver(token)
                continue
            }

            let matched = NSApp.mainMenu?.performKeyEquivalent(with: event) ?? false
            NotificationCenter.default.removeObserver(token)
            NSLog("FLEEN-DIAG: selftest %@: menu matched=%@ delivered=%@",
                  name, matched ? "YES" : "NO", received ? "YES" : "NO")
        }
    }

    // MARK: Status item

    private func setUpStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = NSImage(systemSymbolName: "key.horizontal.fill",
                                     accessibilityDescription: "Fleen")
        item.button?.image?.isTemplate = true
        item.button?.target = self
        item.button?.action = #selector(togglePopover(_:))
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
        item.button?.setAccessibilityLabel("Fleen password vault")
        // If the symbol ever fails to resolve, a button with no image and no title
        // is zero-width — an invisible status item, indistinguishable from a crash.
        // A text fallback guarantees there is always something to click.
        if item.button?.image == nil {
            item.button?.title = "Fleen"
        }

        statusItem = item
        diag("statusItem visible=\(item.isVisible) image=\(item.button?.image != nil)")
    }

    private func prewarmPopover() {
        let popover = NSPopover()
        popover.behavior = .transient
        popover.animates = !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        popover.delegate = self
        popover.contentSize = NSSize(width: Design.Metrics.popoverWidth,
                                     height: Design.Metrics.popoverHeight)

        let hosting = NSHostingController(
            rootView: RootView(session: session, preferences: preferences,
                               presentation: presentation))
        // Deliberately *not* `sizingOptions = [.preferredContentSize]`. That let the
        // popover follow the SwiftUI content's own height, which meant it resized on
        // every navigation — a compact popover for a small folder, a tall one for a
        // long list, jumping between the two as the user moved around. The size is
        // fixed by `popover.contentSize` above and held for every state.
        popover.contentViewController = hosting
        self.popover = popover

        // Force the hosting view to lay out now rather than on first display.
        _ = popover.contentViewController?.view
        diag("popover prewarmed")
        diag("sandboxed = \(ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil)")

        if ProcessInfo.processInfo.environment["FLEEN_SELFTEST"] == "1" {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                MainActor.assumeIsolated { self?.runShortcutSelfTest() }
            }
        }
    }

    @objc private func togglePopover(_ sender: Any?) {
        guard let popover, let button = statusItem?.button else { return }

        if popover.isShown {
            popover.performClose(sender)
            presentation.closed()
            stopWatchingForOutsideClicks()
            return
        }

        // Right-click gets a plain menu; left-click opens the vault.
        if let event = NSApp.currentEvent, event.type == .rightMouseUp {
            showContextMenu(from: button)
            return
        }

        if shouldPromptBiometricsBeforeOpening {
            unlockWithBiometricsThenOpen()
            return
        }

        openPopover()
    }

    // MARK: - Touch ID before the popover

    /// Whether this click should raise the biometric prompt on its own, with no window
    /// behind it.
    ///
    /// Every condition has to hold, because the failure mode of getting this wrong is a
    /// click that appears to do nothing at all: the popover never opens and the only
    /// feedback is a system panel that may not have appeared.
    private var shouldPromptBiometricsBeforeOpening: Bool {
        session.shouldPromptBiometricsBeforeOpening && !isPromptingBeforeOpen
    }

    /// Guards against a second click while the panel is already up. `VaultSession` has
    /// its own re-entrancy guard, but it would silently drop the second attempt and
    /// leave this click doing nothing visible.
    private var isPromptingBeforeOpen = false

    private func unlockWithBiometricsThenOpen() {
        isPromptingBeforeOpen = true
        // An accessory app is not active, and a modal panel raised from a background
        // app can end up behind other windows — which is exactly how an earlier
        // version produced a prompt sound with nothing on screen.
        NSApp.activate(ignoringOtherApps: true)
        diag("biometric prompt requested before opening the popover")

        Task { @MainActor in
            defer { isPromptingBeforeOpen = false }
            // A click is deliberate intent, so it clears any earlier decline — the same
            // rule the Touch ID button on the lock screen follows.
            await session.unlockWithBiometrics(userInitiated: true)

            openPopover()
            // Whatever happened, this click has had its one biometric attempt. Without
            // this the lock screen's own automatic prompt would fire a second panel a
            // moment after a cancelled or failed one.
            presentation.suppressBiometricPrompt()
            diag("biometric prompt finished, unlocked=\(session.state.isUnlocked)")
        }
    }

    private func openPopover() {
        guard let popover, let button = statusItem?.button else { return }
        // Before activating: activation is what makes a Dock tile appear, so the policy
        // has to be right on the way in, not corrected afterwards.
        enforceActivationPolicy(reason: "openPopover")
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        // Keep revealed passwords and one-time codes out of screenshots, screen
        // recordings and screen sharing. The window only exists once shown.
        popover.contentViewController?.view.window?.sharingType = .none
        // Without this the popover's text fields cannot take key input, because an
        // accessory-policy app is not active by default.
        NSApp.activate(ignoringOtherApps: true)

        if let window = popover.contentViewController?.view.window {
            window.makeKey()
            // Join the key-view loop explicitly. A popover's window does not set this
            // up on its own, which is why Tab did not move between the password field
            // and the buttons under Full Keyboard Access.
            window.initialFirstResponder = popover.contentViewController?.view
            window.recalculateKeyViewLoop()
        }

        presentation.opened()
        startWatchingForOutsideClicks()
    }

    /// Closes the popover when the user clicks anywhere else, the way every other menu
    /// bar app behaves.
    ///
    /// `NSPopover.behavior = .transient` is supposed to do this, and does not do it
    /// reliably for a status-item popover in an accessory app: activating the app to
    /// make the popover's window key interferes with the event monitoring `.transient`
    /// depends on, so clicks in other applications could leave it open. A global mouse
    /// monitor is what menu bar apps use instead. Mouse events need no Accessibility
    /// permission — only keyboard monitoring does.
    private func startWatchingForOutsideClicks() {
        stopWatchingForOutsideClicks()
        outsideClickMonitor = NSEvent.addGlobalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown]
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let popover = self.popover, popover.isShown else { return }
                // A global monitor only sees clicks outside this app's windows, so
                // anything arriving here is by definition outside the popover.
                popover.performClose(nil)
            }
        }
    }

    private func stopWatchingForOutsideClicks() {
        if let outsideClickMonitor { NSEvent.removeMonitor(outsideClickMonitor) }
        outsideClickMonitor = nil
    }

    // MARK: - NSPopoverDelegate

    func popoverDidClose(_ notification: Notification) {
        presentation.closed()
        // Nothing to watch for once it is closed; leaving the monitor installed would
        // wake the app on every click for the rest of the session.
        stopWatchingForOutsideClicks()
    }

    private func showContextMenu(from button: NSStatusBarButton) {
        let menu = NSMenu()
        if session.state.isUnlocked {
            menu.addItem(withTitle: "Lock Vault", action: #selector(lockVault), keyEquivalent: "l")
                .target = self
        }
        menu.addItem(withTitle: "Settings…", action: #selector(showSettings), keyEquivalent: ",")
            .target = self
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit Fleen", action: #selector(NSApplication.terminate(_:)),
                     keyEquivalent: "q")

        statusItem?.menu = menu
        button.performClick(nil)
        statusItem?.menu = nil   // restore click-to-open behaviour
    }

    @objc private func lockVault() {
        // Locking always closes the popover. Leaving it open would swap in the unlock
        // screen, whose automatic biometric prompt then fires — so the user asks to
        // lock and is immediately shown a Touch ID panel.
        presentation.suppressBiometricPrompt()
        session.lock()
        popover?.performClose(nil)
        presentation.closed()
        stopWatchingForOutsideClicks()
    }

    /// The policy this build should be in.
    private var desiredActivationPolicy: NSApplication.ActivationPolicy {
        preferences.showInDock ? .regular : .accessory
    }

    /// Re-asserts the activation policy, and says so when it had drifted.
    ///
    /// Setting it once at launch is *supposed* to be enough. This exists because a Dock
    /// icon was reported for a build that had `LSUIElement` set and had been put in
    /// `.accessory` at launch, and nothing in this code ever asks for `.regular`. Rather
    /// than guess at which system interaction flips it — a panel, a prompt, an
    /// activation — the policy is re-applied whenever the app becomes active, and the
    /// drift is logged so the trigger can be identified rather than theorised about.
    private func enforceActivationPolicy(reason: String) {
        let desired = desiredActivationPolicy
        let current = NSApp.activationPolicy()
        guard current != desired else { return }
        if reason != "launch" {
            diag("activation policy drifted to \(current.rawValue) at \(reason); "
                 + "restoring \(desired.rawValue)")
        }
        NSApp.setActivationPolicy(desired)
    }

    @objc private func showSettings() {
        SettingsWindowController.shared.show(preferences: preferences)
    }
}

/// Switches between the lock screen and the vault.
struct RootView: View {
    @Bindable var session: VaultSession
    let preferences: Preferences
    let presentation: PopoverPresentation

    var body: some View {
        Group {
            switch session.state {
            case .empty:
                StatusMessageView(
                    symbol: "doc.badge.plus",
                    title: "No database yet",
                    message: "Choose a KeePass .kdbx file to get started.",
                    actionTitle: "Open Database…",
                    action: chooseDatabase)
                .frame(width: Design.Metrics.popoverWidth, height: Design.Metrics.popoverHeight)

            case .unlocked:
                VaultView(session: session, preferences: preferences)

            case .locked, .unlocking, .failed:
                UnlockView(session: session, preferences: preferences,
                           presentation: presentation)
            }
        }
        // Materials rather than a flat fill, so the popover sits in the system's
        // visual language instead of looking like a pasted-on rectangle.
        .background(.regularMaterial)
    }

    private func chooseDatabase() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowsOtherFileTypes = true
        panel.message = "Choose a KeePass database (.kdbx)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try session.select(url: url) }
        catch { NSAlert(error: error).runModal() }
    }
}
