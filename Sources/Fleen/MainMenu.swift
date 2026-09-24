import AppKit
import FleenKit

/// Commands that the main menu sends to whatever view is showing.
///
/// The menu lives on the app delegate while the selection lives in SwiftUI state, so
/// the two are bridged by notification rather than by threading a reference through
/// every view.
extension Notification.Name {
    static let fleenCopyPassword = Notification.Name("fleen.command.copyPassword")
    static let fleenCopyUsername = Notification.Name("fleen.command.copyUsername")
    static let fleenCopyURL = Notification.Name("fleen.command.copyURL")
    static let fleenCopyTOTP = Notification.Name("fleen.command.copyTOTP")
    static let fleenFocusSearch = Notification.Name("fleen.command.focusSearch")
    static let fleenExpandAll = Notification.Name("fleen.command.expandAll")
    static let fleenCollapseAll = Notification.Name("fleen.command.collapseAll")
    /// Locks *and* dismisses the popover. Views post this rather than locking the
    /// session directly, so the two always happen together.
    static let fleenLockVault = Notification.Name("fleen.command.lockVault")
}

/// Builds the application menu.
///
/// **Why a menu-bar-only app still needs one.** `LSUIElement` apps do not display a
/// menu bar, so it is tempting to skip this — but on macOS the main menu is also what
/// *delivers keyboard shortcuts*. With no Edit menu, ⌘A, ⌘C, ⌘V, ⌘X and ⌘Z do nothing
/// in a text field, because nothing is there to route them to the first responder.
/// That is why selecting all in the password field did not work.
///
/// It is also why `.keyboardShortcut` on a SwiftUI `Menu` item inside a popover was
/// unreliable: those only fire while the view is in the responder chain, which a
/// transient popover in an accessory app often is not. Commands that must always work
/// belong here instead.
@MainActor
enum MainMenu {

    static func install(target: AnyObject, settingsAction: Selector) {
        let mainMenu = NSMenu()

        // MARK: Application

        let appItem = NSMenuItem()
        let appMenu = NSMenu()

        let settings = appMenu.addItem(withTitle: "Settings…",
                                       action: settingsAction, keyEquivalent: ",")
        settings.target = target

        appMenu.addItem(.separator())

        // Posted like every other command rather than targeting the delegate directly,
        // so there is one dispatch path to reason about — and so the shortcut self-test
        // actually observes it.
        addCommand(to: appMenu, title: "Lock Vault", notification: .fleenLockVault, key: "l")

        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide Fleen",
                        action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(withTitle: "Quit Fleen",
                        action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        appItem.submenu = appMenu
        mainMenu.addItem(appItem)

        // MARK: Edit — the reason this file exists

        let editItem = NSMenuItem()
        let editMenu = NSMenu(title: "Edit")

        // Undo/redo are not exposed as typed selectors on NSResponder.
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Delete",
                         action: #selector(NSText.delete(_:)), keyEquivalent: "")
        editMenu.addItem(withTitle: "Select All",
                         action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

        editItem.submenu = editMenu
        mainMenu.addItem(editItem)

        // MARK: View — keyboard movement a window menu would normally provide

        let viewItem = NSMenuItem()
        let viewMenu = NSMenu(title: "View")
        addCommand(to: viewMenu, title: "Focus Search",
                   notification: .fleenFocusSearch, key: "f")
        addCommand(to: viewMenu, title: "Expand All Folders",
                   notification: .fleenExpandAll, key: "]")
        addCommand(to: viewMenu, title: "Collapse All Folders",
                   notification: .fleenCollapseAll, key: "[")
        viewItem.submenu = viewMenu
        mainMenu.addItem(viewItem)

        // MARK: Vault

        let vaultItem = NSMenuItem()
        let vaultMenu = NSMenu(title: "Vault")

        // Option-Command, not Shift-Command. ⇧⌘C never fired: the Edit menu is searched
        // first and its Copy item (⌘C, lowercase equivalent) matched the shifted event
        // too, swallowing it. Option avoids the collision, and plain ⌘C stays Copy.
        addCommand(to: vaultMenu, title: "Copy Password",
                   notification: .fleenCopyPassword, key: "c",
                   modifiers: [.command, .option])
        addCommand(to: vaultMenu, title: "Copy Username",
                   notification: .fleenCopyUsername, key: "b",
                   modifiers: [.command, .option])
        addCommand(to: vaultMenu, title: "Copy Address",
                   notification: .fleenCopyURL, key: "u",
                   modifiers: [.command, .option])
        addCommand(to: vaultMenu, title: "Copy One-Time Code",
                   notification: .fleenCopyTOTP, key: "t",
                   modifiers: [.command, .option])

        vaultItem.submenu = vaultMenu
        mainMenu.addItem(vaultItem)

        NSApp.mainMenu = mainMenu
    }

    /// Menu items that broadcast rather than target a specific object.
    private static func addCommand(to menu: NSMenu, title: String,
                                   notification: Notification.Name,
                                   key: String,
                                   modifiers: NSEvent.ModifierFlags = [.command]) {
        let item = NSMenuItem(title: title,
                              action: #selector(CommandRelay.runCommand(_:)),
                              keyEquivalent: key)
        item.keyEquivalentModifierMask = key.isEmpty ? [] : modifiers
        item.representedObject = notification.rawValue
        item.target = CommandRelay.shared
        menu.addItem(item)
    }
}

/// Turns a menu selection into a notification.
@MainActor
final class CommandRelay: NSObject, NSMenuItemValidation {
    static let shared = CommandRelay()

    /// Deliberately NOT named `perform(_:)`.
    ///
    /// `#selector(CommandRelay.perform(_:))` compiles, but resolves to `NSObject`'s
    /// inherited `perform(_:)` — Objective-C `performSelector:`. AppKit then invoked
    /// that with the menu item where a selector was expected, producing a garbage
    /// selector and killing the app on the first keypress:
    ///
    ///     -[Fleen.CommandRelay ±=¸ı]: unrecognized selector sent to instance
    ///
    /// Every main-menu shortcut was dead for this reason. Any name that does not
    /// collide with NSObject's works; this one is explicit about why.
    @objc func runCommand(_ sender: Any?) {
        guard let item = sender as? NSMenuItem,
              let name = item.representedObject as? String else { return }
        NotificationCenter.default.post(name: Notification.Name(name), object: nil)
    }

    /// Greys out commands that have nothing to act on.
    ///
    /// Expanding folders only means something in the outline layout; in drill-down mode
    /// ⌘] and ⌘[ would be live shortcuts that silently did nothing. A disabled item is
    /// also skipped by key-equivalent dispatch, so this covers both the menu and the
    /// keyboard.
    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        guard let name = menuItem.representedObject as? String else { return true }
        switch Notification.Name(name) {
        case .fleenExpandAll, .fleenCollapseAll:
            return Preferences.shared.browseMode == .tree
        default:
            return true
        }
    }
}
