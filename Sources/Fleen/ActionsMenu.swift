import SwiftUI
import AppKit

/// A native pull-down menu for the actions button.
///
/// Built as an `NSMenu` rather than a SwiftUI `Menu` for one specific reason: AppKit
/// draws key equivalents right-aligned in the standard way, which is what a macOS menu
/// looks like. Writing them into the titles ("Copy Password ⇧⌘C") was a workaround and
/// looked like one.
///
/// It also avoids a dispatch problem. Shortcuts on SwiftUI `Menu` items are unreliable
/// inside a transient popover, which is why the working ones live in `MainMenu`. A
/// standalone `NSMenu` popped up by hand takes no part in global key-equivalent
/// dispatch — its `keyEquivalent`s are drawn but not registered — so the main menu stays
/// the single owner of every shortcut and nothing fires twice.
enum MenuEntry {
    case header(String)
    case separator
    case item(title: String,
              key: String = "",
              modifiers: NSEvent.ModifierFlags = .command,
              enabled: Bool = true,
              action: () -> Void)
}

/// Holds the `NSView` the menu is positioned against.
@MainActor
final class MenuAnchorBox {
    weak var view: NSView?
}

/// An invisible AppKit view that gives the menu something to anchor to, so the SwiftUI
/// button keeps its own styling.
struct MenuAnchor: NSViewRepresentable {
    let box: MenuAnchorBox

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        box.view = view
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        box.view = nsView
    }
}

@MainActor
enum ActionsMenuPresenter {

    /// Builds and shows the menu under `box`'s view.
    static func present(entries: [MenuEntry], from box: MenuAnchorBox) {
        guard let anchor = box.view else { return }

        let menu = NSMenu()
        menu.autoenablesItems = false

        for entry in entries {
            switch entry {
            case .header(let title):
                menu.addItem(.sectionHeader(title: title))
            case .separator:
                menu.addItem(.separator())
            case .item(let title, let key, let modifiers, let enabled, let action):
                let item = NSMenuItem(title: title,
                                      action: #selector(MenuActionTarget.runAction),
                                      keyEquivalent: key)
                item.keyEquivalentModifierMask = key.isEmpty ? [] : modifiers
                item.isEnabled = enabled
                // The target is retained by the item, and the item by the menu, so the
                // closure outlives this call.
                let target = MenuActionTarget(action: action)
                item.target = target
                item.representedObject = target
                menu.addItem(item)
            }
        }

        // Position under the button's bottom edge. Which y that is depends on the
        // view's coordinate system — SwiftUI's backing views are flipped, plain AppKit
        // views are not — so ask rather than assume.
        let bottomEdge = anchor.isFlipped ? anchor.bounds.maxY : anchor.bounds.minY
        let origin = NSPoint(x: anchor.bounds.minX, y: bottomEdge)
        menu.popUp(positioning: nil, at: origin, in: anchor)
    }
}

/// Carries a closure into the AppKit target/action world.
@MainActor
private final class MenuActionTarget: NSObject {
    private let action: () -> Void

    init(action: @escaping () -> Void) {
        self.action = action
        super.init()
    }

    @objc func runAction() { action() }
}
