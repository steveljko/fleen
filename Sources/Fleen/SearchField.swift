import SwiftUI
import AppKit

/// `NSSearchField` wrapped for SwiftUI.
///
/// PLAN.md asks specifically for the AppKit search field rather than a styled
/// `TextField`, and the reason shows up in the details: the native control gets the
/// focus ring, the clear button, the ⌘F/Escape conventions, emoji and dictation
/// support, and the correct VoiceOver role for free. Reimplementing those on top of
/// `TextField` is a lot of work to arrive back where AppKit started.
///
/// It also forwards the arrow keys, so the list below can be driven from the search
/// field without the user ever leaving it — which is what makes the keyboard-only
/// workflow in PLAN.md actually work.
struct SearchField: NSViewRepresentable {
    @Binding var text: String
    var placeholder: String = "Search"
    /// Set true to take first responder; reset to false once taken.
    @Binding var focusRequested: Bool

    var onMoveUp: () -> Void = {}
    var onMoveDown: () -> Void = {}
    var onSubmit: () -> Void = {}
    var onCancel: () -> Void = {}
    /// ← and → drive folder navigation while browsing, so the whole tree can be
    /// walked without the search field ever losing focus.
    var onMoveLeft: () -> Void = {}
    var onMoveRight: () -> Void = {}
    var onMoveToStart: () -> Void = {}
    var onMoveToEnd: () -> Void = {}
    var onPageUp: () -> Void = {}
    var onPageDown: () -> Void = {}

    func makeNSView(context: Context) -> NSSearchField {
        let field = KeyForwardingSearchField()
        field.delegate = context.coordinator
        field.placeholderString = placeholder
        field.sendsSearchStringImmediately = true
        // No debounce by default: PLAN.md asks for instant results, and the index is
        // fast enough that delaying would only add perceived latency. If profiling on
        // a very large database ever says otherwise, this is the one place to change.
        field.sendsWholeSearchString = false
        field.focusRingType = .default
        field.setAccessibilityLabel("Search entries")

        field.onMoveUp = { onMoveUp() }
        field.onMoveDown = { onMoveDown() }
        field.onSubmit = { onSubmit() }
        field.onCancel = { onCancel() }
        field.onMoveLeft = { onMoveLeft() }
        field.onMoveRight = { onMoveRight() }
        field.onMoveToStart = { onMoveToStart() }
        field.onMoveToEnd = { onMoveToEnd() }
        field.onPageUp = { onPageUp() }
        field.onPageDown = { onPageDown() }
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        if field.stringValue != text { field.stringValue = text }
        field.placeholderString = placeholder

        // Re-bind closures each update so they capture current state, not the values
        // they had when the view was first made.
        if let field = field as? KeyForwardingSearchField {
            field.onMoveUp = { onMoveUp() }
            field.onMoveDown = { onMoveDown() }
            field.onSubmit = { onSubmit() }
            field.onCancel = { onCancel() }
            field.onMoveLeft = { onMoveLeft() }
            field.onMoveRight = { onMoveRight() }
            field.onMoveToStart = { onMoveToStart() }
            field.onMoveToEnd = { onMoveToEnd() }
            field.onPageUp = { onPageUp() }
            field.onPageDown = { onPageDown() }
        }

        if focusRequested {
            // Both the focus change and clearing the flag are deferred: mutating a
            // binding from inside `updateNSView` modifies state while SwiftUI is
            // already updating the view, which it warns about and may drop.
            DispatchQueue.main.async {
                guard field.window != nil else { return }
                field.window?.makeFirstResponder(field)
                field.currentEditor()?.selectedRange =
                    NSRange(location: field.stringValue.count, length: 0)
                self.focusRequested = false
            }
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        private let parent: SearchField

        init(_ parent: SearchField) { self.parent = parent }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSSearchField else { return }
            parent.text = field.stringValue
        }
    }
}

/// Forwards the keys a list needs while the search field keeps focus.
private final class KeyForwardingSearchField: NSSearchField {
    var onMoveUp: () -> Void = {}
    var onMoveDown: () -> Void = {}
    var onSubmit: () -> Void = {}
    var onCancel: () -> Void = {}
    /// ← and → drive folder navigation while browsing, so the whole tree can be
    /// walked without the search field ever losing focus.
    var onMoveLeft: () -> Void = {}
    var onMoveRight: () -> Void = {}
    var onMoveToStart: () -> Void = {}
    var onMoveToEnd: () -> Void = {}
    var onPageUp: () -> Void = {}
    var onPageDown: () -> Void = {}

    override func keyDown(with event: NSEvent) {
        switch Int(event.keyCode) {
        case 126: onMoveUp();   return   // ↑
        case 125: onMoveDown(); return   // ↓
        case 36, 76:                     // Return, Enter
            onSubmit(); return
        case 123 where stringValue.isEmpty:   // ← only when not editing text
            onMoveLeft(); return
        case 124 where stringValue.isEmpty:   // → only when not editing text
            onMoveRight(); return
        case 115: onMoveToStart(); return     // Home
        case 119: onMoveToEnd();   return     // End
        case 116: onPageUp();      return     // Page Up
        case 121: onPageDown();    return     // Page Down
        case 53:                         // Escape
            // Escape clears a non-empty search first, and only locks when already
            // empty — the usual two-stage behaviour, rather than dumping the user
            // straight back to the lock screen mid-search.
            if stringValue.isEmpty { onCancel() } else { stringValue = ""; sendAction(action, to: target) }
            return
        default:
            super.keyDown(with: event)
        }
    }
}
