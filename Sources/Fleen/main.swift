import AppKit

// Hand-rolled entry point rather than `@main` + `SwiftUI.App`: this is a menu bar
// utility that owns an NSStatusItem and has no main window, which the SwiftUI App
// lifecycle still makes awkward. AppKit gives direct control over activation policy
// and the status item, and costs nothing at this size.

let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.run()
