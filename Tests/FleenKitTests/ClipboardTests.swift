import Testing
import Foundation
import AppKit
@testable import FleenKit

/// Clipboard behaviour, on a private pasteboard so the developer's real clipboard is
/// never touched by a test run.
@MainActor
@Suite("Clipboard")
struct ClipboardTests {

    static func makeService() -> (ClipboardService, NSPasteboard) {
        let board = NSPasteboard(name: NSPasteboard.Name("com.fleen.tests.\(UUID().uuidString)"))
        return (ClipboardService(pasteboard: board), board)
    }

    @Test("A secret is placed on the pasteboard and marked concealed")
    func copiesSecretConcealed() {
        let (service, board) = Self.makeService()
        service.copySecret("s3cret", clearAfter: 30)

        #expect(board.string(forType: .string) == "s3cret")
        // The marker clipboard managers look for to skip recording an item.
        #expect(board.data(forType: ClipboardService.concealedType) != nil,
                "without this, clipboard managers archive the password to disk")
    }

    @Test("The countdown starts at the configured timeout")
    func startsCountdown() {
        let (service, _) = Self.makeService()
        service.copySecret("x", clearAfter: 30)
        #expect(service.secondsRemaining == 30)
    }

    @Test("A zero timeout means no countdown at all")
    func noCountdownWhenDisabled() {
        let (service, board) = Self.makeService()
        service.copySecret("x", clearAfter: 0)
        #expect(service.secondsRemaining == 0)
        #expect(board.string(forType: .string) == "x", "the value is still copied")
    }

    @Test("Clearing removes our own item and stops the countdown")
    func clearsOurOwnItem() {
        let (service, board) = Self.makeService()
        service.copySecret("s3cret", clearAfter: 30)
        service.clearIfStillOurs()

        #expect(board.string(forType: .string) == nil)
        #expect(service.secondsRemaining == 0)
    }

    @Test("Something the user copied afterwards is left alone")
    func doesNotClearSomeoneElsesItem() {
        let (service, board) = Self.makeService()
        service.copySecret("s3cret", clearAfter: 30)

        // The user copies something of their own; our timer must not eat it.
        board.clearContents()
        board.setString("the user's own text", forType: .string)

        service.clearIfStillOurs()
        #expect(board.string(forType: .string) == "the user's own text")
    }

    @Test("Copying a non-secret leaves no countdown and no concealed marker")
    func copyPlainHasNoCountdown() {
        let (service, board) = Self.makeService()
        service.copySecret("s3cret", clearAfter: 30)
        #expect(service.secondsRemaining == 30)

        service.copyPlain("alice@example.com")
        #expect(service.secondsRemaining == 0,
                "a stale countdown here is what left the toast stuck on screen")
        #expect(board.string(forType: .string) == "alice@example.com")
        #expect(board.data(forType: ClipboardService.concealedType) == nil,
                "a username is not a secret")
    }

    @Test("A second secret copy restarts the countdown rather than stacking")
    func restartsCountdown() {
        let (service, _) = Self.makeService()
        service.copySecret("first", clearAfter: 10)
        service.copySecret("second", clearAfter: 30)
        #expect(service.secondsRemaining == 30)
    }

    @Test("The countdown stops once the pasteboard holds someone else's item")
    func countdownStopsWhenSupersededExternally() async throws {
        let (service, board) = Self.makeService()
        service.copySecret("s3cret", clearAfter: 30)

        board.clearContents()
        board.setString("elsewhere", forType: .string)

        // The ticking task notices on its next tick and stops counting down to a
        // clear that will never happen — which is what left "clears in N s" frozen
        // on screen.
        try await Task.sleep(for: .milliseconds(1_200))
        #expect(service.secondsRemaining == 0)
        #expect(board.string(forType: .string) == "elsewhere")
    }
}
