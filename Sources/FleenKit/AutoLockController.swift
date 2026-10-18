import Foundation
import AppKit

/// Decides when the vault should lock itself.
///
/// Three independent triggers, each individually switchable in Settings:
///
/// * **Idle** — measured with `CGEventSourceSecondsSinceLastEventType`, which
///   reports *system-wide* input idleness. That is the correct signal: the user
///   walking away from the Mac is what matters, not whether our own window happened
///   to have focus. It also needs no Accessibility permission, unlike an event tap.
/// * **Screen lock** — a distributed notification, the only public signal for it.
/// * **Sleep** — `NSWorkspace.willSleepNotification`.
/// * **Switching user** — `NSWorkspace.sessionDidResignActiveNotification`. Fast user
///   switching does not lock the screen, so without this the vault stayed open in the
///   background session until the idle timer caught it. Not switchable: there is no
///   reason to keep a vault open in a session nobody is sitting at.
@MainActor
public final class AutoLockController {

    public enum Reason: Sendable, Equatable {
        case idleTimeout(minutes: Int)
        case screenLocked
        case systemSleep
        case userSwitched
        case manual

        public var explanation: String {
            switch self {
            case .idleTimeout(let minutes):
                return "Locked after \(minutes) minute\(minutes == 1 ? "" : "s") of inactivity."
            case .screenLocked: return "Locked because the screen was locked."
            case .systemSleep:  return "Locked because the Mac went to sleep."
            case .userSwitched: return "Locked because you switched to another user."
            case .manual:       return ""
            }
        }
    }

    private let preferences: Preferences
    private var timer: Timer?
    /// Kept apart because they must be removed from the centre that created them;
    /// removing a workspace observer from the distributed centre silently does nothing.
    private var workspaceObservers: [any NSObjectProtocol] = []
    private var distributedObservers: [any NSObjectProtocol] = []
    private var onLock: ((Reason) -> Void)?

    /// How often idleness is sampled. A timer rather than an event tap, so the app
    /// needs no special permission just to know the Mac is idle.
    private let pollInterval: TimeInterval = 15

    public init(preferences: Preferences = .shared) {
        self.preferences = preferences
    }

    // No deinit teardown: `Timer` is not Sendable, so it cannot be touched from a
    // nonisolated deinit. Callers own the lifetime and call `stop()`; the app does so
    // when the vault locks.

    /// Starts watching. `handler` is called on the main actor when the vault should lock.
    public func start(onLock handler: @escaping (Reason) -> Void) {
        stop()
        self.onLock = handler

        let timer = Timer(timeInterval: pollInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.checkIdle() }
        }
        // .common so the timer keeps firing while a menu or popover is tracking.
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer

        let workspace = NSWorkspace.shared.notificationCenter
        workspaceObservers.append(workspace.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.preferences.lockOnSleep else { return }
                self.onLock?(.systemSleep)
            }
        })

        workspaceObservers.append(workspace.addObserver(
            forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.onLock?(.userSwitched) }
        })

        distributedObservers.append(DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.preferences.lockOnScreenLock else { return }
                self.onLock?(.screenLocked)
            }
        })
    }

    public func stop() {
        timer?.invalidate()
        timer = nil
        let workspace = NSWorkspace.shared.notificationCenter
        for observer in workspaceObservers { workspace.removeObserver(observer) }
        for observer in distributedObservers {
            DistributedNotificationCenter.default().removeObserver(observer)
        }
        workspaceObservers.removeAll()
        distributedObservers.removeAll()
        onLock = nil
    }

    private func checkIdle() {
        let minutes = preferences.idleLockMinutes
        guard minutes > 0 else { return }
        guard Self.systemIdleSeconds() >= Double(minutes) * 60 else { return }
        onLock?(.idleTimeout(minutes: minutes))
    }

    /// Seconds since the last system-wide input event.
    public static func systemIdleSeconds() -> TimeInterval {
        // kCGAnyInputEventType is 0xFFFFFFFF. Built without a force unwrap so a
        // future SDK change cannot turn this into a launch-time crash.
        guard let anyInput = CGEventType(rawValue: ~UInt32(0)) else { return 0 }
        return CGEventSource.secondsSinceLastEventType(.combinedSessionState,
                                                      eventType: anyInput)
    }
}
