import Foundation
import CryptoKit

/// Watches the `.kdbx` file for changes made by something else — KeePassXC on the
/// same Mac, or a sync client dropping in a newer copy.
///
/// Two complications this handles that a naive `DispatchSource` watcher does not:
///
/// * **Atomic replacement.** Almost nothing edits a database in place; KeePassXC and
///   every sync client write a temporary file and rename it over the original. The
///   original inode is then gone, and a watcher holding that file descriptor goes
///   permanently deaf. So a `.delete`/`.rename` event re-arms the watch on the path.
///
/// * **Our own writes.** Saving would otherwise immediately report "the file changed
///   externally". A SHA-256 of the file contents is recorded on every save and every
///   load, and an event whose digest matches what we last wrote is ignored.
public final class DatabaseFileWatcher: @unchecked Sendable {

    private let url: URL
    private let queue = DispatchQueue(label: "com.fleen.file-watcher")
    private var source: DispatchSourceFileSystemObject?
    private var descriptor: CInt = -1
    private var knownDigest: String?
    private var handler: (() -> Void)?
    private var rearmWork: DispatchWorkItem?

    public init(url: URL) {
        self.url = url
    }

    deinit {
        // Deliberately not `cancel()`: that uses `queue.sync`, which deadlocks if the
        // last reference is released on the watcher's own queue. Tearing the source
        // down asynchronously is safe because it owns its file descriptor and closes
        // it in its cancel handler.
        source?.cancel()
    }

    /// Starts watching. `onExternalChange` is called on the main queue, coalesced.
    public func start(onExternalChange: @escaping () -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.handler = onExternalChange
            self.knownDigest = Self.digest(of: self.url)
            self.arm()
        }
    }

    /// Stops watching. Safe to call from any queue except the watcher's own.
    public func cancel() {
        queue.sync {
            rearmWork?.cancel()
            rearmWork = nil
            source?.cancel()
            source = nil
            handler = nil
        }
    }

    /// Records the contents we just wrote, so the resulting event is not mistaken
    /// for somebody else's edit. Call immediately after saving.
    public func noteOurOwnWrite() {
        queue.async { [weak self] in
            guard let self else { return }
            self.knownDigest = Self.digest(of: self.url)
        }
    }

    // MARK: - Internals

    private func arm() {
        dispatchPrecondition(condition: .onQueue(queue))
        source?.cancel()
        source = nil

        descriptor = open(url.path, O_EVTONLY)
        guard descriptor >= 0 else {
            // The file is gone for the moment — typical mid-replacement. Try again
            // shortly rather than giving up on the watch entirely.
            scheduleRearm(after: .milliseconds(300))
            return
        }

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: descriptor,
            eventMask: [.write, .extend, .delete, .rename, .revoke],
            queue: queue)

        source.setEventHandler { [weak self] in
            guard let self, let source = self.source else { return }
            let events = source.data

            if events.contains(.delete) || events.contains(.rename) || events.contains(.revoke) {
                // Replaced or moved: re-arm on the path, then evaluate.
                self.scheduleRearm(after: .milliseconds(150))
            } else {
                // Writes can arrive in bursts as a file is streamed out; settle first.
                self.scheduleCheck(after: .milliseconds(400))
            }
        }

        source.setCancelHandler { [descriptor = self.descriptor] in
            if descriptor >= 0 { close(descriptor) }
        }

        self.source = source
        source.resume()
    }

    private func scheduleRearm(after delay: DispatchTimeInterval) {
        rearmWork?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.arm()
            self.checkForChange()
        }
        rearmWork = work
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private func scheduleCheck(after delay: DispatchTimeInterval) {
        rearmWork?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.checkForChange() }
        rearmWork = work
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private func checkForChange() {
        dispatchPrecondition(condition: .onQueue(queue))
        guard let digest = Self.digest(of: url) else { return }
        guard digest != knownDigest else { return }   // our own write, or a no-op touch
        knownDigest = digest

        guard let handler else { return }
        DispatchQueue.main.async(execute: handler)
    }

    /// SHA-256 of the file. Hashing the ciphertext is cheap (these files are small)
    /// and, unlike a modification date, does not fire on a touch that changed nothing.
    private static func digest(of url: URL) -> String? {
        guard let data = try? Data(contentsOf: url, options: [.uncached]) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
