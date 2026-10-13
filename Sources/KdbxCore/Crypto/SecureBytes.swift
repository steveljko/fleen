import Foundation

/// A heap buffer that zeroes itself on deallocation.
///
/// Every byte of key material in this package lives in one of these. The rule the
/// rest of the code relies on: a `SecureBytes` never hands out a copy that escapes
/// the caller's scope — you get the bytes inside `withUnsafeBytes` and that is all.
/// `Data` and `[UInt8]` are deliberately *not* used for keys: both can be copied,
/// grown and reallocated behind your back, leaving stale plaintext key material
/// scattered across the heap with no way to find it again.
public final class SecureBytes: @unchecked Sendable {
    private let storage: UnsafeMutableRawPointer
    public let count: Int

    /// Whether this buffer is pinned in physical memory.
    ///
    /// Not a guarantee: `mlock` has a per-process limit (`RLIMIT_MEMLOCK`) and can fail,
    /// and failing is not a reason to refuse to open a database. Recorded so the deinit
    /// knows whether to unlock, and so the state is inspectable rather than assumed.
    private let isLocked: Bool

    /// Allocates `count` zeroed bytes, pinned in memory where the OS allows it.
    public init(count: Int) {
        precondition(count >= 0)
        self.count = count
        // A page-aligned allocation we own outright, so `wipe()` on deinit is
        // guaranteed to hit the same memory the key was written into.
        self.storage = UnsafeMutableRawPointer.allocate(
            byteCount: max(count, 1), alignment: 16)
        self.storage.initializeMemory(as: UInt8.self, repeating: 0, count: max(count, 1))

        // Pin the pages so the key cannot be written to swap. Zeroing on deinit is
        // worthless if a copy was paged out first — that copy is on disk, outside this
        // process's reach, and nothing here can erase it. macOS encrypts swap by
        // default, which narrows the exposure but does not remove it: the swap key
        // lives for the boot, so a hibernation image or a live-memory capture still
        // contains the plaintext.
        self.isLocked = mlock(self.storage, max(count, 1)) == 0
    }

    public convenience init(_ bytes: [UInt8]) {
        self.init(count: bytes.count)
        bytes.withUnsafeBytes { src in
            if let base = src.baseAddress { storage.copyMemory(from: base, byteCount: bytes.count) }
        }
    }

    public convenience init(_ data: Data) {
        self.init(count: data.count)
        data.withUnsafeBytes { src in
            if let base = src.baseAddress { storage.copyMemory(from: base, byteCount: data.count) }
        }
    }

    /// Takes a UTF-8 password from a `String` and immediately wipes the interim buffer.
    ///
    /// Caveat, stated plainly because it matters: the `String` the caller passes in is
    /// still a heap allocation we do not own and cannot zero. Callers on the UI side
    /// must source passwords from a buffer they control, not from a long-lived `String`.
    public static func fromUTF8(_ string: String) -> SecureBytes {
        var scratch = Array(string.utf8)
        defer { Self.wipe(&scratch) }
        return SecureBytes(scratch)
    }

    deinit {
        memset_s(storage, count, 0, count)
        // Unlock only after zeroing: unlocking first would allow the pages to be paged
        // out in the window before the wipe, which is the exact thing being prevented.
        if isLocked { munlock(storage, max(count, 1)) }
        storage.deallocate()
    }

    /// Whether this buffer is pinned in physical memory, for diagnostics and tests.
    public var isMemoryLocked: Bool { isLocked }

    /// Read-only access to the raw bytes. The pointer is valid only for the call.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: storage, count: count))
    }

    /// Mutable access, for filling a freshly allocated buffer in place.
    public func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeMutableRawBufferPointer(start: storage, count: count))
    }

    /// Escape hatch for the few APIs that demand a `Data` (CommonCrypto, CryptoKit).
    /// Every use is a deliberate, reviewed leak of key material into unmanaged memory;
    /// keep the returned value's lifetime as short as possible.
    public func unsafeData() -> Data {
        withUnsafeBytes { Data($0) }
    }

    public func isEqual(to other: SecureBytes) -> Bool {
        guard count == other.count else { return false }
        return withUnsafeBytes { a in
            other.withUnsafeBytes { b in
                timingSafeCompare(a, b)
            }
        }
    }

    /// Overwrites an array in place. `memset_s` is the variant the optimiser is
    /// forbidden to elide, which is the entire point.
    public static func wipe<T: FixedWidthInteger>(_ bytes: inout [T]) {
        bytes.withUnsafeMutableBytes { buf in
            if let base = buf.baseAddress { _ = memset_s(base, buf.count, 0, buf.count) }
        }
    }

    /// Zeroes a `Data` in place.
    ///
    /// **`Data` is copy-on-write, and that makes this fragile in a way worth stating.**
    /// `withUnsafeMutableBytes` on a buffer some other `Data` still shares will copy
    /// first and zero *the copy* — the original plaintext survives at an address nothing
    /// can reach again. Any slice counts as a sharer, and `data[n...]` is a slice.
    ///
    /// So every caller must hold the only reference when it wipes. In debug builds that
    /// is checked rather than trusted: if the backing buffer moves across the write, a
    /// copy was made and the wipe did not do what the caller believes.
    public static func wipe(_ data: inout Data,
                            file: StaticString = #fileID, line: UInt = #line) {
        #if DEBUG
        let addressBefore = data.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
        #endif
        data.withUnsafeMutableBytes { buf in
            if let base = buf.baseAddress { _ = memset_s(base, buf.count, 0, buf.count) }
        }
        #if DEBUG
        let addressAfter = data.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
        assert(data.isEmpty || addressBefore == addressAfter,
               """
               SecureBytes.wipe hit a copy-on-write copy at \(file):\(line) — another \
               Data (often a slice) still shares this buffer, so the original plaintext \
               was NOT zeroed. Release the other references before wiping.
               """)
        #endif
    }
}

/// Constant-time comparison. Used for every MAC and header-hash check, so that a
/// caller cannot learn where a forged value first diverges by timing the rejection.
@inlinable
public func timingSafeCompare(_ a: UnsafeRawBufferPointer, _ b: UnsafeRawBufferPointer) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count { diff |= a[i] ^ b[i] }
    return diff == 0
}

@inlinable
public func timingSafeCompare(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    a.withUnsafeBytes { ab in b.withUnsafeBytes { bb in timingSafeCompare(ab, bb) } }
}
