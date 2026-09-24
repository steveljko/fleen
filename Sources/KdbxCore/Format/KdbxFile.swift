import Foundation
import CryptoKit
import Security

/// Reads KDBX4 files. This is the package's entry point.
///
/// **Read-only by design.** Fleen does not write KDBX files at all: the encoder, the
/// header serialiser, the compressor and the encryption paths have been removed rather
/// than merely disabled. A write bug in a password database costs the user their
/// credentials, so the safest version of that code is none. KeePassXC remains the
/// thing that writes.
///
/// Everything here is local: there is not a single network call, URL session, or
/// remote endpoint anywhere in `KdbxCore`, by design and by review. The only I/O is
/// the file the caller names.
public enum KdbxFile {

    // MARK: - Reading

    /// Decrypts and parses a database.
    ///
    /// - Important: run this off the main thread — Argon2 blocks for hundreds of ms.
    public static func open(
        data: Data,
        credentials: CompositeKey
    ) throws -> Database {
        var reader = ByteReader(data)
        let header = try KdbxHeader.parse(&reader)

        // 1. Header integrity: plain SHA-256, detects accidental corruption.
        let storedHash = try reader.readBytes(32)
        let computedHash = Array(SHA256.hash(data: header.rawBytes))
        guard timingSafeCompare(computedHash, storedHash) else {
            throw KdbxError.headerCorrupted
        }

        // 2. Derive keys. This is the expensive step.
        let schedule = try KeySchedule(header: header, compositeKey: credentials)

        // 3. Header authenticity: HMAC under the derived key. A wrong password fails
        //    here, which is where the "wrong credentials" answer legitimately comes
        //    from — before any ciphertext is touched.
        let storedHeaderMac = try reader.readBytes(32)
        let computedHeaderMac = HmacBlockStream.headerMac(header: header.rawBytes, schedule: schedule)
        guard timingSafeCompare(computedHeaderMac, storedHeaderMac) else {
            throw KdbxError.invalidCredentials
        }

        // 4. Authenticate and concatenate the payload blocks, then decrypt.
        let ciphertext = try HmacBlockStream.read(&reader, schedule: schedule)

        // 5. Decompress into exactly ONE owned buffer.
        //
        // Deliberately not `let a = decrypt(); let b = gzip ? inflate(a) : a`. `Data` is
        // copy-on-write, and `SecureBytes.wipe` writes through `withUnsafeMutableBytes`
        // — which, if any other `Data` still shares the buffer, triggers a COW copy and
        // zeroes *that copy*, leaving the original plaintext intact and unreachable.
        // Two aliased values would therefore defeat both wipes. `MemoryHygieneTests`
        // pins this, and a debug-build check inside `wipe` traps if it regresses.
        var payload: Data = try {
            var plaintext = try decrypt(ciphertext, header: header, schedule: schedule)
            guard header.compression == .gzip else { return plaintext }
            defer { SecureBytes.wipe(&plaintext) }
            return try Gzip.decompress(plaintext)
        }()
        defer { SecureBytes.wipe(&payload) }

        // 6. Inner header, then XML — inside a scope, for the same COW reason. The
        //    reader holds a `Data` and `readRest()` hands back a slice of it, both
        //    sharing `payload`'s buffer. They must be released before the deferred wipe
        //    runs, or the wipe hits a copy and the decrypted XML survives in memory.
        //
        //    A Swift scope alone is not enough: `XMLParser` retains the `Data` it is
        //    given and is autoreleased, so it — and the payload buffer with it — outlives
        //    the scope until the pool drains, which by default is long after the wipe.
        //    Hence an explicit `autoreleasepool`. Verified, not assumed: without it the
        //    debug check in `SecureBytes.wipe` traps on every fixture.
        typealias ParsedTree = (meta: DatabaseMeta, root: Group,
                                deleted: [(uuid: UUID, deletionTime: Date)])
        let (parsed, pool): (ParsedTree, [Int: Attachment]) = try autoreleasepool {
            var payloadReader = ByteReader(payload)
            let innerHeader = try KdbxInnerHeader.parse(&payloadReader)
            let xml = payloadReader.readRest()

            let innerStream = try InnerStreamCipher(header: innerHeader)
            let xmlReader = KdbxXmlReader(innerStream: innerStream, binaries: innerHeader.binaries)
            let tree = try xmlReader.parse(xml)

            var pool: [Int: Attachment] = [:]
            for (index, binary) in innerHeader.binaries.enumerated() { pool[index] = binary }
            return (tree, pool)
        }

        return Database(
            meta: parsed.meta,
            rootGroup: parsed.root,
            binaryPool: pool,
            cipher: header.cipher,
            kdf: header.kdf,
            compression: header.compression,
            deletedObjects: parsed.deleted)
    }

    public static func open(
        url: URL,
        credentials: CompositeKey
    ) throws -> Database {
        // Read the whole file up front. The threat model assumes the file may be
        // under a sync client that can swap it mid-read, so we never hold an open
        // handle across the (slow) KDF step and never assume exclusive access.
        let data = try Data(contentsOf: url, options: [.uncached])
        return try open(data: data, credentials: credentials)
    }

    private static func decrypt(_ ciphertext: Data, header: KdbxHeader,
                                schedule: KeySchedule) throws -> Data {
        switch header.cipher {
        case .aes256CBC:
            return try AesCbc.decrypt(key: schedule.cipherKey, iv: header.encryptionIV,
                                      ciphertext: ciphertext)
        case .chacha20:
            var cipher = schedule.cipherKey.withUnsafeBytes {
                ChaCha20(key: $0, nonce: header.encryptionIV, counter: 0)
            }
            return cipher.process(ciphertext)
        }
    }

}

// MARK: - Inspection

/// What can be learned about a database *without* unlocking it.
///
/// The outer header is authenticated but not encrypted, so this is readable with no
/// password at all — which is how `fleen-cli info` reports a database's format, cipher
/// and KDF settings without asking for the master password.
public struct DatabaseInfo: Sendable {
    public let majorVersion: UInt16
    public let minorVersion: UInt16
    public let cipher: KdbxCipher
    public let kdf: KdbxKdf
    public let compression: KdbxCompression
}

extension KdbxFile {
    public static func inspect(data: Data) throws -> DatabaseInfo {
        var reader = ByteReader(data)
        let header = try KdbxHeader.parse(&reader)
        return DatabaseInfo(
            majorVersion: header.majorVersion, minorVersion: header.minorVersion,
            cipher: header.cipher, kdf: header.kdf, compression: header.compression)
    }

    public static func inspect(url: URL) throws -> DatabaseInfo {
        try inspect(data: try Data(contentsOf: url, options: [.uncached]))
    }
}
