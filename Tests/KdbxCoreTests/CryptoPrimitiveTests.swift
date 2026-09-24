import Testing
import Foundation
import Security
import zlib
@testable import KdbxCore

/// Known-answer tests for the two primitives this package implements itself.
/// If any of these fail, nothing else in the suite means anything.
@Suite("Crypto primitives")
struct CryptoPrimitiveTests {

    // MARK: ChaCha20 — RFC 8439

    @Test("RFC 8439 §2.4.2 keystream encrypts the sunscreen plaintext")
    func chacha20RFC8439() throws {
        let key = (0..<32).map { UInt8($0) }
        let nonce: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0]
        let plaintext = Array("""
            Ladies and Gentlemen of the class of '99: If I could offer you \
            only one tip for the future, sunscreen would be it.
            """.utf8)

        // First 16 bytes of the expected ciphertext from the RFC.
        let expectedPrefix: [UInt8] = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
            0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81
        ]

        let secureKey = SecureBytes(key)
        var buffer = plaintext
        var cipher = secureKey.withUnsafeBytes { ChaCha20(key: $0, nonce: nonce, counter: 1) }
        cipher.process(&buffer)

        #expect(Array(buffer.prefix(16)) == expectedPrefix)

        // And it round-trips.
        var decipher = secureKey.withUnsafeBytes { ChaCha20(key: $0, nonce: nonce, counter: 1) }
        decipher.process(&buffer)
        #expect(buffer == plaintext)
    }

    @Test("ChaCha20 keystream for the all-zero key and nonce")
    func chacha20ZeroVector() throws {
        // RFC 8439 §2.3.2 test vector 1: 64 zero bytes under a zero key/nonce.
        let expected: [UInt8] = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
            0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
            0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
            0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7
        ]
        let key = SecureBytes([UInt8](repeating: 0, count: 32))
        var buffer = [UInt8](repeating: 0, count: 32)
        var cipher = key.withUnsafeBytes {
            ChaCha20(key: $0, nonce: [UInt8](repeating: 0, count: 12), counter: 0)
        }
        cipher.process(&buffer)
        #expect(buffer == expected)
    }

    @Test("ChaCha20 handles data spanning many blocks and arbitrary split points")
    func chacha20BlockBoundaries() throws {
        let key = SecureBytes((0..<32).map { UInt8($0 &* 7) })
        let nonce: [UInt8] = Array(repeating: 0xAB, count: 12)
        let plaintext = (0..<1000).map { UInt8($0 & 0xFF) }

        // Encrypt in one shot...
        var oneShot = plaintext
        var a = key.withUnsafeBytes { ChaCha20(key: $0, nonce: nonce) }
        a.process(&oneShot)

        // ...and in awkward chunks that cross 64-byte block boundaries.
        var chunked = [UInt8]()
        var b = key.withUnsafeBytes { ChaCha20(key: $0, nonce: nonce) }
        var offset = 0
        for size in [1, 63, 64, 65, 127, 200, 300, 180] {
            let take = min(size, plaintext.count - offset)
            guard take > 0 else { break }
            var piece = Array(plaintext[offset..<(offset + take)])
            b.process(&piece)
            chunked.append(contentsOf: piece)
            offset += take
        }

        #expect(oneShot == chunked, "keystream must not restart at chunk boundaries")
    }

    // MARK: Salsa20

    @Test("Salsa20 matches the eSTREAM Set 6 vector")
    func salsa20KnownAnswer() throws {
        // eSTREAM Set 6, vector 0.
        let key: [UInt8] = [
            0x00, 0x53, 0xA6, 0xF9, 0x4C, 0x9F, 0xF2, 0x45,
            0x98, 0xEB, 0x3E, 0x91, 0xE4, 0x37, 0x8A, 0xDD,
            0x30, 0x83, 0xD6, 0x29, 0x7C, 0xCF, 0x22, 0x75,
            0xC8, 0x1B, 0x6E, 0xC1, 0x14, 0x67, 0xBA, 0x0D
        ]
        let nonce: [UInt8] = [0x0D, 0x74, 0xDB, 0x42, 0xA9, 0x10, 0x77, 0xDE]
        let expected: [UInt8] = [
            0xF5, 0xFA, 0xD5, 0x3F, 0x79, 0xF9, 0xDF, 0x58,
            0xC4, 0xAE, 0xA0, 0xD0, 0xED, 0x9A, 0x96, 0x01
        ]
        var buffer = [UInt8](repeating: 0, count: 16)
        var cipher = Salsa20(key: key, nonce: nonce)
        cipher.process(&buffer)
        #expect(buffer == expected)
    }

    // MARK: Argon2

    @Test("Argon2id and Argon2d match known-answer vectors",
          arguments: zip(
            [Argon2.Variant.id, Argon2.Variant.d],
            [[UInt8]([0x9c, 0xb5, 0x6f, 0x6c, 0xad, 0x0c, 0x84, 0xf5,
                      0x15, 0x36, 0x56, 0x9e, 0x63, 0xac, 0xbc, 0x47,
                      0xd2, 0xfd, 0xef, 0xae, 0xea, 0x4b, 0x4f, 0x71,
                      0x1e, 0xfb, 0x54, 0x09, 0xe3, 0x7f, 0x34, 0xca]),
             [UInt8]([0xb4, 0x70, 0x45, 0x48, 0x03, 0x69, 0x0f, 0x99,
                      0x95, 0xb4, 0x1f, 0x40, 0xfe, 0x6f, 0x29, 0xaf,
                      0x79, 0xb6, 0x0e, 0x69, 0x2d, 0x24, 0x13, 0x5f,
                      0x45, 0xbc, 0x01, 0x48, 0x42, 0xd5, 0xa5, 0x80])]))
    func argon2KnownAnswer(variant: Argon2.Variant, expected: [UInt8]) throws {
        // Vectors produced by argon2-cffi (an independent binding), parameters:
        // password "password", salt "somesaltsomesalt", t=3, m=64 KiB, p=4, 32 bytes.
        // This pins the wrapper's parameter marshalling — memory units, lane count,
        // version byte — which is where a binding realistically goes wrong. The true
        // cross-implementation check is the fixture suite, which decrypts databases
        // KeePassXC produced with its own Argon2.
        let password = SecureBytes(Array("password".utf8))
        let salt = Array("somesaltsomesalt".utf8)

        let result = try Argon2.hash(
            password: password, salt: salt, variant: variant, version: 0x13,
            memoryKiB: 64, iterations: 3, parallelism: 4, outputLength: 32)

        #expect(result.withUnsafeBytes { [UInt8]($0) } == expected)
    }

    @Test("Argon2 is deterministic and salt-sensitive")
    func argon2Determinism() throws {
        let salt = [UInt8](repeating: 0x02, count: 16)
        var otherSalt = salt
        otherSalt[0] = 0x03

        func hash(_ salt: [UInt8]) throws -> SecureBytes {
            try Argon2.hash(password: SecureBytes(Array("pw".utf8)), salt: salt,
                            variant: .d, version: 0x13,
                            memoryKiB: 32, iterations: 2, parallelism: 1)
        }

        #expect(try hash(salt).isEqual(to: hash(salt)))
        #expect(try !hash(salt).isEqual(to: hash(otherSalt)),
                "a one-bit salt change must change the derived key")
    }

    @Test("Argon2 rejects out-of-range parameters rather than allocating")
    func argon2RejectsBadParameters() throws {
        let password = SecureBytes([1, 2, 3])
        let salt = [UInt8](repeating: 0, count: 16)

        #expect(throws: Argon2.Error.self) {
            try Argon2.hash(password: password, salt: salt, variant: .d, version: 0x13,
                            memoryKiB: 8, iterations: 0, parallelism: 1)
        }
        #expect(throws: Argon2.Error.self) {
            try Argon2.hash(password: password, salt: salt, variant: .d, version: 0x13,
                            memoryKiB: 8, iterations: 1, parallelism: 0)
        }
    }

    // MARK: SecureBytes

    @Test("Constant-time comparison agrees with ordinary equality")
    func timingSafeComparison() {
        #expect(timingSafeCompare([1, 2, 3], [1, 2, 3]))
        #expect(!timingSafeCompare([1, 2, 3], [1, 2, 4]))
        #expect(!timingSafeCompare([1, 2, 3], [1, 2]))
        #expect(timingSafeCompare([], []))
    }

    @Test("SecureBytes round-trips its contents")
    func secureBytesRoundTrip() {
        let bytes: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let secure = SecureBytes(bytes)
        #expect(secure.count == 4)
        #expect(secure.withUnsafeBytes { [UInt8]($0) } == bytes)
        #expect(secure.isEqual(to: SecureBytes(bytes)))
        #expect(!secure.isEqual(to: SecureBytes([0xDE, 0xAD, 0xBE, 0xEE])))
    }

    // MARK: gzip

    /// A compressor for the tests only.
    ///
    /// The engine no longer ships one — Fleen does not write KDBX files — but the
    /// *decompressor* still handles attacker-supplied input and needs real coverage,
    /// including the multi-chunk path. So the test builds its own gzip data with zlib
    /// rather than the production code compressing its own test input.
    static func gzip(_ input: Data) throws -> Data {
        var stream = z_stream()
        guard deflateInit2_(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                            Z_DEFAULT_STRATEGY, ZLIB_VERSION,
                            Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw GzipTestFailure.couldNotStart
        }
        defer { deflateEnd(&stream) }

        var output = Data()
        let chunkSize = 64 * 1024
        var chunk = [UInt8](repeating: 0, count: chunkSize)
        var input = input

        let status: Int32 = input.withUnsafeMutableBytes { inBuf -> Int32 in
            stream.next_in = inBuf.baseAddress?.assumingMemoryBound(to: Bytef.self)
            stream.avail_in = uInt(inBuf.count)
            while true {
                let result: Int32 = chunk.withUnsafeMutableBufferPointer { outBuf -> Int32 in
                    stream.next_out = outBuf.baseAddress
                    stream.avail_out = uInt(chunkSize)
                    return deflate(&stream, Z_FINISH)
                }
                let produced = chunkSize - Int(stream.avail_out)
                if produced > 0 { output.append(contentsOf: chunk[0..<produced]) }
                if result == Z_STREAM_END { return Z_STREAM_END }
                guard result == Z_OK else { return result }
            }
        }
        guard status == Z_STREAM_END else { throw GzipTestFailure.couldNotCompress }
        return output
    }

    enum GzipTestFailure: Error { case couldNotStart, couldNotCompress }

    @Test("gzip decompresses payloads of every size, including multi-chunk ones")
    func gzipDecompresses() throws {
        for size in [0, 1, 5, 64 * 1024, 64 * 1024 + 1, 512 * 1024, 3_000_000] {
            let payload = Data((0..<size).map { UInt8($0 % 251) })
            let restored = try Gzip.decompress(try Self.gzip(payload))
            #expect(restored == payload, "failed at \(size) bytes")
        }
    }

    @Test("gzip decompresses incompressible data without growing it unboundedly")
    func gzipHandlesRandomData() throws {
        var random = Data(count: 200_000)
        _ = random.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 200_000, $0.baseAddress!)
        }
        #expect(try Gzip.decompress(try Self.gzip(random)) == random)
    }

    @Test("gzip rejects damaged input instead of returning partial data")
    func gzipRejectsGarbage() throws {
        #expect(throws: KdbxError.self) {
            _ = try Gzip.decompress(Data([0x1f, 0x8b, 0x08, 0xFF, 0xFF, 0xFF]))
        }
    }

    @Test("A truncated gzip stream is rejected, not silently accepted short")
    func gzipRejectsTruncation() throws {
        let full = try Self.gzip(Data((0..<100_000).map { UInt8($0 % 251) }))
        #expect(throws: KdbxError.self) {
            _ = try Gzip.decompress(full.prefix(full.count / 2))
        }
    }
}
