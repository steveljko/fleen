import Testing
import Foundation
@testable import KdbxCore

/// Cost parameters out of a hostile header.
///
/// These are the bugs fuzzing found, pinned so they cannot come back. All of them are
/// reachable **before any authentication**: the KDF parameters are read from the header,
/// and the header is parsed before the key exists or the HMAC is checked. An attacker who
/// can hand you a `.kdbx` picks these numbers.
@Suite("Hostile KDF parameters")
struct HostileHeaderTests {

    struct Params: Sendable {
        let memoryKiB: UInt32
        let iterations: UInt32
    }

    static let key: SecureBytes = {
        var composite = CompositeKey()
        composite.addPassword("correct horse battery staple")
        return composite.rawKey()
    }()

    // MARK: - Denial of service

    /// Found by fuzzing: a single `open` ran for 107 seconds, and nothing bounded it.
    @Test("Absurd Argon2 memory is refused rather than attempted")
    func rejectsHugeMemory() {
        #expect(throws: Argon2.Error.self) {
            _ = try Argon2.hash(password: Self.key, salt: [UInt8](repeating: 0, count: 16),
                                variant: .d, version: 0x13,
                                memoryKiB: 64 * 1024 * 1024,   // 64 GiB
                                iterations: 2, parallelism: 1)
        }
    }

    @Test("Absurd Argon2 iteration counts are refused")
    func rejectsHugeIterations() {
        #expect(throws: Argon2.Error.self) {
            _ = try Argon2.hash(password: Self.key, salt: [UInt8](repeating: 0, count: 16),
                                variant: .d, version: 0x13,
                                memoryKiB: 65536, iterations: .max, parallelism: 1)
        }
    }

    /// Each bound alone still allows an absurd *combination*, which is what actually
    /// decides how long an unlock takes.
    @Test("A costly-but-individually-legal combination is refused")
    func rejectsProductOfLimits() {
        #expect(throws: Argon2.Error.self) {
            _ = try Argon2.hash(password: Self.key, salt: [UInt8](repeating: 0, count: 16),
                                variant: .d, version: 0x13,
                                memoryKiB: 1024 * 1024,  // 1 GiB, legal alone
                                iterations: 1000,        // legal alone
                                parallelism: 1)
        }
    }

    /// `rounds` is a `UInt64` driving `for _ in 0..<rounds`. Unbounded, a crafted header
    /// means an unlock that never returns.
    @Test("An unbounded AES-KDF round count is refused")
    func rejectsHugeAesRounds() {
        #expect(throws: KdbxError.self) {
            _ = try AesKdf.transform(key: Self.key,
                                     seed: [UInt8](repeating: 0, count: 32),
                                     rounds: .max)
        }
    }

    // MARK: - Still accepting real databases

    /// The limits must not reject anything anyone actually uses. KeePassXC's maximum
    /// memory is 1 GiB and its iteration counts are single digits.
    @Test("Realistic parameters are still accepted", arguments: [
        Params(memoryKiB: 65_536, iterations: 10),    // KeePassXC default-ish
        Params(memoryKiB: 1024 * 1024, iterations: 2), // KeePassXC maximum memory
        Params(memoryKiB: 16, iterations: 1),          // minimum plausible
    ])
    func acceptsRealisticParameters(_ params: Params) throws {
        let memoryKiB = params.memoryKiB, iterations = params.iterations
        let out = try Argon2.hash(password: Self.key, salt: [UInt8](repeating: 0, count: 16),
                                  variant: .id, version: 0x13,
                                  memoryKiB: memoryKiB, iterations: iterations, parallelism: 1)
        #expect(out.count == 32)
    }

    @Test("A realistic AES-KDF round count is still accepted")
    func acceptsRealisticRounds() throws {
        let out = try AesKdf.transform(key: Self.key,
                                       seed: [UInt8](repeating: 0, count: 32),
                                       rounds: 60_000)
        #expect(out.count == 32)
    }

    // MARK: - The contract

    /// A 64-bit cost parameter was narrowed with `UInt32(value)`, which **traps** above
    /// `UInt32.max` — an uncatchable crash from an unauthenticated header. The fix is
    /// that the conversion never happens out of range; this pins the rejection.
    @Test("A 64-bit cost parameter beyond UInt32 is rejected, not narrowed")
    func rejectsOutOfRangeWithoutTrapping() {
        var composite = CompositeKey()
        composite.addPassword("correct horse battery staple")
        let header = try! Self.header(kdf: .argon2d(memoryKiB: UInt64(UInt32.max) + 1,
                                                    iterations: 2, parallelism: 1,
                                                    version: 0x13))
        // Reaching the narrowing at all is the point: it must throw rather than trap.
        #expect(throws: KdbxError.self) {
            _ = try KeySchedule(header: header, compositeKey: composite)
        }
    }

    /// Builds a header from a real fixture with one field replaced.
    static func header(kdf: KdbxKdf) throws -> KdbxHeader {
        let fixture = try Data(contentsOf: Fixture.url("pkp-aes-argon2d.kdbx"))
        var reader = ByteReader(fixture)
        let base = try KdbxHeader.parse(&reader)
        return KdbxHeader(cipher: base.cipher, compression: base.compression,
                          masterSeed: base.masterSeed, encryptionIV: base.encryptionIV,
                          kdf: kdf, kdfSalt: base.kdfSalt,
                          publicCustomData: base.publicCustomData,
                          majorVersion: base.majorVersion, minorVersion: base.minorVersion,
                          rawBytes: base.rawBytes)
    }

    /// `open` documents that it throws `KdbxError`. `Argon2.Error` is a different type,
    /// and it was escaping — which the fuzzer reported as "threw a non-KdbxError".
    @Test("Rejected KDF parameters surface as a KdbxError, not an internal one")
    func kdfErrorsAreWrapped() throws {
        var composite = CompositeKey()
        composite.addPassword("correct horse battery staple")
        let hostile = try Self.header(kdf: .argon2d(memoryKiB: 64 * 1024 * 1024,
                                                    iterations: 2, parallelism: 1,
                                                    version: 0x13))
        #expect(throws: KdbxError.self) {
            _ = try KeySchedule(header: hostile, compositeKey: composite)
        }
    }
}
