import Foundation
import CryptoKit

/// Derives every key KDBX4 needs from the composite key and the header.
///
/// The shape matters and is easy to get subtly wrong:
///   transformed = KDF(compositeKey, kdfParams)
///   cipherKey   = SHA-256 (masterSeed ‖ transformed)
///   hmacSeed    = SHA-512 (masterSeed ‖ transformed ‖ 0x01)
///   blockKey(i) = SHA-512 (LE64(i) ‖ hmacSeed)
/// with the header's own HMAC using block index 0xFFFF_FFFF_FFFF_FFFF.
struct KeySchedule {
    let cipherKey: SecureBytes
    let hmacSeed: SecureBytes

    init(header: KdbxHeader, compositeKey: CompositeKey) throws {
        let raw = compositeKey.rawKey()

        let transformed: SecureBytes
        switch header.kdf {
        case .argon2d(let memoryKiB, let iterations, let parallelism, let version):
            transformed = try Argon2.hash(
                password: raw, salt: header.kdfSalt, variant: .d, version: version,
                memoryKiB: UInt32(memoryKiB), iterations: UInt32(iterations),
                parallelism: parallelism)
        case .argon2id(let memoryKiB, let iterations, let parallelism, let version):
            transformed = try Argon2.hash(
                password: raw, salt: header.kdfSalt, variant: .id, version: version,
                memoryKiB: UInt32(memoryKiB), iterations: UInt32(iterations),
                parallelism: parallelism)
        case .aesKdf(let rounds):
            transformed = try AesKdf.transform(key: raw, seed: header.kdfSalt, rounds: rounds)
        }

        // cipherKey = SHA-256(masterSeed ‖ transformed)
        var keyHasher = SHA256()
        keyHasher.update(data: Data(header.masterSeed))
        transformed.withUnsafeBytes { keyHasher.update(data: Data($0)) }
        self.cipherKey = SecureBytes(Array(keyHasher.finalize()))

        // hmacSeed = SHA-512(masterSeed ‖ transformed ‖ 0x01)
        var macHasher = SHA512()
        macHasher.update(data: Data(header.masterSeed))
        transformed.withUnsafeBytes { macHasher.update(data: Data($0)) }
        macHasher.update(data: Data([0x01]))
        self.hmacSeed = SecureBytes(Array(macHasher.finalize()))
    }

    /// Per-block HMAC key. Index `UInt64.max` is reserved for the header.
    func blockKey(index: UInt64) -> SecureBytes {
        var hasher = SHA512()
        withUnsafeBytes(of: index.littleEndian) { hasher.update(data: Data($0)) }
        hmacSeed.withUnsafeBytes { hasher.update(data: Data($0)) }
        return SecureBytes(Array(hasher.finalize()))
    }

    static let headerBlockIndex = UInt64.max
}

/// Exposes the key-derivation step alone, for measurement.
///
/// Performance work needs to distinguish "the database asked for an expensive KDF"
/// from "Fleen is slow", and those have completely different remedies — the first is
/// the user's own security setting, the second is a bug.
public enum KeyScheduleBenchmark {
    public static func deriveOnly(info: DatabaseInfo, credentials: CompositeKey) throws -> Int {
        let raw = credentials.rawKey()
        switch info.kdf {
        case .argon2d(let memoryKiB, let iterations, let parallelism, let version):
            let out = try Argon2.hash(password: raw, salt: [UInt8](repeating: 0x11, count: 32),
                                      variant: .d, version: version,
                                      memoryKiB: UInt32(memoryKiB), iterations: UInt32(iterations),
                                      parallelism: parallelism)
            return out.count
        case .argon2id(let memoryKiB, let iterations, let parallelism, let version):
            let out = try Argon2.hash(password: raw, salt: [UInt8](repeating: 0x11, count: 32),
                                      variant: .id, version: version,
                                      memoryKiB: UInt32(memoryKiB), iterations: UInt32(iterations),
                                      parallelism: parallelism)
            return out.count
        case .aesKdf(let rounds):
            let out = try AesKdf.transform(key: raw, seed: [UInt8](repeating: 0x11, count: 32),
                                           rounds: rounds)
            return out.count
        }
    }
}
