import Foundation
import CommonCrypto
import CryptoKit

/// Legacy KDBX key derivation: `rounds` successive AES-256-ECB encryptions of the
/// 32-byte composite key under the transform seed, then SHA-256 of the result.
///
/// Uses CommonCrypto's AES rather than a hand-rolled block cipher. Kept only for
/// databases that still specify `AES-KDF`; Argon2 is the default for anything new.
enum AesKdf {
    /// 100 million — comfortably above KeePassXC's defaults, and a few seconds of work.
    static let maximumRounds: UInt64 = 100_000_000

    static func transform(key: SecureBytes, seed: [UInt8], rounds: UInt64) throws -> SecureBytes {
        guard key.count == 32 else { throw KdbxError.cryptoFailure("AES-KDF needs a 32-byte key") }
        guard seed.count == 32 else { throw KdbxError.cryptoFailure("AES-KDF needs a 32-byte seed") }
        // `rounds` is a `UInt64` read straight from an unauthenticated header, and it
        // drives `for _ in 0..<rounds`. Without a ceiling, a crafted file asks for 2^64
        // rounds and the unlock never returns. Real databases use tens of millions.
        guard rounds <= maximumRounds else {
            throw KdbxError.malformedHeader(
                "AES-KDF asks for \(rounds) rounds, beyond the \(maximumRounds) limit")
        }

        let working = SecureBytes(count: 32)
        working.withUnsafeMutableBytes { dst in
            key.withUnsafeBytes { src in dst.copyMemory(from: src) }
        }

        var cryptor: CCCryptorRef?
        let status = seed.withUnsafeBytes { seedBuf -> CCCryptorStatus in
            CCCryptorCreate(
                CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                seedBuf.baseAddress, kCCKeySizeAES256,
                nil, &cryptor)
        }
        guard status == kCCSuccess, let cryptor else {
            throw KdbxError.cryptoFailure("could not initialise AES-KDF cryptor")
        }
        defer { CCCryptorRelease(cryptor) }

        // One cryptor reused across all rounds: re-keying per round would dominate
        // the cost and these databases already specify millions of rounds.
        try working.withUnsafeMutableBytes { buf in
            let base = buf.baseAddress!
            var moved = 0
            for _ in 0..<rounds {
                let s = CCCryptorUpdate(cryptor, base, 32, base, 32, &moved)
                guard s == kCCSuccess, moved == 32 else {
                    throw KdbxError.cryptoFailure("AES-KDF round failed")
                }
            }
        }

        let digest = working.withUnsafeBytes { SHA256.hash(data: Data($0)) }
        return SecureBytes(Array(digest))
    }
}
