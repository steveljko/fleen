import Foundation

/// RFC 8439 ChaCha20 keystream cipher.
///
/// Why this is hand-written when the rule is "don't hand-roll crypto": CryptoKit
/// ships only `ChaChaPoly`, the AEAD construction. KDBX needs the bare keystream —
/// as the outer payload cipher (cipher UUID `D6038A2B-8B6F-4CB5-A524-339A31DBB59A`)
/// and as the inner protected-value stream — and an AEAD cannot be coerced into
/// producing one. The alternative was a third-party dependency for a primitive that
/// is 40 lines of fixed rotations with no secret-dependent branches or table lookups,
/// so the whole function is constant-time by construction.
///
/// Validated against the RFC 8439 §2.3.2 and §2.4.2 test vectors in the test suite.
/// This is the *only* primitive in the package that is not Apple-supplied or PHC
/// reference code, and it is the one place to look hardest during security review.
struct ChaCha20 {
    private var state: [UInt32]
    private var keystream = [UInt8](repeating: 0, count: 64)
    private var keystreamOffset = 64

    /// - Parameters:
    ///   - key: exactly 32 bytes.
    ///   - nonce: 12 bytes (RFC 8439) or 8 bytes (original 64-bit-nonce construction,
    ///     which is what the KDBX inner ChaCha20 stream uses).
    ///   - counter: initial block counter.
    init(key: UnsafeRawBufferPointer, nonce: [UInt8], counter: UInt32 = 0) {
        precondition(key.count == 32, "ChaCha20 requires a 256-bit key")
        precondition(nonce.count == 12 || nonce.count == 8, "nonce must be 8 or 12 bytes")

        // "expand 32-byte k"
        var s: [UInt32] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]
        for i in 0..<8 { s.append(Self.load32(key, i * 4)) }

        if nonce.count == 12 {
            s.append(counter)
            for i in 0..<3 { s.append(Self.load32(nonce, i * 4)) }
        } else {
            // 8-byte nonce: the block counter is 64 bits wide.
            s.append(counter)
            s.append(0)
            for i in 0..<2 { s.append(Self.load32(nonce, i * 4)) }
        }
        self.state = s
    }

    private static func load32(_ b: UnsafeRawBufferPointer, _ i: Int) -> UInt32 {
        UInt32(b[i]) | (UInt32(b[i + 1]) << 8) | (UInt32(b[i + 2]) << 16) | (UInt32(b[i + 3]) << 24)
    }

    private static func load32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) | (UInt32(b[i + 1]) << 8) | (UInt32(b[i + 2]) << 16) | (UInt32(b[i + 3]) << 24)
    }

    @inline(__always)
    private static func quarterRound(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        s[a] &+= s[b]; s[d] ^= s[a]; s[d] = (s[d] << 16) | (s[d] >> 16)
        s[c] &+= s[d]; s[b] ^= s[c]; s[b] = (s[b] << 12) | (s[b] >> 20)
        s[a] &+= s[b]; s[d] ^= s[a]; s[d] = (s[d] << 8)  | (s[d] >> 24)
        s[c] &+= s[d]; s[b] ^= s[c]; s[b] = (s[b] << 7)  | (s[b] >> 25)
    }

    private mutating func generateBlock() {
        var w = state
        for _ in 0..<10 {   // 20 rounds = 10 column rounds + 10 diagonal rounds
            Self.quarterRound(&w, 0, 4,  8, 12)
            Self.quarterRound(&w, 1, 5,  9, 13)
            Self.quarterRound(&w, 2, 6, 10, 14)
            Self.quarterRound(&w, 3, 7, 11, 15)
            Self.quarterRound(&w, 0, 5, 10, 15)
            Self.quarterRound(&w, 1, 6, 11, 12)
            Self.quarterRound(&w, 2, 7,  8, 13)
            Self.quarterRound(&w, 3, 4,  9, 14)
        }
        for i in 0..<16 {
            let v = w[i] &+ state[i]
            keystream[i * 4 + 0] = UInt8(truncatingIfNeeded: v)
            keystream[i * 4 + 1] = UInt8(truncatingIfNeeded: v >> 8)
            keystream[i * 4 + 2] = UInt8(truncatingIfNeeded: v >> 16)
            keystream[i * 4 + 3] = UInt8(truncatingIfNeeded: v >> 24)
        }
        keystreamOffset = 0
        // Advance the counter, carrying into word 13 for the 64-bit-counter variant.
        state[12] = state[12] &+ 1
        if state[12] == 0 { state[13] = state[13] &+ 1 }
        SecureBytes.wipe(&w)
    }

    /// XORs `data` with the keystream in place. Encryption and decryption are the
    /// same operation; the caller must never reuse a (key, nonce) pair across two
    /// different plaintexts.
    mutating func process(_ data: inout [UInt8]) {
        var i = 0
        while i < data.count {
            if keystreamOffset == 64 { generateBlock() }
            let take = min(64 - keystreamOffset, data.count - i)
            for j in 0..<take { data[i + j] ^= keystream[keystreamOffset + j] }
            keystreamOffset += take
            i += take
        }
    }

    mutating func process(_ data: Data) -> Data {
        var bytes = [UInt8](data)
        process(&bytes)
        defer { SecureBytes.wipe(&bytes) }
        return Data(bytes)
    }
}
