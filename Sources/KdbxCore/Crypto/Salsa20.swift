import Foundation

/// Salsa20 keystream, needed only for the KDBX inner protected-value stream when
/// the inner stream ID is `salsa20` (2). Same reasoning as `ChaCha20`: no Apple API
/// exposes a bare Salsa20 keystream, and the core is a fixed permutation with no
/// secret-dependent control flow.
///
/// KDBX fixes the nonce at `E8 30 09 4B 97 20 5D 2A` and derives the key as
/// `SHA-256(innerRandomStreamKey)`.
struct Salsa20 {
    static let kdbxNonce: [UInt8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]

    private var state: [UInt32]
    private var keystream = [UInt8](repeating: 0, count: 64)
    private var keystreamOffset = 64

    init(key: [UInt8], nonce: [UInt8]) {
        precondition(key.count == 32 && nonce.count == 8)
        // "expand 32-byte k" split across the four constant words.
        state = [UInt32](repeating: 0, count: 16)
        state[0] = 0x6170_7865
        state[5] = 0x3320_646e
        state[10] = 0x7962_2d32
        state[15] = 0x6b20_6574
        for i in 0..<4 { state[1 + i] = Self.load32(key, i * 4) }
        for i in 0..<4 { state[11 + i] = Self.load32(key, 16 + i * 4) }
        state[6] = Self.load32(nonce, 0)
        state[7] = Self.load32(nonce, 4)
        state[8] = 0   // counter low
        state[9] = 0   // counter high
    }

    private static func load32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) | (UInt32(b[i + 1]) << 8) | (UInt32(b[i + 2]) << 16) | (UInt32(b[i + 3]) << 24)
    }

    @inline(__always)
    private static func quarterRound(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        s[b] ^= rotl(s[a] &+ s[d], 7)
        s[c] ^= rotl(s[b] &+ s[a], 9)
        s[d] ^= rotl(s[c] &+ s[b], 13)
        s[a] ^= rotl(s[d] &+ s[c], 18)
    }

    @inline(__always)
    private static func rotl(_ v: UInt32, _ n: UInt32) -> UInt32 { (v << n) | (v >> (32 - n)) }

    private mutating func generateBlock() {
        var w = state
        for _ in 0..<10 {
            Self.quarterRound(&w,  0,  4,  8, 12)
            Self.quarterRound(&w,  5,  9, 13,  1)
            Self.quarterRound(&w, 10, 14,  2,  6)
            Self.quarterRound(&w, 15,  3,  7, 11)
            Self.quarterRound(&w,  0,  1,  2,  3)
            Self.quarterRound(&w,  5,  6,  7,  4)
            Self.quarterRound(&w, 10, 11,  8,  9)
            Self.quarterRound(&w, 15, 12, 13, 14)
        }
        for i in 0..<16 {
            let v = w[i] &+ state[i]
            keystream[i * 4 + 0] = UInt8(truncatingIfNeeded: v)
            keystream[i * 4 + 1] = UInt8(truncatingIfNeeded: v >> 8)
            keystream[i * 4 + 2] = UInt8(truncatingIfNeeded: v >> 16)
            keystream[i * 4 + 3] = UInt8(truncatingIfNeeded: v >> 24)
        }
        keystreamOffset = 0
        state[8] = state[8] &+ 1
        if state[8] == 0 { state[9] = state[9] &+ 1 }
        SecureBytes.wipe(&w)
    }

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
}
