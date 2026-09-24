import Foundation
import CryptoKit

/// Tiny shims so hashing over an `UnsafeRawBufferPointer` reads the same at every
/// call site without each one hand-rolling a `Data` copy.
struct SHA256Wrapper {
    private var hasher = SHA256()
    mutating func update(_ buffer: UnsafeRawBufferPointer) { hasher.update(bufferPointer: buffer) }
    mutating func finalize() -> [UInt8] { Array(hasher.finalize()) }
}

struct SHA512Wrapper {
    private var hasher = SHA512()
    mutating func update(_ buffer: UnsafeRawBufferPointer) { hasher.update(bufferPointer: buffer) }
    mutating func finalize() -> [UInt8] { Array(hasher.finalize()) }
}
