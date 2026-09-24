import Foundation
import CArgon2

/// Thin Swift wrapper over the PHC reference Argon2 implementation.
public enum Argon2 {
    public enum Variant: UInt32, Sendable {
        case d = 0, i = 1, id = 2

        var argon2Type: Argon2_type {
            switch self {
            case .d: return Argon2_d
            case .i: return Argon2_i
            case .id: return Argon2_id
            }
        }
    }

    public enum Error: Swift.Error, Sendable {
        case failed(code: Int32, message: String)
        case invalidParameters(String)
    }

    /// Derives `outputLength` bytes. Both the password and the result stay in
    /// `SecureBytes`, so neither is ever copied into a growable heap buffer.
    ///
    /// - Note: This is the expensive call in the whole unlock path — by design.
    ///   Callers must run it off the main thread.
    public static func hash(
        password: SecureBytes,
        salt: [UInt8],
        variant: Variant,
        version: UInt32,
        memoryKiB: UInt32,
        iterations: UInt32,
        parallelism: UInt32,
        outputLength: Int = 32
    ) throws -> SecureBytes {
        guard iterations >= 1 else { throw Error.invalidParameters("iterations must be >= 1") }
        guard parallelism >= 1 else { throw Error.invalidParameters("parallelism must be >= 1") }
        guard memoryKiB >= 8 * parallelism else {
            throw Error.invalidParameters("memory must be >= 8 * parallelism KiB")
        }
        guard version == 0x13 || version == 0x10 else {
            throw Error.invalidParameters("unsupported Argon2 version \(version)")
        }

        let out = SecureBytes(count: outputLength)
        var saltCopy = salt

        let status: Int32 = password.withUnsafeBytes { pwd in
            out.withUnsafeMutableBytes { outBuf in
                saltCopy.withUnsafeMutableBufferPointer { saltBuf in
                    var ctx = Argon2_Context(
                        out: outBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        outlen: UInt32(outputLength),
                        pwd: UnsafeMutablePointer(mutating:
                            pwd.baseAddress!.assumingMemoryBound(to: UInt8.self)),
                        pwdlen: UInt32(pwd.count),
                        salt: saltBuf.baseAddress,
                        saltlen: UInt32(saltBuf.count),
                        secret: nil, secretlen: 0,
                        ad: nil, adlen: 0,
                        t_cost: iterations,
                        m_cost: memoryKiB,
                        lanes: parallelism,
                        threads: parallelism,
                        version: version,
                        allocate_cbk: nil, free_cbk: nil,
                        // Tell the reference code to wipe its own working memory and
                        // the password buffer it was handed before returning.
                        // ARGON2_FLAG_CLEAR_PASSWORD; a C macro, so not imported by name.
                        // The reference code zeroes the password buffer it was handed
                        // before returning — callers must pass a key they are done with.
                        flags: UInt32(1)
                    )
                    return argon2_ctx(&ctx, variant.argon2Type)
                }
            }
        }

        SecureBytes.wipe(&saltCopy)

        guard status == ARGON2_OK.rawValue else {
            let msg = String(cString: argon2_error_message(status))
            throw Error.failed(code: status, message: msg)
        }
        return out
    }
}
