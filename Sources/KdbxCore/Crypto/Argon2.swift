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

    /// 1 GiB — KeePassXC's own maximum.
    static let maximumMemoryKiB: UInt32 = 1024 * 1024
    /// Real databases use single digits; 1000 is already extravagant.
    static let maximumIterations: UInt32 = 1000
    /// More lanes than any Mac has cores several times over.
    static let maximumParallelism: UInt32 = 64
    /// memoryKiB × iterations. Roughly 100× a typical database, which bounds a hostile
    /// unlock to tens of seconds rather than hours.
    static let maximumWork: UInt64 = 64 * 1024 * 1024

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

        // Upper bounds, which is the half that was missing.
        //
        // These parameters come out of the file's own header, and the header is parsed
        // before anything is authenticated — so an attacker who can hand you a `.kdbx`
        // chooses them. Only the lower bounds were checked, so a crafted header could
        // ask for billions of iterations or terabytes of memory and the engine would
        // dutifully try: fuzzing produced a single `open` that ran for 107 seconds, and
        // nothing stopped it going far higher.
        //
        // The limits are far above anything a real database uses — KeePassXC's own
        // maximum is 1 GiB with single-digit iterations — so a rejection here means the
        // file is hostile or corrupt, not that someone was unusually careful.
        guard memoryKiB <= Self.maximumMemoryKiB else {
            throw Error.invalidParameters(
                "memory of \(memoryKiB) KiB exceeds the \(Self.maximumMemoryKiB) KiB limit")
        }
        guard iterations <= Self.maximumIterations else {
            throw Error.invalidParameters(
                "\(iterations) iterations exceeds the limit of \(Self.maximumIterations)")
        }
        guard parallelism <= Self.maximumParallelism else {
            throw Error.invalidParameters(
                "parallelism of \(parallelism) exceeds the limit of \(Self.maximumParallelism)")
        }
        // Each bound alone still permits an absurd combination, so the product is capped
        // too: this is what actually bounds the time an unlock can take.
        guard UInt64(memoryKiB) * UInt64(iterations) <= Self.maximumWork else {
            throw Error.invalidParameters(
                "the combination of \(memoryKiB) KiB and \(iterations) iterations is "
                + "beyond any plausible database")
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
