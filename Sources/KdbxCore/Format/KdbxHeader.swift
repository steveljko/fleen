import Foundation

/// Well-known KDBX identifiers, spelled out so nothing depends on a magic literal
/// buried in the parser.
public enum KdbxCipher: Sendable, Equatable, CaseIterable {
    case aes256CBC
    case chacha20

    static let aesUUID      = UUID(uuidString: "31C1F2E6-BF71-4350-BE58-05216AFC5AFF")!
    static let chachaUUID   = UUID(uuidString: "D6038A2B-8B6F-4CB5-A524-339A31DBB59A")!
    /// Twofish is a valid KDBX cipher we deliberately do not implement.
    static let twofishUUID  = UUID(uuidString: "AD68F29F-576F-4BB9-A36A-D47AF965346C")!

    /// Names a cipher that is legitimate KDBX but unsupported here, so the error can
    /// say which one rather than printing a bare UUID at the user.
    public static func knownName(for uuid: UUID) -> String? {
        switch uuid {
        case twofishUUID: return "Twofish"
        default: return nil
        }
    }

    init(uuid: UUID) throws {
        switch uuid {
        case Self.aesUUID:    self = .aes256CBC
        case Self.chachaUUID: self = .chacha20
        default:              throw KdbxError.unsupportedCipher(uuid)
        }
    }

    var uuid: UUID {
        switch self {
        case .aes256CBC: return Self.aesUUID
        case .chacha20:  return Self.chachaUUID
        }
    }

    /// Outer-payload IV length. AES-CBC takes a 16-byte IV; KDBX ChaCha20 uses the
    /// 12-byte RFC 8439 nonce.
    var ivLength: Int {
        switch self {
        case .aes256CBC: return 16
        case .chacha20:  return 12
        }
    }

    public var displayName: String {
        switch self {
        case .aes256CBC: return "AES-256"
        case .chacha20:  return "ChaCha20"
        }
    }
}

public enum KdbxKdf: Sendable, Equatable {
    case argon2d(memoryKiB: UInt64, iterations: UInt64, parallelism: UInt32, version: UInt32)
    case argon2id(memoryKiB: UInt64, iterations: UInt64, parallelism: UInt32, version: UInt32)
    case aesKdf(rounds: UInt64)

    static let aesKdfUUID   = UUID(uuidString: "C9D9F39A-628A-4460-BF74-0D08C18A4FEA")!
    static let argon2dUUID  = UUID(uuidString: "EF636DDF-8C29-444B-91F7-A9A403E30A0C")!
    static let argon2idUUID = UUID(uuidString: "9E298B19-56DB-4773-B23D-FC3EC6F0A1E6")!

    public var displayName: String {
        switch self {
        case .argon2d:  return "Argon2d"
        case .argon2id: return "Argon2id"
        case .aesKdf:   return "AES-KDF"
        }
    }
}

public enum KdbxCompression: UInt32, Sendable {
    case none = 0
    case gzip = 1
}

/// The parsed outer header, plus the exact bytes it occupied.
///
/// `rawBytes` is retained deliberately: both the SHA-256 integrity check and the
/// HMAC are computed over the header's original byte representation, and
/// re-serialising to verify would be a subtle correctness trap if our writer ever
/// disagreed with the writer that produced the file.
struct KdbxHeader {
    var cipher: KdbxCipher
    var compression: KdbxCompression
    var masterSeed: [UInt8]
    var encryptionIV: [UInt8]
    var kdf: KdbxKdf
    var kdfSalt: [UInt8]
    var publicCustomData: Data?
    var majorVersion: UInt16
    var minorVersion: UInt16
    var rawBytes: Data

    static let signature1: UInt32 = 0x9AA2_D903
    static let signature2: UInt32 = 0xB54B_FB67

    private enum FieldID: UInt8 {
        case endOfHeader = 0
        case comment = 1
        case cipherID = 2
        case compressionFlags = 3
        case masterSeed = 4
        case transformSeed = 5        // KDBX3 only
        case transformRounds = 6      // KDBX3 only
        case encryptionIV = 7
        case innerRandomStreamKey = 8 // KDBX3 only
        case streamStartBytes = 9     // KDBX3 only
        case innerRandomStreamID = 10 // KDBX3 only
        case kdfParameters = 11       // KDBX4
        case publicCustomData = 12    // KDBX4
    }

    static func parse(_ reader: inout ByteReader) throws -> KdbxHeader {
        let start = reader.offset

        guard try reader.readUInt32() == signature1,
              try reader.readUInt32() == signature2 else {
            throw KdbxError.notAKdbxFile
        }

        let minor = try reader.readUInt16()
        let major = try reader.readUInt16()
        // KDBX3 was explicitly descoped for this build; say so precisely rather
        // than failing later with a confusing crypto error.
        guard major == 4 else { throw KdbxError.unsupportedVersion(major: major, minor: minor) }

        var cipher: KdbxCipher?
        var compression: KdbxCompression?
        var masterSeed: [UInt8]?
        var encryptionIV: [UInt8]?
        var kdfParams: VariantDictionary?
        var publicCustomData: Data?

        loop: while true {
            let rawID = try reader.readUInt8()
            let length = Int(try reader.readUInt32())
            let payload = try reader.read(length)

            guard let field = FieldID(rawValue: rawID) else {
                // Unknown fields are skipped, not rejected: that is what keeps a
                // newer KeePass file readable here.
                continue
            }

            switch field {
            case .endOfHeader:
                break loop
            case .cipherID:
                guard let uuid = UUID(kdbxBytes: [UInt8](payload)) else {
                    throw KdbxError.malformedHeader("cipher ID is not 16 bytes")
                }
                cipher = try KdbxCipher(uuid: uuid)
            case .compressionFlags:
                guard length == 4 else { throw KdbxError.malformedHeader("bad compression flags") }
                let raw = payload.withUnsafeBytes {
                    UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
                guard let c = KdbxCompression(rawValue: raw) else {
                    throw KdbxError.unsupportedCompression(raw)
                }
                compression = c
            case .masterSeed:
                guard length == 32 else {
                    throw KdbxError.malformedHeader("master seed must be 32 bytes, got \(length)")
                }
                masterSeed = [UInt8](payload)
            case .encryptionIV:
                encryptionIV = [UInt8](payload)
            case .kdfParameters:
                kdfParams = try VariantDictionary(parsing: payload)
            case .publicCustomData:
                publicCustomData = payload
            case .comment:
                continue
            case .transformSeed, .transformRounds, .innerRandomStreamKey,
                 .streamStartBytes, .innerRandomStreamID:
                // KDBX3 fields; a v4 file should not carry them, but ignoring is
                // safer than rejecting a file KeePass itself would open.
                continue
            }
        }

        guard let cipher else { throw KdbxError.malformedHeader("no cipher ID") }
        guard let compression else { throw KdbxError.malformedHeader("no compression flags") }
        guard let masterSeed else { throw KdbxError.malformedHeader("no master seed") }
        guard let encryptionIV else { throw KdbxError.malformedHeader("no encryption IV") }
        guard let kdfParams else { throw KdbxError.malformedHeader("no KDF parameters") }
        guard encryptionIV.count == cipher.ivLength else {
            throw KdbxError.malformedHeader(
                "\(cipher.displayName) needs a \(cipher.ivLength)-byte IV, got \(encryptionIV.count)")
        }

        let (kdf, salt) = try Self.parseKdf(kdfParams)
        let rawBytes = reader.data[start..<reader.offset]

        return KdbxHeader(
            cipher: cipher, compression: compression, masterSeed: masterSeed,
            encryptionIV: encryptionIV, kdf: kdf, kdfSalt: salt,
            publicCustomData: publicCustomData,
            majorVersion: major, minorVersion: minor, rawBytes: rawBytes)
    }

    private static func parseKdf(_ params: VariantDictionary) throws -> (KdbxKdf, [UInt8]) {
        guard let uuidBytes = params.bytes("$UUID"), let uuid = UUID(kdbxBytes: uuidBytes) else {
            throw KdbxError.malformedHeader("KDF parameters have no $UUID")
        }

        switch uuid {
        case KdbxKdf.aesKdfUUID:
            guard let seed = params.bytes("S"), let rounds = params.uint64("R") else {
                throw KdbxError.malformedHeader("AES-KDF parameters incomplete")
            }
            guard rounds > 0 else { throw KdbxError.malformedHeader("AES-KDF rounds must be > 0") }
            return (.aesKdf(rounds: rounds), seed)

        case KdbxKdf.argon2dUUID, KdbxKdf.argon2idUUID:
            guard let salt = params.bytes("S"),
                  let parallelism = params.uint32("P"),
                  let memoryBytes = params.uint64("M"),
                  let iterations = params.uint64("I") else {
                throw KdbxError.malformedHeader("Argon2 parameters incomplete")
            }
            // KDBX stores Argon2 memory in *bytes*; libargon2 wants KiB.
            let memoryKiB = memoryBytes / 1024
            let version = params.uint32("V") ?? 0x13

            // Bound the cost before allocating: a hostile file could otherwise ask
            // for terabytes of memory and take the process down on open.
            guard memoryKiB >= 8, memoryKiB <= 4 * 1024 * 1024 else {
                throw KdbxError.malformedHeader("Argon2 memory parameter out of range (\(memoryKiB) KiB)")
            }
            guard iterations >= 1, iterations <= 1 << 24 else {
                throw KdbxError.malformedHeader("Argon2 iteration count out of range (\(iterations))")
            }
            guard parallelism >= 1, parallelism <= 1 << 12 else {
                throw KdbxError.malformedHeader("Argon2 parallelism out of range (\(parallelism))")
            }

            if uuid == KdbxKdf.argon2dUUID {
                return (.argon2d(memoryKiB: memoryKiB, iterations: iterations,
                                 parallelism: parallelism, version: version), salt)
            } else {
                return (.argon2id(memoryKiB: memoryKiB, iterations: iterations,
                                  parallelism: parallelism, version: version), salt)
            }

        default:
            throw KdbxError.unsupportedKdf(uuid)
        }
    }
}
