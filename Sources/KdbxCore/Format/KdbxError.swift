import Foundation

/// Every failure mode the engine can produce.
///
/// Deliberately coarse where it touches key material: `invalidCredentials` covers
/// both "wrong password" and "right password, corrupted payload", because the KDBX4
/// HMAC check cannot distinguish them and pretending otherwise would leak.
public enum KdbxError: Error, Sendable {
    case notAKdbxFile
    case unsupportedVersion(major: UInt16, minor: UInt16)
    case malformedHeader(String)
    case unsupportedCipher(UUID)
    case unsupportedKdf(UUID)
    case unsupportedCompression(UInt32)
    case invalidCredentials
    case headerCorrupted
    case payloadCorrupted(String)
    case malformedXML(String)
    case cryptoFailure(String)
    case keyfileUnreadable(String)
}

extension KdbxError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notAKdbxFile:
            return "This file isn’t a KeePass database."
        case .unsupportedVersion(let major, let minor):
            return "Unsupported database format (version \(major).\(minor))."
        case .malformedHeader(let detail):
            return "The database header is malformed: \(detail)"
        case .unsupportedCipher(let id):
            if let name = KdbxCipher.knownName(for: id) {
                return "This database is encrypted with \(name), which Fleen doesn’t support."
            }
            return "Unsupported encryption cipher (\(id.uuidString))."
        case .unsupportedKdf(let id):
            return "Unsupported key derivation function (\(id.uuidString))."
        case .unsupportedCompression(let id):
            return "Unsupported compression algorithm (\(id))."
        case .invalidCredentials:
            return "Incorrect password, key file, or both."
        case .headerCorrupted:
            return "The database header failed its integrity check — the file may be damaged or tampered with."
        case .payloadCorrupted(let detail):
            return "The database contents are damaged: \(detail)"
        case .malformedXML(let detail):
            return "The database contents could not be parsed: \(detail)"
        case .cryptoFailure(let detail):
            return "A cryptographic operation failed: \(detail)"
        case .keyfileUnreadable(let detail):
            return "The key file could not be read: \(detail)"
        }
    }
}
