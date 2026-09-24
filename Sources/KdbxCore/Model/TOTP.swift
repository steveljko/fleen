import Foundation
import CryptoKit

/// Time-based one-time passwords (RFC 6238), as stored by KeePass.
///
/// The generator itself is a standard HOTP truncation over an HMAC; CryptoKit
/// supplies every hash, so there is no hand-rolled crypto here. The fiddly parts are
/// all in the *parsing*: KeePass databases carry TOTP configuration in at least
/// three shapes, and a reader that handles only the tidy one silently shows nothing
/// for a lot of real entries.
public struct TOTP: Sendable, Equatable {

    public enum Algorithm: String, Sendable, CaseIterable {
        case sha1 = "SHA1"
        case sha256 = "SHA256"
        case sha512 = "SHA512"
    }

    /// The shared secret, already base32-decoded.
    public let secret: [UInt8]
    public let digits: Int
    public let period: Int
    public let algorithm: Algorithm
    public let issuer: String?
    public let label: String?

    public init(secret: [UInt8], digits: Int = 6, period: Int = 30,
                algorithm: Algorithm = .sha1,
                issuer: String? = nil, label: String? = nil) {
        self.secret = secret
        // Clamp rather than reject: a database with a silly digit count should still
        // produce a usable code instead of no code at all.
        self.digits = min(max(digits, 6), 10)
        self.period = period > 0 ? period : 30
        self.algorithm = algorithm
        self.issuer = issuer
        self.label = label
    }

    // MARK: - Generating

    /// The code for a given moment, zero-padded to `digits`.
    public func code(at date: Date = Date()) -> String {
        let counter = UInt64(max(0, floor(date.timeIntervalSince1970 / Double(period))))
        return code(counter: counter)
    }

    /// HOTP (RFC 4226) over the time counter.
    func code(counter: UInt64) -> String {
        var message = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        defer { SecureBytes.wipe(&message) }

        let key = SymmetricKey(data: Data(secret))
        var mac: [UInt8]
        switch algorithm {
        case .sha1:
            mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256:
            mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512:
            mac = Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        defer { SecureBytes.wipe(&mac) }

        // Dynamic truncation: the low nibble of the last byte picks the offset.
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let binary = (UInt32(mac[offset] & 0x7F) << 24)
            | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8)
            | UInt32(mac[offset + 3])

        let modulus = UInt32(pow(10, Double(digits)))
        return String(format: "%0\(digits)u", binary % modulus)
    }

    /// Seconds until the current code expires.
    public func secondsRemaining(at date: Date = Date()) -> Int {
        let elapsed = date.timeIntervalSince1970.truncatingRemainder(dividingBy: Double(period))
        return max(0, Int((Double(period) - elapsed).rounded(.up)))
    }

    /// 0…1 through the current period, for a countdown indicator.
    public func progress(at date: Date = Date()) -> Double {
        let elapsed = date.timeIntervalSince1970.truncatingRemainder(dividingBy: Double(period))
        return min(1, max(0, elapsed / Double(period)))
    }

    /// The code grouped for legibility: "123 456" rather than "123456".
    public static func formatted(_ code: String) -> String {
        guard code.count > 4 else { return code }
        let middle = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[code.startIndex..<middle]) \(code[middle...])"
    }

    // MARK: - Parsing

    /// Parses an `otpauth://totp/...` URI.
    public static func parse(uri: String) -> TOTP? {
        guard let components = URLComponents(string: uri.trimmingCharacters(in: .whitespaces)),
              components.scheme?.lowercased() == "otpauth" else { return nil }
        // HOTP is counter-based and cannot be shown as a time code; refuse rather
        // than silently generating a wrong value.
        guard components.host?.lowercased() == "totp" else { return nil }

        let items = components.queryItems ?? []
        func value(_ name: String) -> String? {
            items.first { $0.name.lowercased() == name }?.value
        }

        guard let rawSecret = value("secret"),
              let secret = base32Decode(rawSecret), !secret.isEmpty else { return nil }

        let label = components.path.hasPrefix("/")
            ? String(components.path.dropFirst()).removingPercentEncoding
            : components.path.removingPercentEncoding

        return TOTP(
            secret: secret,
            digits: value("digits").flatMap { Int($0) } ?? 6,
            period: value("period").flatMap { Int($0) } ?? 30,
            algorithm: value("algorithm").flatMap { Algorithm(rawValue: $0.uppercased()) } ?? .sha1,
            issuer: value("issuer"),
            label: label?.isEmpty == false ? label : nil)
    }

    /// Parses KeePassXC's older field pair: a bare base32 seed plus `period;digits`.
    public static func parse(seed: String, settings: String?) -> TOTP? {
        guard let secret = base32Decode(seed), !secret.isEmpty else { return nil }

        var period = 30
        var digits = 6
        if let settings {
            let parts = settings.split(separator: ";").map(String.init)
            if let first = parts.first, let value = Int(first) { period = value }
            // The second field is "S" for Steam's alphabet, which is not RFC 6238;
            // leaving digits at 6 keeps the entry usable rather than failing outright.
            if parts.count > 1, let value = Int(parts[1]) { digits = value }
        }
        return TOTP(secret: secret, digits: digits, period: period)
    }

    /// RFC 4648 base32, tolerant of the ways secrets are written in the wild:
    /// lowercase, padding, and the spaces or dashes people paste in from a website.
    public static func base32Decode(_ string: String) -> [UInt8]? {
        var bits = 0
        var accumulator = 0
        var output: [UInt8] = []

        for character in string.uppercased() {
            if character == "=" || character == " " || character == "-" { continue }

            let value: Int
            switch character {
            case "A"..."Z":
                value = Int(character.asciiValue! - Character("A").asciiValue!)
            case "2"..."7":
                value = Int(character.asciiValue! - Character("2").asciiValue!) + 26
            default:
                return nil   // not base32 at all
            }

            accumulator = (accumulator << 5) | value
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((accumulator >> bits) & 0xFF))
            }
        }
        return output
    }
}

extension Entry {
    /// The entry's one-time password configuration, from whichever shape it is
    /// stored in. Returns nil when the entry has no TOTP.
    public var totp: TOTP? {
        // Preferred: a full otpauth URI in the `otp` field, as KeePassXC writes now.
        if let otp = fields["otp"]?.reveal(), let parsed = TOTP.parse(uri: otp) {
            return parsed
        }
        // Some databases store the URI under `TOTP` instead.
        if let otp = fields["TOTP"]?.reveal(), let parsed = TOTP.parse(uri: otp) {
            return parsed
        }
        // Older KeePassXC: a bare seed plus a settings string.
        if let seed = fields["TOTP Seed"]?.reveal() {
            return TOTP.parse(seed: seed, settings: fields["TOTP Settings"]?.reveal())
        }
        return nil
    }
}
