import Foundation
import CryptoKit

/// The user-supplied half of the key: password and/or key file.
///
/// KeePass composes these by hashing each component to 32 bytes, concatenating in a
/// fixed order (password, then key file), and hashing the concatenation. Order is
/// part of the format — getting it wrong yields a valid-looking key that simply
/// never opens anything.
public struct CompositeKey: Sendable {
    private var components: [SecureBytes] = []

    /// A composite key that has already been computed, used as-is.
    ///
    /// Distinct from a component because `rawKey()` hashes its components: feeding a
    /// finished key back in as a component would hash it a second time and derive a
    /// completely different master key.
    private var finishedKey: SecureBytes?

    public init() {}

    /// Wraps an already-computed composite key — the value `rawKey()` produced
    /// earlier, as stored behind Touch ID.
    ///
    /// The result derives byte-identically to the credentials it came from, which is
    /// what makes biometric unlock equivalent to typing the password rather than a
    /// separate, weaker path.
    public static func precomposed(_ rawKey: SecureBytes) -> CompositeKey {
        var key = CompositeKey()
        key.finishedKey = rawKey
        return key
    }

    public mutating func addPassword(_ password: SecureBytes) {
        let digest = password.withUnsafeBytes { SHA256.hash(data: Data($0)) }
        components.append(SecureBytes(Array(digest)))
    }

    public mutating func addPassword(_ password: String) {
        let secure = SecureBytes.fromUTF8(password)
        addPassword(secure)
    }

    /// Adds a key file, honouring all four formats KeePass recognises.
    public mutating func addKeyFile(data: Data) throws {
        components.append(try Self.keyFileKey(from: data))
    }

    public mutating func addKeyFile(url: URL) throws {
        do {
            try addKeyFile(data: Data(contentsOf: url))
        } catch let error as KdbxError {
            throw error
        } catch {
            throw KdbxError.keyfileUnreadable(error.localizedDescription)
        }
    }

    /// Adds an already-derived 32-byte key as **one component**, e.g. a YubiKey
    /// challenge-response result. Not wired to hardware in this build.
    ///
    /// For a key that is already the finished composite, use `precomposed(_:)`.
    public mutating func addRawKey(_ key: SecureBytes) {
        components.append(key)
    }

    public var isEmpty: Bool { components.isEmpty && finishedKey == nil }

    static func keyFileKey(from data: Data) throws -> SecureBytes {
        // 1. KeePass XML key file (v1 and v2). Checked first because an XML file
        //    could coincidentally be 32 or 64 bytes long.
        if let key = try XmlKeyFile.parse(data) { return key }

        // 2. Raw 32-byte binary key file.
        if data.count == 32 { return SecureBytes(data) }

        // 3. 64 hex characters.
        if data.count == 64, let hex = String(data: data, encoding: .utf8),
           let bytes = Self.hexDecode(hex) {
            return SecureBytes(bytes)
        }

        // 4. Anything else: SHA-256 of the whole file.
        return SecureBytes(Array(SHA256.hash(data: data)))
    }

    private static func hexDecode(_ string: String) -> [UInt8]? {
        let chars = Array(string.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = Self.hexValue(chars[i]), let lo = Self.hexValue(chars[i + 1]) else {
                return nil
            }
            out.append(hi << 4 | lo)
            i += 2
        }
        return out
    }

    private static func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30            // 0-9
        case 0x61...0x66: return c - 0x61 + 10       // a-f
        case 0x41...0x46: return c - 0x41 + 10       // A-F
        default: return nil
        }
    }

    /// SHA-256 over the concatenated component hashes.
    ///
    /// Public so the app layer can store it behind a biometric gate. It is still
    /// only an *input* to the KDF — holding it does not shortcut Argon2, and it is
    /// not the user's password, so it cannot be tried against their other accounts.
    public func rawKey() -> SecureBytes {
        if let finishedKey { return finishedKey }
        var hasher = SHA256()
        for component in components {
            component.withUnsafeBytes { hasher.update(data: Data($0)) }
        }
        return SecureBytes(Array(hasher.finalize()))
    }
}

/// KeePass XML key files. v1 stores base64; v2 stores hex plus a truncated SHA-256
/// checksum over the key, which we verify — a corrupted key file should say so
/// rather than silently producing a key that fails to open the database.
enum XmlKeyFile {
    static func parse(_ data: Data) throws -> SecureBytes? {
        guard let text = String(data: data, encoding: .utf8),
              text.contains("<KeyFile"), text.contains("<Key>") else { return nil }

        guard let rawData = element(named: "Data", in: text) else {
            throw KdbxError.keyfileUnreadable("XML key file has no <Data> element")
        }
        let version = element(named: "Version", in: text) ?? "1.00"

        if version.hasPrefix("2") {
            let hex = rawData.filter { !$0.isWhitespace }
            guard let bytes = hexDecode(hex) else {
                throw KdbxError.keyfileUnreadable("XML key file <Data> is not valid hex")
            }
            // v2 embeds the first 4 bytes of SHA-256(key) as a `Hash` attribute.
            if let expected = attribute(named: "Hash", ofElement: "Data", in: text),
               let expectedBytes = hexDecode(expected) {
                let actual = Array(SHA256.hash(data: Data(bytes)).prefix(expectedBytes.count))
                guard timingSafeCompare(actual, expectedBytes) else {
                    throw KdbxError.keyfileUnreadable("XML key file failed its checksum — the file is damaged")
                }
            }
            return SecureBytes(bytes)
        }

        guard let decoded = Data(base64Encoded: rawData.filter { !$0.isWhitespace }) else {
            throw KdbxError.keyfileUnreadable("XML key file <Data> is not valid base64")
        }
        return SecureBytes(decoded)
    }

    private static func element(named name: String, in text: String) -> String? {
        guard let open = text.range(of: "<\(name)"),
              let openEnd = text.range(of: ">", range: open.upperBound..<text.endIndex),
              let close = text.range(of: "</\(name)>", range: openEnd.upperBound..<text.endIndex)
        else { return nil }
        return String(text[openEnd.upperBound..<close.lowerBound])
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func attribute(named attr: String, ofElement element: String, in text: String) -> String? {
        guard let open = text.range(of: "<\(element)"),
              let openEnd = text.range(of: ">", range: open.upperBound..<text.endIndex) else { return nil }
        let tag = text[open.upperBound..<openEnd.lowerBound]
        guard let attrRange = tag.range(of: "\(attr)=\"") else { return nil }
        guard let quoteEnd = tag.range(of: "\"", range: attrRange.upperBound..<tag.endIndex) else { return nil }
        return String(tag[attrRange.upperBound..<quoteEnd.lowerBound])
    }

    private static func hexDecode(_ string: String) -> [UInt8]? {
        let chars = Array(string.utf8)
        guard !chars.isEmpty, chars.count % 2 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = value(chars[i]), let lo = value(chars[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
            i += 2
        }
        return out
    }

    private static func value(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x61...0x66: return c - 0x61 + 10
        case 0x41...0x46: return c - 0x41 + 10
        default: return nil
        }
    }
}
