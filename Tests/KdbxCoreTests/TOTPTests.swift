import Testing
import Foundation
@testable import KdbxCore

@Suite("TOTP")
struct TOTPTests {

    /// RFC 6238 Appendix B. The seeds are ASCII digits repeated to the hash's key
    /// length, and the reference codes are 8 digits.
    static let sha1Secret = Array("12345678901234567890".utf8)
    static let sha256Secret = Array("12345678901234567890123456789012".utf8)
    static let sha512Secret = Array("1234567890123456789012345678901234567890123456789012345678901234".utf8)

    @Test("RFC 6238 SHA-1 vectors",
          arguments: zip([59, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000, 20_000_000_000],
                         ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]))
    func rfc6238SHA1(time: Int, expected: String) {
        let totp = TOTP(secret: Self.sha1Secret, digits: 8, period: 30, algorithm: .sha1)
        #expect(totp.code(at: Date(timeIntervalSince1970: TimeInterval(time))) == expected)
    }

    @Test("RFC 6238 SHA-256 vectors",
          arguments: zip([59, 1_111_111_109, 1_234_567_890, 20_000_000_000],
                         ["46119246", "68084774", "91819424", "77737706"]))
    func rfc6238SHA256(time: Int, expected: String) {
        let totp = TOTP(secret: Self.sha256Secret, digits: 8, period: 30, algorithm: .sha256)
        #expect(totp.code(at: Date(timeIntervalSince1970: TimeInterval(time))) == expected)
    }

    @Test("RFC 6238 SHA-512 vectors",
          arguments: zip([59, 1_111_111_109, 1_234_567_890, 20_000_000_000],
                         ["90693936", "25091201", "93441116", "47863826"]))
    func rfc6238SHA512(time: Int, expected: String) {
        let totp = TOTP(secret: Self.sha512Secret, digits: 8, period: 30, algorithm: .sha512)
        #expect(totp.code(at: Date(timeIntervalSince1970: TimeInterval(time))) == expected)
    }

    @Test("Six-digit codes are zero-padded, not truncated")
    func padsShortCodes() {
        // A code whose numeric value is small must still be 6 characters.
        let totp = TOTP(secret: Self.sha1Secret, digits: 6, period: 30)
        for offset in 0..<200 {
            let code = totp.code(at: Date(timeIntervalSince1970: TimeInterval(offset * 30)))
            #expect(code.count == 6, "got “\(code)”")
            #expect(code.allSatisfy { $0.isNumber })
        }
    }

    @Test("The code is stable within a period and changes across the boundary")
    func rollsOverOnPeriodBoundary() {
        let totp = TOTP(secret: Self.sha1Secret, digits: 6, period: 30)
        // 1_000_000_020 is 30 × 33_333_334, i.e. exactly on a period boundary.
        // Picking a time that is *not* aligned makes this test meaningless, because
        // two timestamps 10s apart can land in the same window or different ones.
        let periodStart = 1_000_000_020.0
        let atStart = Date(timeIntervalSince1970: periodStart)
        let sameWindow = Date(timeIntervalSince1970: periodStart + 29)
        let nextWindow = Date(timeIntervalSince1970: periodStart + 30)

        #expect(totp.code(at: atStart) == totp.code(at: sameWindow))
        #expect(totp.code(at: atStart) != totp.code(at: nextWindow))
    }

    @Test("Countdown reports the time left in the period")
    func reportsSecondsRemaining() {
        let totp = TOTP(secret: Self.sha1Secret, period: 30)
        let periodStart = 1_000_000_020.0   // on a 30-second boundary; see above

        #expect(totp.secondsRemaining(at: Date(timeIntervalSince1970: periodStart)) == 30)
        #expect(totp.secondsRemaining(at: Date(timeIntervalSince1970: periodStart + 10)) == 20)
        #expect(totp.secondsRemaining(at: Date(timeIntervalSince1970: periodStart + 29)) == 1)

        let progress = totp.progress(at: Date(timeIntervalSince1970: periodStart + 15))
        #expect(abs(progress - 0.5) < 0.01)
    }

    // MARK: Base32

    @Test("Base32 decoding matches known values")
    func decodesBase32() {
        #expect(TOTP.base32Decode("JBSWY3DP").map { String(decoding: $0, as: UTF8.self) } == "Hello")
        #expect(TOTP.base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
                    .map { String(decoding: $0, as: UTF8.self) } == "12345678901234567890")
    }

    @Test("Base32 tolerates lowercase, padding, spaces and dashes")
    func decodesUntidyBase32() {
        let canonical = TOTP.base32Decode("JBSWY3DP")
        #expect(TOTP.base32Decode("jbswy3dp") == canonical)
        #expect(TOTP.base32Decode("JBSW Y3DP") == canonical)
        #expect(TOTP.base32Decode("JBSW-Y3DP") == canonical)
        #expect(TOTP.base32Decode("JBSWY3DP====") == canonical)
    }

    @Test("Characters outside the base32 alphabet are rejected")
    func rejectsInvalidBase32() {
        // 0, 1 and 8 are deliberately absent from the alphabet.
        #expect(TOTP.base32Decode("JBSWY3D0") == nil)
        #expect(TOTP.base32Decode("hello!") == nil)
    }

    // MARK: URI parsing

    @Test("A full otpauth URI is parsed")
    func parsesURI() throws {
        let totp = try #require(TOTP.parse(
            uri: "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60"))
        #expect(totp.digits == 8)
        #expect(totp.period == 60)
        #expect(totp.algorithm == .sha256)
        #expect(totp.issuer == "GitHub")
        #expect(totp.label == "GitHub:alice")
    }

    @Test("Missing parameters fall back to the RFC defaults")
    func appliesDefaults() throws {
        let totp = try #require(TOTP.parse(uri: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP"))
        #expect(totp.digits == 6)
        #expect(totp.period == 30)
        #expect(totp.algorithm == .sha1)
    }

    @Test("Counter-based HOTP URIs are refused, not silently treated as time-based")
    func refusesHOTP() {
        // Generating a time code from an HOTP secret would produce a plausible-looking
        // number that never works.
        #expect(TOTP.parse(uri: "otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP&counter=1") == nil)
    }

    @Test("Malformed URIs return nil rather than a broken generator")
    func refusesGarbage() {
        #expect(TOTP.parse(uri: "not a uri") == nil)
        #expect(TOTP.parse(uri: "otpauth://totp/Example") == nil)          // no secret
        #expect(TOTP.parse(uri: "otpauth://totp/Example?secret=!!!!") == nil)
        #expect(TOTP.parse(uri: "https://example.com?secret=JBSWY3DP") == nil)
    }

    @Test("The legacy seed + settings pair is parsed")
    func parsesLegacyFields() throws {
        let totp = try #require(TOTP.parse(seed: "JBSWY3DPEHPK3PXP", settings: "60;8"))
        #expect(totp.period == 60)
        #expect(totp.digits == 8)

        let defaults = try #require(TOTP.parse(seed: "JBSWY3DPEHPK3PXP", settings: nil))
        #expect(defaults.period == 30)
        #expect(defaults.digits == 6)

        // Steam's "S" alphabet is not RFC 6238; fall back to 6 digits rather than fail.
        let steam = try #require(TOTP.parse(seed: "JBSWY3DPEHPK3PXP", settings: "30;S"))
        #expect(steam.digits == 6)
    }

    @Test("Codes are grouped for readability")
    func formatsCodes() {
        #expect(TOTP.formatted("123456") == "123 456")
        #expect(TOTP.formatted("12345678") == "1234 5678")
        #expect(TOTP.formatted("1234") == "1234")
    }

    // MARK: Against real databases

    @Test("Both storage shapes resolve from a real database")
    func readsFromFixture() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")

        let modern = try #require(database.allEntries.first { $0.title == "TOTP Entry" })
        let modernTOTP = try #require(modern.totp, "the otpauth URI form must resolve")

        let legacy = try #require(database.allEntries.first { $0.title == "TOTP Legacy" })
        let legacyTOTP = try #require(legacy.totp, "the seed + settings form must resolve")

        // Both fixtures carry the same secret, so they must agree at the same instant.
        let moment = Date(timeIntervalSince1970: 1_700_000_000)
        #expect(modernTOTP.code(at: moment) == legacyTOTP.code(at: moment))
        #expect(modernTOTP.code(at: moment).count == 6)
    }

    @Test("An entry without TOTP reports none")
    func noTOTPIsNil() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")
        let plain = try #require(database.allEntries.first { $0.title == "Example Entry" })
        #expect(plain.totp == nil)
    }
}
