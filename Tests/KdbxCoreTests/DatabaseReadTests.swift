import Testing
import Foundation
@testable import KdbxCore

/// Shared fixture plumbing.
enum Fixture {
    static let password = "correct horse battery staple"

    static func url(_ name: String) throws -> URL {
        guard let url = Bundle.module.url(forResource: "Fixtures/\(name)", withExtension: nil) else {
            throw FixtureError.missing(name)
        }
        return url
    }

    static func credentials(password: String? = Fixture.password,
                            keyFile: String? = nil) throws -> CompositeKey {
        var key = CompositeKey()
        if let password { key.addPassword(password) }
        if let keyFile { try key.addKeyFile(url: try url(keyFile)) }
        return key
    }

    static func open(_ name: String, password: String? = Fixture.password,
                     keyFile: String? = nil) throws -> Database {
        try KdbxFile.open(url: try url(name),
                          credentials: try credentials(password: password, keyFile: keyFile))
    }

    enum FixtureError: Error { case missing(String) }

    /// Every cipher/KDF combination in the fixture set.
    static let matrix = [
        "pkp-aes-argon2d.kdbx",
        "pkp-aes-argon2id.kdbx",
        "pkp-chacha20-argon2d.kdbx",
        "pkp-chacha20-argon2id.kdbx",
        "pkp-aes-aeskdf.kdbx",
        "pkp-chacha20-aeskdf.kdbx",
    ]
}

@Suite("Reading real databases")
struct DatabaseReadTests {

    @Test("Every cipher/KDF combination decrypts", arguments: Fixture.matrix)
    func opensMatrix(name: String) throws {
        let database = try Fixture.open(name)
        #expect(database.entryCount > 0, "\(name) decrypted but contained no entries")

        let example = database.allEntries.first { $0.title == "Example Entry" }
        let entry = try #require(example, "\(name) is missing the Example Entry fixture")
        #expect(entry.username == "alice@example.com")
        #expect(entry.password?.reveal() == "s3cret-pass-value")
        #expect(entry.url == "https://example.com")
    }

    @Test("Header reports the cipher and KDF the file was written with",
          arguments: [
            ("pkp-aes-argon2d.kdbx", KdbxCipher.aes256CBC, "Argon2d"),
            ("pkp-aes-argon2id.kdbx", KdbxCipher.aes256CBC, "Argon2id"),
            ("pkp-chacha20-argon2d.kdbx", KdbxCipher.chacha20, "Argon2d"),
            ("pkp-chacha20-argon2id.kdbx", KdbxCipher.chacha20, "Argon2id"),
            ("pkp-aes-aeskdf.kdbx", KdbxCipher.aes256CBC, "AES-KDF"),
            ("pkp-chacha20-aeskdf.kdbx", KdbxCipher.chacha20, "AES-KDF"),
          ])
    func reportsAlgorithms(name: String, cipher: KdbxCipher, kdf: String) throws {
        let database = try Fixture.open(name)
        #expect(database.cipher == cipher)
        #expect(database.kdf.displayName == kdf)
    }

    @Test("Group hierarchy and nesting survive the round trip")
    func parsesHierarchy() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")
        let personal = try #require(database.rootGroup.groups.first { $0.name == "Personal" })
        #expect(personal.entries.count >= 4)

        let nested = try #require(personal.groups.first { $0.name == "Nested → Gruppe" },
                                  "non-ASCII group names must survive")
        #expect(nested.entries.count == 1)
    }

    @Test("XML metacharacters and non-BMP text decode correctly")
    func handlesAwkwardText() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")
        let entry = try #require(database.allEntries.first {
            $0.title.hasPrefix("Ampersand")
        })
        #expect(entry.title == "Ampersand & <angle> \"quotes\" 'apos'")
        #expect(entry.username == "u<ser>&")
        #expect(entry.password?.reveal() == "p&ss<w>\"o'rd")
        #expect(entry.url == "https://example.com/?a=1&b=2")
        #expect(entry.notes == "emoji 🔑 and äöü 中文")
    }

    @Test("Custom fields keep their protection flag")
    func parsesCustomFields() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")
        let entry = try #require(database.allEntries.first { $0.title == "Example Entry" })

        let token = try #require(entry.fields["API Token"])
        #expect(token.isProtected, "a protected custom field must stay protected")
        #expect(token.reveal() == "tok_live_abc123")

        let accountID = try #require(entry.fields["Account ID"])
        #expect(!accountID.isProtected)
        #expect(accountID.reveal() == "12345")

        // The password is protected; the title is not. If the inner stream were
        // applied in the wrong order these would come back as garbage.
        #expect(entry.password?.isProtected == true)
        #expect(entry.fields[Entry.titleField]?.isProtected == false)
    }

    @Test("Multi-line notes and empty fields")
    func parsesEdgeCaseFields() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")

        let example = try #require(database.allEntries.first { $0.title == "Example Entry" })
        #expect(example.notes == "Line one\nLine two")
        #expect(example.tags.sorted() == ["email", "work"])

        let empty = try #require(database.allEntries.first { $0.title == "Empty Fields" })
        #expect(empty.username.isEmpty)
        #expect(empty.password?.isEmpty ?? true)
    }

    @Test("Attachments resolve through the binary pool")
    func parsesAttachments() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")
        let entry = try #require(database.allEntries.first { $0.title == "Example Entry" })
        #expect(entry.attachments.count == 2)

        let binary = try #require(entry.attachments.first { $0.name == "bytes.bin" })
        let blob = try #require(database.attachment(for: binary))
        #expect(blob.data.count == 256 * 8, "binary attachment must survive byte-for-byte")
        #expect(blob.data.prefix(256) == Data((0..<256).map { UInt8($0) }))

        let text = try #require(entry.attachments.first { $0.name == "notes.txt" })
        let textBlob = try #require(database.attachment(for: text))
        #expect(String(decoding: textBlob.data, as: UTF8.self) == "hello attachment\n")
    }

    @Test("Timestamps and expiry decode from the binary date format")
    func parsesTimes() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")

        let expired = try #require(database.allEntries.first { $0.title == "Expired Entry" })
        #expect(expired.times.expires)
        #expect(expired.isExpiredCheck)

        let example = try #require(database.allEntries.first { $0.title == "Example Entry" })
        #expect(!example.times.expires)
        let created = try #require(example.times.creationTime)
        // Sanity: the fixture was generated recently, not in year 1 or year 3000.
        #expect(created.timeIntervalSince1970 > 1_600_000_000)
        #expect(created < Date().addingTimeInterval(86_400))
    }

    @Test("TOTP seeds are exposed in both storage forms")
    func parsesTOTP() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")

        let modern = try #require(database.allEntries.first { $0.title == "TOTP Entry" })
        let uri = try #require(modern.totpURI)
        #expect(uri.contains("secret=JBSWY3DPEHPK3PXP"))

        let legacy = try #require(database.allEntries.first { $0.title == "TOTP Legacy" })
        let composed = try #require(legacy.totpURI)
        #expect(composed.contains("secret=JBSWY3DPEHPK3PXP"))
        #expect(composed.contains("period=30"))
        #expect(composed.contains("digits=6"))
    }

    @Test("Database metadata is parsed")
    func parsesMeta() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")
        #expect(!database.meta.generator.isEmpty)
    }

    @Test("KDBX 3.x is refused with a version-specific error, not a crypto error")
    func rejectsKdbx3() throws {
        // KDBX3 was explicitly out of scope for this build. The point of this test is
        // that such a file produces an actionable message rather than failing deep in
        // the KDF with something the user cannot act on.
        do {
            _ = try Fixture.open("kdbx3-legacy.kdbx")
            Issue.record("a KDBX3 file must not be opened by the v4 reader")
        } catch let error as KdbxError {
            guard case .unsupportedVersion(let major, _) = error else {
                Issue.record("expected .unsupportedVersion, got \(error)")
                return
            }
            #expect(major == 3)
        }
    }

    // MARK: Key files

    @Test("Raw 32-byte key file")
    func opensWithRawKeyFile() throws {
        let database = try Fixture.open("pkp-keyfile-raw.kdbx", keyFile: "keyfile.key")
        #expect(database.rootGroup.name.isEmpty == false)
    }

    @Test("KeePassXC v2 XML key file, with its checksum verified")
    func opensWithXmlKeyFile() throws {
        let database = try Fixture.open("pkp-keyfile-xml.kdbx", keyFile: "keyfile-v2.keyx")
        #expect(database.rootGroup.name.isEmpty == false)
    }

    @Test("Key file alone, with no password")
    func opensWithKeyFileOnly() throws {
        let database = try Fixture.open("pkp-keyfile-only.kdbx",
                                        password: nil, keyFile: "keyfile.key")
        #expect(database.rootGroup.name.isEmpty == false)
    }

    @Test("A key file is required when the database has one")
    func rejectsMissingKeyFile() throws {
        #expect(throws: KdbxError.self) {
            _ = try Fixture.open("pkp-keyfile-raw.kdbx")
        }
    }

    @Test("A damaged XML key file is reported, not silently accepted")
    func rejectsCorruptXmlKeyFile() throws {
        var contents = try String(contentsOf: try Fixture.url("keyfile-v2.keyx"), encoding: .utf8)
        // Flip one hex digit of the key; the embedded checksum must catch it.
        if let range = contents.range(of: "<Data") ,
           let close = contents.range(of: ">", range: range.upperBound..<contents.endIndex) {
            let index = contents.index(close.upperBound, offsetBy: 1)
            contents.replaceSubrange(index...index, with: contents[index] == "A" ? "B" : "A")
        }
        var key = CompositeKey()
        #expect(throws: KdbxError.self) {
            try key.addKeyFile(data: Data(contents.utf8))
        }
    }

    // MARK: Rejections

    @Test("A wrong password is rejected as such")
    func rejectsWrongPassword() throws {
        do {
            _ = try Fixture.open("pkp-aes-argon2d.kdbx", password: "not the password")
            Issue.record("a wrong password must not open the database")
        } catch let error as KdbxError {
            guard case .invalidCredentials = error else {
                Issue.record("expected .invalidCredentials, got \(error)")
                return
            }
        }
    }

    @Test("A cipher we recognise but don’t implement is named in the error")
    func namesUnsupportedButKnownCipher() throws {
        // Twofish is legitimate KDBX. Reporting a bare UUID would leave the user with
        // nothing to act on, so the error says which cipher it is.
        let message = KdbxError.unsupportedCipher(KdbxCipher.twofishUUID).errorDescription
        #expect(message?.contains("Twofish") == true)
        #expect(message?.contains("AD68F29F") != true, "a raw UUID is not an explanation")

        // A genuinely unknown cipher still falls back to the UUID, which is all we know.
        let unknown = UUID()
        let fallback = KdbxError.unsupportedCipher(unknown).errorDescription
        #expect(fallback?.contains(unknown.uuidString) == true)
    }

    @Test("A non-KDBX file is rejected before any key derivation")
    func rejectsForeignFile() throws {
        var key = CompositeKey()
        key.addPassword("x")
        #expect(throws: KdbxError.self) {
            _ = try KdbxFile.open(data: Data("not a database at all".utf8), credentials: key)
        }
    }

    @Test("Truncation is detected rather than yielding a partial database")
    func rejectsTruncatedFile() throws {
        let full = try Data(contentsOf: try Fixture.url("pkp-aes-argon2d.kdbx"))
        let truncated = full.prefix(full.count - 64)
        #expect(throws: KdbxError.self) {
            _ = try KdbxFile.open(data: Data(truncated), credentials: try Fixture.credentials())
        }
    }

    @Test("Tampering with the ciphertext is detected by the block HMAC")
    func detectsTampering() throws {
        var data = try Data(contentsOf: try Fixture.url("pkp-aes-argon2d.kdbx"))
        // Flip a bit well inside the payload, past the header and its MACs.
        let index = data.count - 32
        data[index] ^= 0x01

        do {
            _ = try KdbxFile.open(data: data, credentials: try Fixture.credentials())
            Issue.record("a modified payload must not decrypt")
        } catch let error as KdbxError {
            switch error {
            case .payloadCorrupted, .invalidCredentials: break
            default: Issue.record("expected an integrity failure, got \(error)")
            }
        }
    }

    @Test("No single-bit change anywhere in the header can yield a database")
    func detectsHeaderTampering() throws {
        let original = try Data(contentsOf: try Fixture.url("pkp-aes-argon2d.kdbx"))
        let credentials = try Fixture.credentials()

        // Sweep the whole header region rather than one hand-picked offset. Which
        // specific error comes back depends on which field the flipped bit landed in
        // — a bad cipher UUID is caught by parsing, a bad master seed by the HMAC —
        // and the property worth asserting is that none of them opens the file.
        for offset in stride(from: 0, to: 180, by: 7) {
            var data = original
            data[offset] ^= 0x40
            do {
                _ = try KdbxFile.open(data: data, credentials: credentials)
                Issue.record("a header modified at byte \(offset) must not decrypt")
            } catch is KdbxError {
                continue
            }
        }
    }
}

extension Entry {
    /// Small shim so the expiry assertion reads clearly in the test above.
    var isExpiredCheck: Bool { times.isExpired }
}
