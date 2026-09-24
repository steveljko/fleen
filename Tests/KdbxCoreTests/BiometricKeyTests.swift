import Testing
import Foundation
@testable import KdbxCore

/// Covers the key path biometric unlock takes.
///
/// Touch ID does not replace the KDF: what is stored is the *composite key*, and
/// unlocking with it must derive byte-identically to typing the password. These tests
/// pin that equivalence without touching the Keychain, which cannot be exercised in a
/// test run.
@Suite("Biometric key round trip")
struct BiometricKeyTests {

    @Test("A stored composite key reproduces the same derived key as the password")
    func precomposedKeyMatchesPassword() throws {
        var typed = CompositeKey()
        typed.addPassword("correct horse battery staple")
        let stored = typed.rawKey()

        // This is exactly what enrolment saves and biometric unlock loads back.
        let restored = CompositeKey.precomposed(stored)

        #expect(restored.rawKey().isEqual(to: stored),
                "re-hashing the stored key would derive a different master key entirely")
    }

    @Test("A real database opens with the stored composite key, not just the password")
    func opensFixtureWithStoredKey() throws {
        // Uses a fixture rather than a database written here: the engine no longer
        // writes KDBX files, and reading a file another implementation produced is the
        // stronger check anyway.
        var typed = CompositeKey()
        typed.addPassword(Fixture.password)

        // This is exactly the value enrolment stores behind Touch ID.
        let biometric = CompositeKey.precomposed(typed.rawKey())

        let database = try KdbxFile.open(url: try Fixture.url("pkp-aes-argon2d.kdbx"),
                                         credentials: biometric)
        let entry = try #require(database.allEntries.first { $0.title == "Example Entry" })
        #expect(entry.password?.reveal() == "s3cret-pass-value")
    }

    @Test("Password plus key file also round-trips through a stored composite key")
    func opensWithStoredKeyForCompositeCredentials() throws {
        var typed = CompositeKey()
        typed.addPassword(Fixture.password)
        try typed.addKeyFile(url: try Fixture.url("keyfile.key"))

        let biometric = CompositeKey.precomposed(typed.rawKey())
        #expect(throws: Never.self) {
            _ = try KdbxFile.open(url: try Fixture.url("pkp-keyfile-raw.kdbx"),
                                  credentials: biometric)
        }
    }

    @Test("A precomposed key is not empty, so it is accepted for unlocking")
    func precomposedKeyIsNotEmpty() {
        let key = CompositeKey.precomposed(SecureBytes([UInt8](repeating: 7, count: 32)))
        #expect(!key.isEmpty)
    }

    @Test("addRawKey still behaves as a component, for challenge-response keys")
    func rawKeyRemainsAComponent() {
        // addRawKey exists for YubiKey-style challenge-response, where the value IS
        // one component among several. It must not be confused with a finished key.
        let material = SecureBytes([UInt8](repeating: 3, count: 32))

        var asComponent = CompositeKey()
        asComponent.addRawKey(material)

        let asFinished = CompositeKey.precomposed(material)

        #expect(!asComponent.rawKey().isEqual(to: asFinished.rawKey()),
                "a component is hashed; a precomposed key is used as-is")
    }
}
