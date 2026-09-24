import Testing
import Foundation
import Security
@testable import FleenKit

/// Exercises the Keychain wrapper in exactly the situation that broke: an unsigned
/// binary with no Apple Developer team.
///
/// The test bundle is unsigned, so the data-protection keychain rejects it with
/// `errSecMissingEntitlement` — the same failure a locally built `Fleen.app` hits.
/// If the legacy fallback regresses, these go red here rather than only on a user's
/// machine.
///
/// Biometric access control cannot be tested: `.biometryCurrentSet` needs real user
/// presence. These cover the storage path underneath it.
@Suite("Keychain fallback", .serialized)
struct KeychainTests {

    static let service = "com.fleen.tests.keychain"

    static func query(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    static func cleanUp(account: String) {
        _ = Keychain.delete(query(account: account))
    }

    @Test("An item can be written and read back without a signing team")
    func roundTripsWithoutEntitlements() throws {
        let account = "roundtrip-\(UUID().uuidString)"
        defer { Self.cleanUp(account: account) }

        var write = Self.query(account: account)
        write[kSecValueData as String] = Data("secret-value".utf8)
        write[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let addStatus = Keychain.add(write)
        #expect(addStatus == errSecSuccess,
                "write failed: \(Keychain.describe(addStatus))")

        var read = Self.query(account: account)
        read[kSecReturnData as String] = true

        var item: CFTypeRef?
        let readStatus = Keychain.copyMatching(read, into: &item)
        #expect(readStatus == errSecSuccess,
                "read failed: \(Keychain.describe(readStatus))")
        #expect(item as? Data == Data("secret-value".utf8))
    }

    @Test("Deleting removes the item from whichever keychain holds it")
    func deletesItem() throws {
        let account = "delete-\(UUID().uuidString)"

        var write = Self.query(account: account)
        write[kSecValueData as String] = Data("x".utf8)
        #expect(Keychain.add(write) == errSecSuccess)

        _ = Keychain.delete(Self.query(account: account))

        var read = Self.query(account: account)
        read[kSecReturnData as String] = true
        var item: CFTypeRef?
        #expect(Keychain.copyMatching(read, into: &item) == errSecItemNotFound)
    }

    @Test("A missing item reports not-found rather than an entitlement error")
    func missingItemIsNotFound() {
        var read = Self.query(account: "never-written-\(UUID().uuidString)")
        read[kSecReturnData as String] = true
        var item: CFTypeRef?

        let status = Keychain.copyMatching(read, into: &item)
        #expect(status == errSecItemNotFound)
        #expect(status != Keychain.missingEntitlement,
                "the fallback should have handled the entitlement case")
    }

    @Test("The entitlement failure is explained in plain language")
    func describesMissingEntitlement() {
        let message = Keychain.describe(Keychain.missingEntitlement)
        #expect(message.contains("Developer team"))
        #expect(!message.contains("-34018"), "a raw OSStatus is not an explanation")
    }
}
