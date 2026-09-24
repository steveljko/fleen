import Foundation
import Security

/// Keychain access that works in both a signed and an unsigned build.
///
/// macOS has two keychains. The modern **data-protection** keychain is the one that
/// supports access-control flags properly, but it requires an `application-identifier`
/// entitlement, which only a build signed with a real team has. Ask for it without
/// that entitlement and every call fails with `errSecMissingEntitlement` (-34018) —
/// which surfaces to the user as "a required entitlement isn't present" and no
/// working Touch ID.
///
/// The legacy file-based keychain has no such requirement and still supports
/// biometric ACLs, so it is a genuine fallback rather than a downgrade in what the
/// user gets: the item is still gated on Touch ID either way.
///
/// So every call tries the data-protection keychain first and retries on the legacy
/// one when the entitlement is missing. Signed builds get the modern behaviour;
/// unsigned development builds still work.
enum Keychain {

    static let missingEntitlement: OSStatus = -34018

    private static func dataProtection(_ query: [String: Any]) -> [String: Any] {
        var query = query
        query[kSecUseDataProtectionKeychain as String] = true
        return query
    }

    private static func legacy(_ query: [String: Any]) -> [String: Any] {
        var query = query
        query[kSecUseDataProtectionKeychain as String] = false
        // An access group is a data-protection concept and is itself entitlement
        // gated; leaving it in guarantees the fallback fails too.
        query.removeValue(forKey: kSecAttrAccessGroup as String)
        return query
    }

    /// Whether this build can use the data-protection keychain at all.
    ///
    /// Probed once by attempting a throwaway write: the answer depends on whether the
    /// binary carries an `application-identifier` entitlement, which only a build
    /// signed with a real Apple Developer team has. Callers need to know because it
    /// decides whether a biometric gate can be *enforced by the OS* or only by us.
    static let supportsDataProtection: Bool = {
        let probe: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.fleen.Fleen.capability-probe",
            kSecAttrAccount as String: "probe",
            kSecValueData as String: Data([0]),
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(probe as CFDictionary)
        let status = SecItemAdd(probe as CFDictionary, nil)
        SecItemDelete(probe as CFDictionary)
        return status != missingEntitlement
    }()

    static func add(_ query: [String: Any]) -> OSStatus {
        let status = SecItemAdd(dataProtection(query) as CFDictionary, nil)
        guard status == missingEntitlement else { return status }
        return SecItemAdd(legacy(query) as CFDictionary, nil)
    }

    static func copyMatching(_ query: [String: Any], into result: inout CFTypeRef?) -> OSStatus {
        let status = SecItemCopyMatching(dataProtection(query) as CFDictionary, &result)

        // Fall through on "not found" as well as on the entitlement failure. A read
        // only reports the missing entitlement when there is something to refuse; for
        // an item that lives in the legacy keychain it simply reports nothing found,
        // so keying the fallback on the entitlement error alone means writes land in
        // one keychain and reads look in the other.
        guard status == missingEntitlement || status == errSecItemNotFound else {
            return status
        }

        var fallbackResult: CFTypeRef?
        let fallbackStatus = SecItemCopyMatching(legacy(query) as CFDictionary, &fallbackResult)
        if fallbackStatus == errSecSuccess {
            result = fallbackResult
            return fallbackStatus
        }
        // Neither had it: report the legacy status unless the first attempt carried
        // the more informative entitlement error.
        return status == missingEntitlement ? status : fallbackStatus
    }

    static func delete(_ query: [String: Any]) -> OSStatus {
        let status = SecItemDelete(dataProtection(query) as CFDictionary)
        // Delete from both: an earlier build may have written to either one, and a
        // stale item left behind would shadow the new one.
        _ = SecItemDelete(legacy(query) as CFDictionary)
        return status
    }

    /// Maps the statuses worth explaining differently.
    static func describe(_ status: OSStatus) -> String {
        switch status {
        case missingEntitlement:
            return "macOS refused Keychain access because the app is not signed with an Apple Developer team. Sign the build to enable Touch ID."
        case errSecUserCanceled:
            return "Authentication was cancelled."
        case errSecAuthFailed:
            return "Authentication failed."
        case errSecItemNotFound:
            return "No saved key was found."
        default:
            return SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)"
        }
    }
}
