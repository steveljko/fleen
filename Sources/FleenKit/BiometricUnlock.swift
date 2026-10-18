import Foundation
import LocalAuthentication
import Security
import CryptoKit
import KdbxCore

/// Touch ID unlock, as a convenience layer over the real master key — never a
/// replacement for it.
///
/// What is stored is the **composite key** (the SHA-256 over the password and key
/// file hashes), not the master password. That distinction matters:
///
/// * The password itself is never written anywhere, so it cannot leak from here and
///   be tried against the user's other accounts.
/// * The composite key is still only an *input* to the KDF. Unlocking with Touch ID
///   runs the full Argon2 derivation exactly as a typed password does, so enabling
///   biometrics does not weaken the KDF or make the database cheaper to attack.
///
/// The item is protected with `.biometryCurrentSet`, so **enrolling a new finger or
/// face invalidates it** and the user must type the master password again. That is
/// the intended behaviour: an attacker who can add a biometric to the device must
/// not thereby gain the vault.
public enum BiometricUnlock {

    public enum Failure: Error, LocalizedError {
        case notAvailable(String)
        case userCancelled
        case itemNotFound
        case keychain(OSStatus)
        /// The Keychain accepted the item but does not enforce its biometric gate.
        case protectionNotEnforced
        /// The biometric prompt was shown and did not succeed.
        case authenticationFailed(String)

        public var errorDescription: String? {
            switch self {
            case .notAvailable(let reason): return reason
            case .userCancelled: return "Unlock was cancelled."
            case .itemNotFound: return "No saved key for this database — unlock with your master password first."
            case .keychain(let status):
                return Keychain.describe(status)
            case .authenticationFailed(let detail):
                return detail
            case .protectionNotEnforced:
                return "Touch ID can’t be used safely in this build. macOS stored the key without enforcing the biometric lock, so it would open with no prompt at all. Sign the app with your Apple Developer team to enable Touch ID."
            }
        }
    }

    /// How strongly a stored key is tied to the user's biometrics.
    ///
    /// The distinction is not cosmetic and is surfaced in Settings, because the two
    /// give genuinely different guarantees.
    public enum ProtectionLevel: Sendable, Equatable {
        /// The Keychain itself refuses to release the key without biometrics. Requires
        /// a build signed with an Apple Developer team.
        case enforcedByKeychain
        /// The key sits in the login keychain and *Fleen* demands biometrics before
        /// reading it. A real Touch ID prompt, but enforced by this app rather than by
        /// the OS — so someone running code as you could read the key without it.
        case enforcedByApp

        public var isCryptographicallyBound: Bool { self == .enforcedByKeychain }

        public var explanation: String {
            switch self {
            case .enforcedByKeychain:
                return "The key is held in the Keychain, which will not release it without Touch ID."
            case .enforcedByApp:
                return "This build is not signed, so macOS will not enforce the Touch ID lock on the stored key. Fleen still requires Touch ID before reading it, but that is enforced by the app rather than by the system. Sign the build for the stronger guarantee."
            }
        }
    }

    /// The level this build can actually deliver.
    public static var availableProtectionLevel: ProtectionLevel {
        Keychain.supportsDataProtection ? .enforcedByKeychain : .enforcedByApp
    }

    /// Whether this build may store a key at all.
    ///
    /// App-enforced storage leaves the composite key in the login keychain with no OS
    /// gate, where anyone who knows the macOS login password can read it with
    /// `security find-generic-password -w` — and with the `.kdbx` that key opens the
    /// vault. That is acceptable for a development build and nothing else, so a release
    /// build without the data-protection keychain offers no Touch ID at all.
    public static var canStoreKeys: Bool {
        #if DEBUG
        return true
        #else
        return availableProtectionLevel.isCryptographicallyBound
        #endif
    }

    static let unsignedBuildReason =
        "Touch ID needs a build signed with your Apple Developer team, so macOS itself can guard the stored key."

    static let service = "com.fleen.Fleen.vault-key"

    public enum Biometry: Sendable, Equatable {
        case touchID
        case opticID
        /// No biometric sensor, but the Mac's own login password can still authorise —
        /// which is the whole point of the fallback: a Mac without Touch ID, or with the
        /// lid shut and an external keyboard attached, is not a Mac without security.
        case devicePassword
        case none(reason: String)

        public var isAvailable: Bool {
            if case .none = self { return false }
            return true
        }

        public var displayName: String {
            switch self {
            case .touchID: return "Touch ID"
            case .opticID: return "Optic ID"
            case .devicePassword: return "your Mac password"
            case .none: return "Biometric unlock"
            }
        }
    }

    /// The LocalAuthentication policy matching the user's choice.
    ///
    /// `.deviceOwnerAuthentication` is satisfied by the sensor *or* the Mac's login
    /// password, which keeps unlocking possible with the lid shut or on a Mac without
    /// Touch ID — but it also means the login password alone opens the vault. That is a
    /// real reduction (the login password is typed far more often, in front of more
    /// people, than the master password), so it is opt-in.
    static func policy(allowDevicePassword: Bool) -> LAPolicy {
        allowDevicePassword ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics
    }

    /// What this Mac can actually do, for the settings UI to reflect honestly.
    public static func availability(
        allowDevicePassword: Bool = Preferences.shared.allowDevicePasswordFallback
    ) -> Biometry {
        guard canStoreKeys else { return .none(reason: unsignedBuildReason) }
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(policy(allowDevicePassword: allowDevicePassword),
                                        error: &error) else {
            return .none(reason: error?.localizedDescription
                         ?? "This Mac cannot authenticate you — set a login password first.")
        }
        switch context.biometryType {
        case .touchID: return .touchID
        case .opticID: return .opticID
        default: return .devicePassword
        }
    }

    /// Stores the composite key behind a biometric gate.
    ///
    /// Uses the data-protection keychain when the build can (the OS then refuses to
    /// release the key without Touch ID). When it cannot — an unsigned build, where the
    /// legacy keychain accepts an access-control policy and then ignores it — the key is
    /// stored plainly and Fleen requires Touch ID itself before reading it. Which of the
    /// two applied is reported by `availableProtectionLevel`, and shown in Settings,
    /// because they are not equivalent.
    public static func enroll(
        compositeKey: SecureBytes, account: String,
        allowDevicePassword: Bool = Preferences.shared.allowDevicePasswordFallback
    ) throws {
        guard canStoreKeys else { throw Failure.notAvailable(unsignedBuildReason) }
        remove(account: account)

        var secret = compositeKey.unsafeData()
        defer { SecureBytes.wipe(&secret) }

        switch availableProtectionLevel {
        case .enforcedByKeychain:
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                // Device-only: never syncs to iCloud Keychain, never restored onto
                // different hardware.
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                // `.biometryCurrentSet`: enrolling a new fingerprint invalidates the
                // key. The login password is accepted only if the user opted in, since
                // it then opens the vault on its own.
                allowDevicePassword ? [.biometryCurrentSet, .or, .devicePasscode]
                                    : [.biometryCurrentSet],
                &error
            ) else {
                let message = (error?.takeRetainedValue()).map { String(describing: $0) }
                    ?? "could not create an access control policy"
                throw Failure.notAvailable(message)
            }

            var query = baseQuery(account: account)
            query[kSecValueData as String] = secret
            query[kSecAttrAccessControl as String] = access
            query[kSecUseDataProtectionKeychain as String] = true

            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else { throw Failure.keychain(status) }

            // Trust nothing: confirm the gate is actually enforced before reporting
            // success. The legacy keychain silently ignores the policy, and a key that
            // reads back with no prompt would be a placebo lock.
            guard isProtectionEnforced(account: account) else {
                remove(account: account)
                throw Failure.protectionNotEnforced
            }

        case .enforcedByApp:
            // No access control: it would be ignored here, and attaching one would
            // imply protection that does not exist.
            var query = baseQuery(account: account)
            query[kSecValueData as String] = secret
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            query[kSecUseDataProtectionKeychain as String] = false

            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else { throw Failure.keychain(status) }
        }
    }

    /// The shared query identifying this database's key.
    static func baseQuery(account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        // No access group: the key is this app's alone. A shared group existed only so
        // another process in the group could read it. Nothing else needs it.
        return query
    }

    /// Whether the stored item genuinely demands user presence.
    ///
    /// Asks for the data with interaction forbidden. A properly protected item
    /// answers `errSecInteractionNotAllowed`; an unprotected one simply hands the key
    /// over, which is exactly the case worth catching.
    public static func isProtectionEnforced(account: String) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        let status = Keychain.copyMatching(query, into: &item)

        if status == errSecSuccess {
            // The key came back with no authentication: the gate is not enforced.
            if var data = item as? Data { SecureBytes.wipe(&data) }
            return false
        }
        // Anything that refused to answer without interaction is enforcing something.
        return status == errSecInteractionNotAllowed || status == errSecAuthFailed
            || status == errSecUserCanceled
    }

    /// Prompts for biometrics and returns the stored composite key.
    ///
    /// Async because in app-enforced mode the biometric prompt is ours to present, and
    /// `LAContext.evaluatePolicy` is callback-based.
    public static func retrieve(
        account: String, reason: String,
        allowDevicePassword: Bool = Preferences.shared.allowDevicePasswordFallback
    ) async throws -> SecureBytes {
        guard canStoreKeys else { throw Failure.notAvailable(unsignedBuildReason) }
        switch availableProtectionLevel {
        case .enforcedByKeychain:
            // The Keychain shows its own prompt as a condition of releasing the item.
            guard isProtectionEnforced(account: account) else {
                remove(account: account)
                throw Failure.protectionNotEnforced
            }

            let context = LAContext()
            context.localizedReason = reason
            // With the fallback on, the button asks for the Mac's login password. With
            // it off, the item will not accept that password anyway, so the button
            // leads back to the master password field instead (it cancels the prompt).
            context.localizedFallbackTitle = allowDevicePassword
                ? "Use Password…" : "Use Master Password"

            var query = baseQuery(account: account)
            query[kSecReturnData as String] = true
            query[kSecUseAuthenticationContext as String] = context
            query[kSecUseOperationPrompt as String] = reason
            query[kSecUseDataProtectionKeychain as String] = true

            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            switch status {
            case errSecSuccess:
                guard var data = item as? Data else { throw Failure.itemNotFound }
                defer { SecureBytes.wipe(&data) }
                return SecureBytes(data)
            case errSecItemNotFound:
                throw Failure.itemNotFound
            case errSecUserCanceled, errSecAuthFailed:
                throw Failure.userCancelled
            default:
                throw Failure.keychain(status)
            }

        case .enforcedByApp:
            // Demand biometrics before touching the item. This is the whole protection
            // in this mode, so it happens first and a failure returns nothing.
            try await authenticate(reason: reason, allowDevicePassword: allowDevicePassword)

            var query = baseQuery(account: account)
            query[kSecReturnData as String] = true
            query[kSecUseDataProtectionKeychain as String] = false

            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            guard status == errSecSuccess, var data = item as? Data else {
                throw status == errSecItemNotFound
                    ? Failure.itemNotFound
                    : Failure.keychain(status)
            }
            defer { SecureBytes.wipe(&data) }
            return SecureBytes(data)
        }
    }

    #if DEBUG
    /// Test seam, compiled only in debug builds.
    ///
    /// Replaces *the prompt*, never the requirement: `retrieve` still refuses to return
    /// a key unless this succeeds. It exists because the alternative is a test suite
    /// that puts a real Touch ID prompt in front of whoever runs it, and then passes or
    /// fails depending on whether they touched the sensor.
    nonisolated(unsafe) static var authenticatorForTesting: (@Sendable (String) async throws -> Void)?
    #endif

    /// Presents the system biometric prompt, throwing unless it succeeds.
    static func authenticate(reason: String, allowDevicePassword: Bool) async throws {
        #if DEBUG
        if let authenticatorForTesting {
            try await authenticatorForTesting(reason)
            return
        }
        #endif

        let context = LAContext()
        context.localizedFallbackTitle = allowDevicePassword
            ? "Use Password…" : "Use Master Password"
        let policy = Self.policy(allowDevicePassword: allowDevicePassword)

        var availabilityError: NSError?
        guard context.canEvaluatePolicy(policy, error: &availabilityError) else {
            throw Failure.notAvailable(
                availabilityError.map { describe($0) }
                ?? "This Mac cannot authenticate you — set a login password first.")
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(policy, localizedReason: reason) { success, error in
                // `context` is captured here deliberately, and this is not redundant.
                //
                // An `LAContext` must stay alive for the whole evaluation. Only the
                // outer closure referenced it before, and that closure is released as
                // soon as `evaluatePolicy` returns — so the context could be
                // deallocated mid-prompt, which cancels the evaluation and reports a
                // generic failure. That is what surfaced as "authentication failed"
                // even when the fingerprint was fine.
                withExtendedLifetime(context) {
                    if success {
                        continuation.resume()
                        return
                    }
                    guard let error else {
                        continuation.resume(throwing: Failure.authenticationFailed(
                            "Touch ID did not complete."))
                        return
                    }
                    continuation.resume(throwing: Self.failure(for: error as NSError))
                }
            }
        }
    }

    /// Maps LocalAuthentication errors to something the user can act on.
    ///
    /// The distinctions matter: a lockout needs the master password, a cancel needs
    /// nothing at all, and only an actual mismatch is worth calling a failure.
    static func failure(for error: NSError) -> Failure {
        guard error.domain == LAError.errorDomain,
              let code = LAError.Code(rawValue: error.code) else {
            return .authenticationFailed(error.localizedDescription)
        }

        switch code {
        case .userCancel, .systemCancel, .appCancel:
            return .userCancelled
        case .userFallback:
            // The user asked for the password route; not an error.
            return .userCancelled
        case .biometryLockout:
            return .authenticationFailed(
                "Touch ID is locked because of too many failed attempts. Unlock with your master password once to re-enable it.")
        case .biometryNotEnrolled:
            return .notAvailable("No fingerprints are enrolled on this Mac. Add one in System Settings › Touch ID & Password.")
        case .biometryNotAvailable:
            return .notAvailable("Touch ID is not available on this Mac.")
        case .authenticationFailed:
            return .authenticationFailed("Touch ID didn’t recognise you. Try again, or use your master password.")
        default:
            return .authenticationFailed(error.localizedDescription)
        }
    }

    static func describe(_ error: NSError) -> String {
        switch failure(for: error) {
        case .notAvailable(let reason): return reason
        case .authenticationFailed(let detail): return detail
        default: return error.localizedDescription
        }
    }

    public static func hasEnrolledKey(account: String) -> Bool {
        guard canStoreKeys else { return false }
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = false
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail

        var item: CFTypeRef?
        let status = Keychain.copyMatching(query, into: &item)
        guard status == errSecSuccess || status == errSecInteractionNotAllowed else {
            return false
        }

        switch availableProtectionLevel {
        case .enforcedByKeychain:
            // Present is not enough: an item that opens without a prompt must not put a
            // Touch ID button on the unlock screen.
            return isProtectionEnforced(account: account)
        case .enforcedByApp:
            // In this mode the item deliberately has no OS-level gate — Fleen supplies
            // the prompt — so existence is the right question to ask.
            return true
        }
    }

    @discardableResult
    public static func remove(account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        return Keychain.delete(query) == errSecSuccess
    }

    /// Removes every stored key, for every database. Used when the user turns Touch ID
    /// off or changes what it accepts: an unused key left behind is still a key.
    public static func removeAll() {
        _ = Keychain.delete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ])
    }

    /// Deletes keys a release build must not keep: anything in the legacy keychain.
    ///
    /// Earlier builds wrote the composite key there with no OS-level gate (app-enforced
    /// mode), where the macOS login password is enough to read it out. A release build
    /// never reads such an item, so leaving it on disk would only leave it extractable.
    /// The user re-enrols the next time they unlock with the master password.
    public static func purgeUnprotectedKeys() {
        #if !DEBUG
        _ = Keychain.deleteLegacy([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ])
        #endif
    }

    /// A stable per-database account name. The path is hashed rather than stored so
    /// the Keychain item does not disclose where the user keeps their vault.
    public static func account(for url: URL) -> String {
        let path = url.standardizedFileURL.path
        return "db-" + SHA256Hex.hash(Data(path.utf8))
    }
}

enum SHA256Hex {
    /// `SHA256Wrapper` lives inside KdbxCore and is not public, so hash here directly.
    static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
