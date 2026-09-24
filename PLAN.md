# Build: Native macOS KeePassXC (.kdbx) Reader with System-Wide Autofill

Build a native macOS application that reads KeePassXC (.kdbx v4) databases and
provides system-wide autofill, comparable in spirit to the KeePassXC macOS app
but faster, more native, and tightly integrated with macOS.

## Tech stack

- Swift 6 + SwiftUI for UI, AppKit where needed (NSStatusItem menu bar app,
  global event monitoring)
- No Electron, no cross-platform framework — must be a truly native,
  lightweight app
- Minimum target: macOS 14 Sonoma (needed for modern Credential Provider
  Extension APIs)
- Use Swift Package Manager, not CocoaPods

## Core functionality — Phase 1: database engine

1. Implement a KDBX4 (and ideally KDBX3 for backward compat) file parser from
   scratch or via a vetted Swift package:
   - Parse the outer header (cipher ID, compression flags, master seed,
     encryption IV, KDF parameters)
   - Support KDF: Argon2d/Argon2id (primary, via a Swift Argon2 binding) and
     AES-KDF (legacy)
   - Support ciphers: AES256-CBC and ChaCha20
   - Decrypt and decompress (gzip) the inner XML payload
   - Parse the inner XML into a Group/Entry tree: titles, usernames,
     passwords, URLs, notes, custom fields, attachments, icons, TOTP seeds
   - Support composite keys: password + keyfile + (stretch goal) YubiKey
     HMAC-SHA1 challenge-response over the standard USB HID/CCID interfaces
2. Write correctness tests against real KeePassXC-generated test .kdbx files
   (multiple KDF/cipher combos) — do NOT trust the implementation until it
   round-trips against known-good test vectors
3. All decryption must be local-only. No network calls anywhere in the app.
   Flag this explicitly in code review.

## Core functionality — Phase 2: secure app shell

1. Menu bar app (NSStatusItem), no Dock icon by default, optional main window
   for browsing/search
2. Master key entry with:
   - Password field (no plaintext logging, no plaintext in memory longer than
     necessary)
   - Touch ID / biometric unlock as a *convenience* layer on top of the real
     master key, using Keychain with `kSecAccessControlBiometryCurrentSet` —
     never store the raw master password insecurely
3. Auto-lock after configurable idle timeout, on screen lock, and on sleep
4. Clipboard copy for username/password with auto-clear after N seconds
   (configurable), and clipboard history disabled/excluded for sensitive
   copies (`org.nspasteboard.ConcealedType`)
5. Fuzzy search across all entries (title, username, URL, tags) — must be
   fast even with 10k+ entry databases (index in memory after unlock, never
   touch disk unencrypted)
6. Live file-watching: detect external changes to the .kdbx file (e.g.
   KeePassXC itself editing it) and prompt to reload

## Core functionality — Phase 3: autofill

Implement BOTH of these, since they cover different use cases:

1. **System-wide AutoFill (Safari + apps that support Password AutoFill)**:
   build an `ASCredentialProviderExtension` target so this app appears in
   System Settings > Passwords > Password Options, and in the AutoFill picker
   in Safari/apps. This requires:
   - App Group entitlement to share unlocked-session data (encrypted at rest,
     cleared on lock) between main app and extension
   - Proper `ASCredentialIdentityStoreExtension` sync so credential
     suggestions match saved URLs
   - Handle biometric/user-verification prompts inside the extension context
2. **Global Auto-Type (KeePassXC-style)**: a global hotkey (e.g.
   Cmd+Shift+V) that, when pressed in any app, matches the frontmost app's
   window title/bundle ID/URL (if browser) against entry URLs/titles, then
   synthesizes keystrokes via `CGEvent` to type username [Tab] password
   [Enter] into the focused field. Needs Accessibility permission
   (`AXIsProcessTrusted`) — handle the permission-request UX gracefully.

## Security requirements (non-negotiable)

- Master password and derived keys must be wiped from memory (zeroing
  buffers) as soon as they're no longer needed
- No sensitive data written to disk unencrypted, ever — including no debug
  logs containing passwords/keys
- App Sandbox enabled; document exactly which entitlements are needed and why
- Code-sign and notarize the build; Credential Provider Extensions require
  specific entitlements — research and apply
  `com.apple.developer.authentication-services.autofill-credential-provider`
- Threat-model note: assume the .kdbx file itself may be synced via
  iCloud/Dropbox — app must never assume exclusive file access

## UI/UX requirements (non-negotiable)

- Must feel like a first-party Apple app — study the design language of
  Passwords.app, Bitwarden's macOS app, and 1Password 8 as references, but
  don't clone any of them outright
- SwiftUI throughout, but don't fight it where AppKit is faster/more native
  (e.g. NSSearchField for the search bar, NSTableView-backed list for very
  large entry lists if SwiftUI's List starts dropping frames past a few
  thousand rows)
- Search must feel instant: no visible latency between keystroke and
  filtered results, even on a 10k+ entry database. Debounce only if
  profiling shows it's needed, not by default
- Cold launch to "ready to unlock" should be under ~300ms. Unlock-to-
  searchable should be dominated only by the Argon2 KDF time (which is
  unavoidable and expected — communicate this to the user with a real
  progress indicator, not a spinner that lies about progress)
- Full keyboard navigation: arrow keys through the list, Cmd+F to focus
  search, Cmd+C to copy password, Enter to auto-type, Esc to lock/clear
  search — no mouse required for the core workflow
- Native macOS interactions: window vibrancy/materials where appropriate,
  proper light/dark mode (including auto-switching), Quick Look-style
  previews for attachments, drag-and-drop for keyfiles
- Menu bar icon + popover should open instantly (pre-warm the view, don't
  lazily construct on first click)
- Respect Reduce Motion / accessibility settings; full VoiceOver support on
  entry list, unlock screen, and settings
- Empty states, error states (wrong password, corrupted file, missing
  keyfile) and loading states must all be designed, not default SwiftUI
  placeholders
- Settings window should be a proper macOS settings pane (Cmd+,), not a
  haphazard sheet

## Performance requirements

- Profile with Instruments (Time Profiler + Allocations) before declaring
  any phase "done" — don't just eyeball it
- Database parsing/decryption must run off the main thread; UI must never
  block during unlock or reload
- Memory: decrypted entry data should be the only sensitive data resident;
  avoid redundant copies of the decrypted tree (e.g. one canonical in-memory
  store, not a parsed-XML copy plus a separate UI-model copy)
- Binary size and launch time should be checked before shipping — this is a
  menu bar utility, it should feel weightless

## Deliverables I want from you

1. Start by proposing the project structure (main app target + extension
   target + shared framework for the KDBX engine) before writing code
2. Build Phase 1 first and prove it against real test .kdbx files before
   moving to UI
3. Flag any part where a third-party crypto library is safer than a custom
   implementation (e.g. Argon2, AES) — prefer well-audited libraries
   (CryptoKit where possible, libsodium/Argon2 bindings otherwise) over
   hand-rolled crypto
4. After each phase, summarize what's implemented, what's stubbed, and what
   security review is still needed
5. Include a README covering: build steps, entitlements setup, how to enable
   the Credential Provider in System Settings, and known limitations

Ask me clarifying questions about scope (e.g. do I need Windows/attachment
support, YubiKey support, browser extension integration) before starting if
anything is ambiguous.
