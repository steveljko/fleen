# Fleen — Security Audit

**Date:** 2026-10-15 · **Commit audited:** `b23414c` (main, clean tree) · **Platform:** macOS 26.6.2 (25G83), Apple Silicon, Swift 6.3.3
**Method:** full read of all 9,100 lines of Swift (`Sources/`), the build/sign scripts and entitlements; a separate harness in `audit/` that links the real `KdbxCore`/`FleenKit`, an independent KDBX4 writer (`audit/tools/kdbxgen.py`, cross-checked against pykeepass), self-memory scans for canaries and derived keys, fuzzing with 40 hostile files, and inspection of the installed release build (`/Applications/Fleen.app`) and a fresh `Scripts/build-app.sh --release` build.
No application source was modified. No real database, master password or stored keychain secret was read.

Every finding is marked **verified** (reproduced, with output) or **suspected** (from reading code or platform behaviour; not reproduced).

---

## 1. Executive summary

Fleen's engine is in good shape. Every untrusted length is bounds-checked. The header and every payload block are authenticated before decryption, in constant time. KDF cost, gzip output and XML entities are capped. There is no network code, no write path, no URL scheme or IPC surface, and the release build is sandboxed and hardened. On this macOS version, locking the vault removes the master password, every entry password and every derived key from process memory. I verified this with canary scans.

The weak spots are **around** the engine: Touch ID storage, the lock state machine, and how revealed or copied secrets leave the app.

### Can the master password or entry passwords leak, and how?

| Asset | Leaks? | How |
|---|---|---|
| **Vault contents (equivalent to the master password)** | **Yes, if Touch ID is enabled (it is on this Mac).** | Touch ID stores the composite key. With it plus the `.kdbx` file you can decrypt everything without the master password. The installed release build stores it in the **legacy login keychain, with no biometric binding** (F-01). Anyone who knows the **macOS login password** can extract it with `security find-generic-password … -w` and decrypt the vault offline, for as long as the master password stays the same. Turning Touch ID off in Settings does **not** delete it (F-02). Even with correct signing, the `.or .devicePasscode` policy makes the login password sufficient (F-01). |
| **Master password itself** | No evidence of a leak. | Never stored, logged or indexed. It is absent from memory after unlock (engine and session level; verified). The SwiftUI `SecureField` buffer was not tested dynamically (§5). |
| **Entry passwords** | **Yes, through output channels.** | (a) Revealed passwords are captured by screenshots, screen recording and screen sharing, because no window sets `sharingType = .none` (F-04). (b) Copied passwords go to the general pasteboard without `.currentHostOnly`, so **Universal Clipboard sends them to your iPhone/iPad**, where Fleen's auto-clear does not reach (F-05). (c) A lock requested during an unlock is silently undone, leaving the vault decrypted (F-03). |
| **Notes, usernames, URLs, titles (non-protected fields)** | Yes, in memory after lock. | Foundation's `XMLParser` (libxml2) keeps an unwiped copy of the whole decrypted XML that survives `lock()` (F-06). This copy does not contain protected passwords. |

**No Critical findings.** One High (F-01), five Medium, the rest Low/Info.

### Fix status (applied after the audit, same day)

All 252 tests pass (235 original + 17 new regression tests in `Tests/*/AuditRegressionTests.swift`). `audit/run_all.sh` was re-run against the fixed code.

| ID | Status | Fix | Re-verified by |
|---|---|---|---|
| F-01 | **Fixed** | `build-app.sh` merges `application-identifier`/`team-identifier` from the profile and fails the build without them. Unprotected (app-enforced) storage is debug-only. Release builds purge legacy-keychain keys at launch. Login-password fallback is an opt-in, off by default. | `codesign -d --entitlements` on a fresh `build-signed.sh` build shows both keys; policy tests |
| F-02 | **Fixed** | Turning Touch ID off, or changing the fallback, calls `BiometricUnlock.removeAll()` | code path |
| F-03 | **Fixed** | `unlockGeneration` token in `VaultSession`; auto-lock also acts while unlocking | harness `race` → `state=locked database loaded=false`; 2 tests that fail on the old code |
| F-04 | **Fixed** | `sharingType = .none` on the popover and Settings windows | not dynamically re-tested (needs GUI) |
| F-05 | **Fixed** | `prepareForNewContents(with: .currentHostOnly)` + `org.nspasteboard.TransientType` | harness `clipboard`, test |
| F-06 | **Fixed** | `XMLParser` replaced by `KdbxXmlTokenizer`, which tokenises in place over the wiped buffer and refuses DTDs | harness memscans: **no canary of any kind after lock**; the XML-comment canary never appears even while open |
| F-07 | **Fixed** | 64-bit modulus | harness `totp 10` → `code=1698480987`; test |
| F-08 | **Fixed** | Folder depth ≤ 512, no history inside history, tokenizer depth ≤ 4096 | the 4 crashing fuzz files now throw `malformedXML`; tests |
| F-09 | **Fixed** | "Open in browser" accepts http/https only | code path |
| F-10 | **Fixed** | `rawKey()` returns `finishedKey.copy()` | harness `precomposed` → two OK opens; test |
| F-11 | **Fixed** | Lock on `sessionDidResignActiveNotification` | code path, test |
| F-12 | Partly | Header limits now equal the `Argon2` limits (1 GiB / 1000 / 64). The bounded ~28 s worst case remains by design. | fuzz |
| F-13 | **Fixed** | Reference-counted page pinning | test |
| F-14 | Mitigated | Revealed fields auto-hide after 30 s. AX/Services exposure while revealed is inherent. | — |
| F-15 | **Fixed** | Digests hashed from buffers (no `Data`/`Array` temporaries), cipher state wiped, Gzip COW copy removed | memscans |
| F-16 | Partly | Large key files hashed in chunks; `getpass` buffer wiped. **Not changed:** sandbox attachment export (needs a product decision on `read-write`), the PII in scripts. | test |

---

## 2. Threat model

**In scope**
- Malware running as the same user, without root.
- A person with physical access to the Mac, unlocked or able to log in. This includes someone who knows or has observed the login password.
- A malicious or corrupt `.kdbx`: a shared vault, or a file swapped by a sync provider. The KDF parameters and header are attacker-controlled before authentication; the payload is attacker-controlled only if the attacker also supplies the password, as with a shared vault.
- Clipboard managers, Universal Clipboard, screen recording and screen sharing, backups (Time Machine copies of `~/Library`), logs.

**Out of scope:** root or kernel compromise, SIP disabled, hardware attacks on the Secure Enclave, compromise of the build machine or signing identity. Live-memory findings (F-06, F-15) only matter against out-of-scope attackers *or* via swap, hibernation images and core dumps. I report them because the README makes explicit claims about memory hygiene.

---

## 3. Recon

### 3.1 Stack and dependencies

| Item | Detail |
|---|---|
| Language / UI | Swift 6.3 (language mode 6), SwiftUI hosted in AppKit (`NSStatusItem` + `NSPopover`), hand-rolled `main.swift` |
| Build | SwiftPM (`Package.swift`) plus `Scripts/build-app.sh`, which assembles and signs the `.app` |
| Targets | `CArgon2` (vendored C), `KdbxCore` (engine), `FleenKit` (app logic), `Fleen` (UI), `fleen-cli` |
| Third-party code | **Only** `Sources/CArgon2`: PHC reference Argon2 `20190702`, described as unmodified. This is still the latest upstream release; upstream is dormant but not abandoned. **No published CVEs found** for the reference implementation. There are no SPM, CocoaPods or Carthage dependencies. |
| System libraries | CryptoKit (SHA-2, HMAC), CommonCrypto (AES-CBC/ECB), zlib (inflate), Foundation `XMLParser` (libxml2), Security, LocalAuthentication. All are patched with the OS. |
| Hand-written crypto | `ChaCha20.swift`, `Salsa20.swift`. Reviewed: correct RFC 8439 / Salsa20 quarter-rounds, no secret-dependent branches or lookups, covered by known-answer tests. Note that the key state array is never wiped (F-15). |

### 3.2 Secret data flow

```
SecureField(String @State)  ──attemptUnlock──▶ password String (copied, @State cleared)
   UnlockView.swift:245,359                      │
                                                 ▼
VaultSession.unlock ─▶ CompositeKey.addPassword(String)  SHA256(pw) → SecureBytes (mlock'd)
   VaultSession.swift:176        CompositeKey.swift:34-41    + key file (SHA/hex/XML)  ─┐
                                                                                        ▼
Task.detached ─▶ KdbxFile.open: header SHA-256 ▶ KDF(raw composite) ▶ header HMAC ▶ block HMACs
                 KdbxFile.swift:23-102          Argon2/AES-KDF          (constant time, before decrypt)
                     ▼
     AES-CBC / ChaCha20 ─▶ gzip inflate ─▶ inner header (stream key) ─▶ XMLParser (SAX)
                                                                         │ protected values: inner
                                                                         │ ChaCha20 → SecureBytes
                                                                         ▼
                              Database (Entry.fields: .plain(String) | .protected(SecureBytes))
                              + SearchIndex (title/user/url/tags only) + credentials kept for reload
                                                                         │
             ┌─────────────────────────────┬────────────────────────────┼────────────────────────┐
             ▼                             ▼                            ▼                        ▼
     reveal() → String → Text      copySecret → NSPasteboard     Touch ID enrol:          lock(): database=nil,
     (EntryDetailView FieldRow)    (+ConcealedType, timer,       rawKey → Keychain        credentials=nil, index
     no sharingType  [F-04]        changeCount)  [F-05]          (legacy!)  [F-01/02]     reset, clipboard cleared
                                                                                          [race F-03]
```

### 3.3 Entry points / attack surface

| Surface | Present? | Notes |
|---|---|---|
| URL schemes (`CFBundleURLTypes`) | No | Info.plist is generated in `build-app.sh` and has none |
| Document types / Finder "Open With" | No | No `CFBundleDocumentTypes` |
| AppleScript / Apple Events / sdef | No | |
| XPC, helpers, extensions, App Groups | No | Removed, per the README. Confirmed: one binary, no `Contents/PlugIns` or `XPCServices` |
| Services provider (`NSServices`) | No | However, selectable revealed text can be *sent* to Services (Info) |
| Drag & drop | Yes | Key-file row accepts any file URL (`UnlockView.swift:304`) |
| Open/Save panels | Yes | Database, key file, attachment export |
| Global hotkeys / event taps | No | Only a global **mouse** monitor to close the popover (`AppDelegate.swift:300`) |
| Distributed notifications | Yes | Listens for `com.apple.screenIsLocked`. Any process can post it, but it only causes a lock (harmless) |
| Environment / defaults | Yes | `FLEEN_DIAG`, `FLEEN_SELFTEST`, defaults key `FleenDiagnostics`. None log secrets (§3.4) |
| File watcher | Yes | `DatabaseFileWatcher` (read-only hashing) |
| Update mechanism | No | No Sparkle or auto-update |
| Network | **No** | No networking APIs in source; `nm -u` of the shipped binary shows no socket, `connect`, `URLSession` or `getaddrinfo` imports; no `network.*` entitlement (sandbox enforces this) |

### 3.4 Logging

`NSLog` appears at `VaultSession.swift:223`, `:291` and `VaultView.swift:853` (entry **titles**, only with `FLEEN_DIAG=1` set in the environment), plus `AppDelegate.swift:137,144`. `Diagnostics.log` writes only launch, activation and biometric-flow events. The existing log, `~/Library/Containers/com.fleen.Fleen/Data/Library/Logs/Fleen-diagnostics.log` (228 lines, enabled by `FleenDiagnostics=true` in your prefs), contains no titles, URLs or secrets. **Verified.** No `os_log`/`Logger` use, and no `print` in the app (only in `fleen-cli`).

---

## 4. Findings

Severity: Critical / High / Medium / Low / Info. Status: **verified** or **suspected**.

---

### F-01 · High · verified — Touch ID key is not biometrically bound; the macOS login password unlocks the vault

**Where**
- `Scripts/build-app.sh:157,164`: signs with `Resources/Fleen.entitlements`, which lacks `com.apple.application-identifier` / `com.apple.developer.team-identifier`.
- `Sources/FleenKit/Keychain.swift:45-57`: the probe falls back on `errSecMissingEntitlement`.
- `Sources/FleenKit/BiometricUnlock.swift:174-184`: stores the key with **no access control**.
- `BiometricUnlock.swift:150`: `[.biometryCurrentSet, .or, .devicePasscode]`.

**Description.** The data-protection keychain needs `com.apple.application-identifier` *in the code signature*. Xcode copies it from the provisioning profile; `build-app.sh` embeds the profile but never merges its entitlements. So the "signed, sandboxed" release still fails the probe, and `availableProtectionLevel` becomes `.enforcedByApp`. The composite key, which with the `.kdbx` file opens the vault, is then written to the **legacy login keychain** with a plain app ACL and no biometric requirement. The Touch ID prompt is shown by Fleen itself, not enforced by the OS. Separately, even a correctly entitled build uses `.or .devicePasscode`, so the login password always satisfies the gate. This also likely defeats the claim that enrolling a new fingerprint invalidates the item (suspected; that part was not tested).

**Proof** (metadata and ACL only; the secret was not read):
```
$ codesign -d --entitlements - /Applications/Fleen.app
  com.apple.security.app-sandbox = true
  com.apple.security.files.bookmarks.app-scope = true
  com.apple.security.files.user-selected.read-only = true        ← no application-identifier
$ security find-generic-password -s com.fleen.Fleen.vault-key
keychain: "/Users/stevic/Library/Keychains/login.keychain-db"     ← legacy keychain
$ security dump-keychain -a …   (item com.fleen.Fleen.vault-key)
  entry 0: decrypt … don't-require-password
     applications: /Applications/Fleen.app  (DR: identifier "com.fleen.Fleen" and … Apple Development …)
  entry 3: partition_id  teamid:94WY2HW4JW
```

**Attack scenario.** A colleague or partner knows or has watched you type your Mac password. That password is typed far more often, and in front of more people, than the vault password. At your Mac (or any session they can log in to), they run `security find-generic-password -s com.fleen.Fleen.vault-key -w`, enter the login password at the keychain prompt, and copy the `.kdbx` from Dropbox/iCloud. They now have offline access to every password until you change the master password. Same-user malware can do the same if you approve one keychain dialog.

**Fix**
1. Merge the profile's identifiers into the signing entitlements:
   ```bash
   # build-app.sh, after `cp Resources/Fleen.entitlements build/entitlements/app.plist`
   P=build/entitlements/profile.plist
   for k in com.apple.application-identifier com.apple.developer.team-identifier; do
     v=$(plutil -extract "Entitlements.${k//./\\.}" raw -o - "$P")
     /usr/libexec/PlistBuddy -c "Add :$k string $v" build/entitlements/app.plist
   done
   ```
   Then confirm Settings shows "Enforced by the Keychain" and that `security find-generic-password -s com.fleen.Fleen.vault-key` returns **nothing**, because data-protection items are not visible to the `security` tool.
2. Do not silently store an unprotected key in release builds:
   ```swift
   case .enforcedByApp:
       #if !DEBUG
       throw Failure.notAvailable("Touch ID needs a properly signed build.")
       #endif
   ```
3. Make the login-password fallback an explicit, labelled opt-in, or drop it: `[.biometryCurrentSet]` only. Then document honestly that "Touch ID unlock ⇒ vault security ≥ biometric + device, not the master password".
4. After fixing, delete the existing legacy item (see F-02).

---

### F-02 · Medium · verified — Turning Touch ID off leaves the key in the keychain

**Where:** `Sources/Fleen/SettingsView.swift:130-132` (only sets `preferences.biometricUnlockEnabled`); `BiometricUnlock.remove(account:)` is never called from the UI. Switching databases doesn't remove old keys either.

**Description / scenario.** A user who disables Touch ID because they no longer trust the setup still has the composite key in the keychain, extractable as in F-01, indefinitely. The Settings text "Stores the derived key" is also inaccurate: it is the composite (pre-KDF) key.

**Proof:** the code path above; `grep -rn "remove(account" Sources/Fleen` → no matches.

**Fix**
```swift
.onChange(of: biometricEnabled) { _, value in
    preferences.biometricUnlockEnabled = value
    if !value, let account = session.biometricAccount { BiometricUnlock.remove(account: account) }
}
```
Add a "Forget saved Touch ID keys" button that deletes every `com.fleen.Fleen.vault-key` item.

---

### F-03 · Medium · verified — A lock (or database switch) during unlock is undone when the KDF finishes

**Where:**
- `Sources/FleenKit/VaultSession.swift:253-297` (`performUnlock`) and `:343-362` (`reload`): `adopt(...)` runs unconditionally after `await`.
- `Sources/Fleen/AppDelegate.swift:88`: auto-lock ignores events while `.unlocking`.

**Description.** `lock()` and `select()` don't cancel an in-flight unlock. When `Task.detached` returns, `adopt` sets `state = .unlocked` and installs the database regardless. The screen-lock and sleep handlers also return early unless the state is already `.unlocked`.

**Proof** (`audit/Harness`, `race`):
```
during KDF: state=unlocking
after lock(.screenLocked): state=locked database=false
after KDF finished: state=unlocked database loaded=true url=slow.kdbx entries=["SLOW-DB-ENTRY"]

after select(other): state=locked url=other.kdbx
after KDF finished: state=unlocked database loaded=true url=other.kdbx entries=["SLOW-DB-ENTRY"]
```

**Scenarios.** (1) You start a Touch ID unlock, or have a slow Argon2 database, then shut the lid or press ⌃⌘Q. The vault finishes decrypting behind the lock screen, and stays unlocked until the idle timer next fires. (2) ⌘L during "Unlocking…" does nothing. (3) Switching databases mid-unlock shows database B's name with A's contents. A's credentials are then kept against B's URL, and "Remember with Touch ID" would file A's key under B's keychain account.

**Fix**
```swift
private var unlockGeneration = 0
public func lock(reason: …) { unlockGeneration &+= 1; … }

private func performUnlock(url: URL, key: CompositeKey, enrollBiometrics: Bool) async {
    let generation = unlockGeneration
    state = .unlocking
    let opened = await Task.detached { … }.value
    guard generation == unlockGeneration, url == databaseURL else { return }   // superseded
    …
}
```
Apply the same pattern to `reload()`. In `AppDelegate`, lock on `.unlocking` too: `guard self.session.state.isUnlocked || self.session.state.isBusy`.

---

### F-04 · Medium · verified (static) — Revealed passwords and TOTP codes are visible to screenshots, recording and screen sharing

**Where:** no `sharingType` anywhere (`grep -rn sharingType Sources` → none). Affects the popover window (`AppDelegate.swift:271`) and the Settings window (`SettingsView.swift:29`).

**Description / scenario.** During a Zoom/Meet/Teams share, or with any screen-recording-permitted app (including malware that has obtained the Screen Recording permission), revealed passwords, card numbers and the always-visible TOTP code are captured. Password-manager popovers commonly appear on top of a shared screen.

**Fix**
```swift
popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
popover.contentViewController?.view.window?.sharingType = .none
```
Do the same in `SettingsWindowController`. Caveat (suspected): on macOS 15+, some ScreenCaptureKit capture paths have been reported to ignore `.none`. Verify with QuickTime screen recording after the change.

---

### F-05 · Medium · verified (static) / runtime partly verified — Copied secrets reach other devices through Universal Clipboard; no Transient marker

**Where:** `Sources/FleenKit/ClipboardService.swift:49-54`. It uses `clearContents()` + `setString`, with no `prepareForNewContents(with: .currentHostOnly)` and no `org.nspasteboard.TransientType`.

**Proof.** Runtime check on a private pasteboard (`audit … clipboard`): the concealed marker is present, auto-clear works, and the `changeCount` guard holds:
```
after copy: types=["public.utf8-plain-text","NSStringPboardType","org.nspasteboard.ConcealedType"]
3.2s later (timeout 2s): value=nil (cleared)
user overwrote it, 3.2s later: value=user copied this
```
Handoff itself was not tested; that is platform behaviour for the general pasteboard without `.currentHostOnly`.

**Scenario.** With Handoff on, a copied password lands on the user's iPhone/iPad clipboard. Fleen's 10–30 s clear runs only on the Mac, and iOS apps can read the clipboard.

**Fix**
```swift
pasteboard.prepareForNewContents(with: .currentHostOnly)   // replaces clearContents()
pasteboard.setString(value, forType: .string)
pasteboard.setData(Data(), forType: Self.concealedType)
pasteboard.setData(Data(), forType: .init("org.nspasteboard.TransientType"))
ownedChangeCount = pasteboard.changeCount
```

---

### F-06 · Medium · verified — The decrypted XML (notes, usernames, URLs, titles) survives `lock()` in libxml2 memory

**Where:** `Sources/KdbxCore/Format/KdbxXmlReader.swift:47` (`XMLParser(data:)`). The README claims the decrypted payload "is zeroed".

**Description.** Fleen correctly wipes its own payload buffer. But `XMLParser`/libxml2 copies its input into internal buffers that Fleen cannot reach. In the session test that copy is a **live 28 KiB block after `lock()`**; in the engine-only test it is unzeroed memory outside any live block. It holds every non-protected field in plaintext. Protected values appear only as inner-stream ciphertext, and the inner stream key is *not* in this copy.

**Proof** (`memscan-engine` / `memscan-session`, canary `FleenXmlCommentCanary-77123` sits in an XML comment and never becomes a Swift String):
```
── session: after lock() and clipboard clear
  FOUND  notes (plain field) [utf8] ×1  MALLOC_SMALL@0x4c4020193 [LIVE block +0x4193 of 28672B]
  FOUND  xml comment (never a String) [utf8] ×1  MALLOC_SMALL@0x4c4020049 [LIVE block +0x4049 of 28672B]
  (master password, entry password, all six derived keys: clean)
$ fleen-audit xmlprobe whole   # XMLParser alone, every Swift-side buffer wiped
  FOUND  xml input canary ×1  MALLOC_SMALL@0x6bc000021 [not in a live malloc block]
```
Reproduced with and without gzip and with both ciphers, so this is not a gzip artefact.

**Scenario.** A memory capture after lock (core dump, hibernation or swap image, or a root-level attacker) yields every note and username. Notes often hold recovery codes and PINs.

**Fix** (both options untested; re-run `audit/run_all.sh` to confirm):
- Robust: replace `XMLParser` with a small in-place KDBX tokenizer over the `Data` Fleen already owns and wipes. The KDBX XML subset is simple: no DTDs needed, and entities limited to the five predefined ones plus numeric references.
- Lower-effort, partial: install zeroing libxml2 allocators once at startup (`xmlMemSetup` with a `free` that does `memset_s(p, malloc_size(p), …)` first). This does not help for buffers libxml2 keeps alive, which the 28 KiB live block suggests exist.
- Correct the README claim in the meantime.

---

### F-07 · Low · verified — Crafted TOTP entry (`digits=10`) crashes the app; a copied password then stays on the clipboard

**Where:** `Sources/KdbxCore/Model/TOTP.swift:72`. `UInt32(pow(10, Double(digits)))` traps when `digits == 10`, which the clamp at `:33` allows.

**Proof:**
```
$ fleen-audit totp 9   → code=205558683  exit=0
$ fleen-audit totp 10  → (no code)       exit=133   # SIGTRAP
```

**Scenario.** A shared vault contains an entry with `otpauth://…&digits=10` or `TOTP Settings = 30;10`. Opening it, or ⌥⌘T or ⌘-click on it, kills Fleen. Because the clear timer dies with the process and `applicationWillTerminate` doesn't run on a crash, a password copied just before **remains on the clipboard indefinitely**. It crashes again every time the entry is opened.

**Fix:** `let modulus = UInt64(pow(10, Double(digits)))` and `String(format: "%0\(digits)llu", UInt64(binary) % modulus)`. Or clamp `digits` to 6…9.

---

### F-08 · Low · verified — Deeply nested groups or history crash the app (stack overflow)

**Where:** recursive walks `Group.allEntries()` (`Entry.swift:255`), `SearchIndex.walk` (`SearchIndex.swift:87`), `Database.group/path(...)`, and the recursive release of nested `Entry.history` (`KdbxXmlReader.swift:148` accepts `<History>` inside history entries).

**Proof:**
```
depth 10000 groups → OK      depth 20000 / 200000 groups → exit 139 (SIGSEGV) in allEntries/index
history nesting 50000:
  stage 1 open OK · stage 2 allEntries OK · stage 3 SearchIndex OK · stage 4 releasing Database → exit 139
```

**Scenario.** A hostile shared vault crashes Fleen on unlock (groups) or on **lock/quit** (history), repeatably.

**Fix:** reject unreasonable structure in the parser.
```swift
case "Group":   groupStack.append(Group()); if groupStack.count > 512 { fail("groups nested too deeply") }
case "History": inHistory += 1;           if inHistory > 1 { fail("nested history") }
```

---

### F-09 · Low · verified (static) — "Open in browser" opens any URL scheme from the entry

**Where:** `Sources/Fleen/EntryDetailView.swift:291-294`. Any URL with a scheme goes to `NSWorkspace.shared.open`.

**Scenario.** A shared or tampered vault entry has its URL set to `file:///Users/…/Downloads/payload.app`, an `smb://` share, or another app's custom URL scheme. The button labelled "Open in browser" launches an app, mounts a remote share, or triggers that other app's URL handler. Not executed here because it would launch apps; this is documented `NSWorkspace` behaviour.

**Fix:**
```swift
guard let url = URL(string: entry.url),
      let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme) else { return }
```

---

### F-10 · Low · verified — After a Touch ID unlock (Argon2), Reload always fails as "Incorrect password"

**Where:** `CompositeKey.rawKey()` returns the shared `finishedKey` instance (`CompositeKey.swift:118`). `Argon2.hash` passes `ARGON2_FLAG_CLEAR_PASSWORD` (`Argon2.swift:116`), which zeroes it. `VaultSession` keeps that zeroed key for `reload()`.

**Proof:**
```
open #1: OK          stored composite key all-zero after open #1: true
open #2: THREW invalidCredentials
(AES-KDF control: both opens OK, key intact)
```
Fails closed: no leak, but the external-change "Reload" and ⌘R are broken for Touch ID users.

**Fix:** have `rawKey()` return a copy, e.g. a `SecureBytes.copy()` helper that allocates and `copyMemory`s, so the KDF can destroy its input.

---

### F-11 · Low · verified (static) — No lock on fast user switching

**Where:** `Sources/FleenKit/AutoLockController.swift:66-83`. It handles sleep and `com.apple.screenIsLocked` only.

**Scenario.** You switch to another user account without the screen locking. The vault stays unlocked in your background session until the idle timeout. Default 5 minutes, sampled every 15 s.

**Fix:** also observe `NSWorkspace.sessionDidResignActiveNotification`; optionally `com.apple.screensaver.didstart`.

---

### F-12 · Low · verified — Hostile KDF parameters can pin ~1 GiB RAM and ~28 s per unlock attempt

**Where:** limits in `Argon2.swift:19-26` (1 GiB, 1000 iterations, 64 lanes, product ≤ 64 Mi KiB·iter). The header-level limits in `KdbxHeader.swift:230-238` are looser (4 GiB, 2²⁴), but `Argon2.swift` is the binding one.

**Proof:**
```
argon2-max-allowed-p1    THREW invalidCredentials time=28.26s maxRSS=1033MiB
argon2-max-allowed-p64   THREW invalidCredentials time=5.09s  maxRSS=1035MiB
aeskdf-max-allowed       THREW invalidCredentials time=1.59s
argon2-over-memory / 4GiB / huge-iter / p0 / aeskdf-2^64  → rejected instantly
```
Bounded, so this is by design. Optionally show the KDF cost from `info` when it exceeds ~5 s, before running it, and allow cancelling.

---

### F-13 · Low · suspected — mlock pinning is not reliable

**Where:** `SecureBytes.swift:28-38, 70`. Allocations are 16-byte aligned (the comment says "page-aligned"), so many `SecureBytes` share a page. `munlock` in one instance's `deinit` unpins the page for every other live instance on it, because mlock is not reference-counted. Fix: allocate page-aligned, page-sized slabs, or keep a page-refcount table.

### F-14 · Info · verified — Accessibility and Services exposure of revealed values

Revealed values are ordinary `Text` with `.textSelection(.enabled)` (`EntryDetailView.swift:371`). Any app with Accessibility permission can read them via AX. The TOTP code is in an AX label (`TOTPView.swift:60`). Selected text can be sent to Services or Writing Tools. This is inherent to showing text; mitigate by keeping reveal short-lived, e.g. auto-hide after 15–30 s. Also: the 23 Sep diagnostics log shows an older build had `accessibility trusted = true`. Remove Fleen from **System Settings › Privacy & Security › Accessibility** if it is still listed.

### F-15 · Info · verified — Key-material temporaries are not wiped, but this OS scrubs them anyway

Unwiped copies:
- `Data($0)` / `Array(hasher.finalize())` temporaries of derived keys: `KeySchedule.swift:59-76`, `CompositeKey.swift:35,121-123`, `AesKdf.swift:56-57`, `HmacBlockStream.swift:36,61`, `KdbxInnerHeader.swift:94-108`.
- `ChaCha20`/`Salsa20` `state` arrays holding keys (`ChaCha20.swift:17`, `Salsa20.swift:13`).
- The `var input = input` COW copy in `Gzip.swift:26,39`.
- TOTP secrets as `[UInt8]`/`String`.

On macOS 26.6 libmalloc zeroes freed blocks: `zerofree` probe clean at 32 B to 400 KB, and **all six derived keys plus both password canaries were absent after release/lock**. So this is defence-in-depth only, and only on this OS. The `Hashers.swift` wrappers exist to avoid such copies but are unused at most of these sites; use them, and wipe the cipher state in a `wipe()` method.

### F-16 · Info — Miscellaneous

- **Attachments.** Plain `Data`, never zeroed (already documented). Not part of the canary tests.
- **Attachment export (suspected).** Likely fails in the sandboxed build, because the sandbox has only `files.user-selected.read-only` and `NSSavePanel` writes need `read-write`.
- **Key file input.** Read whole into memory with no size cap (`CompositeKey.swift:51`). Pointing it at a multi-GB file exhausts memory; KeePass streams the hash.
- **CLI.** `fleen-cli` uses `getpass()`, whose static buffer is not cleared. CLI only.
- **Release identity.** The installed release is signed with an *Apple Development* certificate and not notarised; `spctl -a` → `rejected` (expected; noted in the README).
- **PII in the repo.** `Scripts/build-signed.sh:15` and `notarize.sh` contain your Apple ID email and team IDs. Not secret, but in the repo.
- **README is out of date.** "159 tests" (actual: 235, all passing). "decrypted payload … is zeroed" (see F-06). The Touch ID "Enforced by the Keychain" description of signed builds (see F-01).

---

## 5. Not verified (needs the GUI, or your machine)

These need the real app driven by hand. I did not automate your GUI or touch your database.

1. **Master password residue in AppKit/SwiftUI** (`SecureField` → `NSSecureTextField` field editor, undo buffers). Proposed check: re-sign a copy of `build/Fleen.app` with `get-task-allow`, unlock `audit/out/canary-aes-aeskdf-gz.kdbx` with `FleenAuditCanary-91827`, reveal and copy the entry, lock, then `lldb -p <pid> -o "process save-core /tmp/fleen.core"` and search the core for the canaries in UTF-8/UTF-16. Requires Developer Mode or an admin prompt for lldb.
2. **Secure Event Input during password entry.** Expected on with `NSSecureTextField`. Check with `ioreg -l -w 0 | grep SecureInput` while the field has focus.
3. **Whether the popover's `@State detailEntry` keeps an `Entry` (and its `SecureBytes`) alive after an auto-lock while the popover is closed.** SwiftUI may not re-render a detached hosting view. The harness shows `VaultSession` itself drops everything.
4. **Universal Clipboard propagation** (F-05) and the **`sharingType` caveat** on macOS 26 (F-04).

---

## 6. Done correctly (brief)

- **Integrity.** Header SHA-256 is checked before the KDF. The header HMAC is checked before decryption. Every block HMAC is checked before its bytes are used. All comparisons are constant-time. With CBC only decrypted after the MAC, there is no padding oracle.
- **Robust parsing.** Every read is bounds-checked. Of 40 hostile files, the only crashes were F-07/F-08: all 12 truncations, max lengths, a 1 GiB gzip bomb (capped at 512 MiB), billion-laughs (rejected by libxml2) and XXE (not resolved) were handled cleanly.
- **Memory.** Protected values are decrypted straight into `SecureBytes`. The search index never contains secrets. After `lock()`, the master password, entry passwords and all six derived keys are gone (verified).
- **Clipboard.** Concealed marker, auto-clear, a `changeCount`-safe clear, and a clear on lock and quit (verified).
- **Attack surface.** No network, URL schemes, IPC, writes or auto-update. Sandboxed, read-only file access.
- **Binary hardening.** Hardened runtime with no `get-task-allow`, `disable-library-validation`, `allow-dyld-environment-variables`, `allow-jit` or `allow-unsigned-executable-memory`. `DYLD_INSERT_LIBRARIES` injection is blocked (verified, with an unhardened control that *was* injected).
- **Keychain flags.** `WhenUnlockedThisDeviceOnly` and non-synchronizable keychain items. Auto-lock on idle, sleep and screen lock by default.
- **On-disk traces.** None: no saved application state, caches or temp files (verified in the container).

---

## 7. Prioritised fix list

| # | Fix | Finding | Effort |
|---|---|---|---|
| 1 | Merge `application-identifier`/`team-identifier` into signing; refuse unprotected key storage in release; reconsider `.or .devicePasscode`; delete the existing legacy keychain item | F-01 | S |
| 2 | Delete the stored key when Touch ID is turned off; add "Forget saved keys" | F-02 | XS |
| 3 | Generation token for unlock/reload; auto-lock also while unlocking | F-03 | S |
| 4 | `sharingType = .none` on popover and Settings windows | F-04 | XS |
| 5 | `prepareForNewContents(with: .currentHostOnly)` + TransientType | F-05 | XS |
| 6 | TOTP modulus in `UInt64` | F-07 | XS |
| 7 | Nesting limits in `KdbxXmlReader` | F-08 | XS |
| 8 | Restrict "Open in browser" to http/https | F-09 | XS |
| 9 | `rawKey()` returns a copy | F-10 | XS |
| 10 | Lock on `sessionDidResignActive` | F-11 | XS |
| 11 | Replace `XMLParser` (or zeroing libxml2 allocators) + correct README | F-06 | M |
| 12 | Wipe cipher state, use `Hashers` wrappers, page-aware mlock | F-13, F-15 | S |
| 13 | Auto-hide revealed fields; README corrections; key-file size cap | F-14, F-16 | S |

---

## Appendix — reproducing

```bash
cd audit
python3 -m venv .venv && .venv/bin/pip install pykeepass==4.1.1.post1
./run_all.sh            # builds the harness, generates DBs, runs every check above
```
All test databases use throwaway passwords (`FleenAuditCanary-91827`, `pw`, `other`).
