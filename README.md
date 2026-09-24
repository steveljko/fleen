# Fleen

A native macOS KeePass (`.kdbx` v4) **reader**: a menu bar vault browser with search,
TOTP and concealed clipboard copy.

**Status: read-only viewer, complete and tested. No autofill, no auto-type — see
[why](#no-autofill-and-no-auto-type).**

---

## Scope, as agreed

| Decision | Choice |
|---|---|
| KDBX engine | Written here, on CryptoKit + the PHC reference Argon2 |
| Format | KDBX4 only — **KDBX3 is out of scope** and refused with a clear error |
| Ciphers | AES-256-CBC, ChaCha20 |
| KDFs | Argon2d, Argon2id, AES-KDF |
| Attachments | Supported |
| YubiKey | Out of scope for this build |
| Access | **Read only** — see below |
| Filling credentials | **Out of scope** — copy to clipboard instead |

## Project structure

```
fleen/
├── Package.swift               SwiftPM: engine, app logic, app, CLI, tests
├── Scripts/build-app.sh        Assembles + signs Fleen.app
├── Resources/                  Info.plist inputs and entitlements
├── Sources/
│   ├── CArgon2/                Vendored PHC reference Argon2 (unmodified)
│   ├── KdbxCore/               ── Phase 1 ── the format engine, no UI
│   │   ├── Crypto/             SecureBytes, Argon2, AES-KDF, AES-CBC, ChaCha20, Salsa20
│   │   ├── Format/             Header, VariantDictionary, HMAC stream, XML, gzip
│   │   └── Model/              Database, Group, Entry, FieldValue, attachments
│   ├── FleenKit/               ── Phase 2 ── app logic, still no UI
│   │   ├── VaultSession        Lock/unlock state machine, the single source of truth
│   │   ├── SearchIndex         Fast search over non-secret fields only
│   │   ├── ClipboardService    Concealed copy + auto-clear
│   │   ├── AutoLockController  Idle / screen lock / sleep
│   │   ├── DatabaseFileWatcher External-change detection
│   │   ├── BiometricUnlock     Keychain, biometryCurrentSet
│   │   └── KdfProgressEstimator
│   ├── Fleen/                  ── Phase 2 ── the menu bar app (SwiftUI + AppKit)
│   └── fleen-cli/              Headless harness for testing the engine
└── Tests/
    ├── KdbxCoreTests/          79 tests, incl. real fixtures + KeePassXC interop
    └── FleenKitTests/          80 tests
```

Fleen is a **single bundle**: one binary, no extensions, no helper processes. The
target split is about testability, not deployment — `KdbxCore` has no AppKit or UI
dependency and `FleenKit` no UI dependency, so both run headlessly under `swift test`
and from `fleen-cli`.

## Build, run and test

### Run the tests

```bash
swift test                 # 159 tests
```

The KeePassXC interop suite skips itself if the reference app is absent. To include it:

```bash
brew install --cask keepassxc
```

### Build and run the app

```bash
Scripts/build-app.sh       # debug build, ad-hoc signed
open build/Fleen.app
```

Fleen has **no Dock icon** — it is a menu bar utility. Look for a key icon in the
menu bar at the top right, and click it. From there: **Open Database…**, pick a
`.kdbx`, and unlock.

To quit, right-click the menu bar icon and choose Quit, or:

```bash
pkill -f Fleen.app
```

### If nothing seems to happen

Fleen has **no Dock icon and no window** — it is a menu bar app. Launching it
successfully looks exactly like launching it unsuccessfully, so check first:

```bash
Scripts/diagnose.sh
```

That reports whether the bundle exists, whether its signature is valid, and whether
the process is running — and if it is not, relaunches it in the foreground with
diagnostics so you can see where it stops.

On first launch Fleen now opens its popover automatically, so you should see the
window immediately. After that it lives in the menu bar only.

**If it says "running" but you still cannot see it**, the icon is hidden. A crowded
menu bar (or the notch on a MacBook Pro) can push a new status item off-screen
entirely. Either free up menu bar space, or give Fleen a Dock icon instead:

```bash
# Note the path: a sandboxed build reads its preferences from its container, so the
# usual `defaults write com.fleen.Fleen …` writes to a file the app never reads.
PREFS=~/Library/Containers/com.fleen.Fleen/Data/Library/Preferences/com.fleen.Fleen.plist
defaults write "$PREFS" showInDock -bool true
pkill -f Fleen.app && open /Applications/Fleen.app
```

To go back to menu-bar-only — which is the default, and where you want to end up once
you have found the icon:

```bash
defaults delete "$PREFS" showInDock
pkill -f Fleen.app && open /Applications/Fleen.app
```

Check which mode is in force without guessing from the Dock:

```bash
lsappinfo info -only ApplicationType $(lsappinfo find bundleid=com.fleen.Fleen | head -1)
# "UIElement" = menu bar only, "Foreground" = Dock icon
```

For a signed, sandboxed build you need both an identity **and** a provisioning
profile:

```bash
Scripts/build-app.sh --release \
    --sign "Apple Development: you@example.com (XXXXXXXXXX)" \
    --profile ~/Downloads/Fleen_macOS.provisionprofile
```

`--profile` is what swaps in `Resources/Fleen.entitlements` and turns the sandbox on —
signing alone does not, because a sandboxed bundle without a profile will not launch at
all (see [error 163](#launchd-job-spawn-failed-posix-error-163)). Without it,
`Fleen.dev.entitlements` is used with the sandbox off.

`Scripts/build-signed.sh` wraps that command with this machine's identity and profile
path already filled in.

### Try the engine without the UI

`fleen-cli` points the engine at a real database. Passwords are read with `getpass()`,
so they never reach argv or shell history.

```bash
swift build

# Header only — no password needed
.build/debug/fleen-cli info ~/path/to/your.kdbx

# Unlock and list
.build/debug/fleen-cli ls ~/path/to/your.kdbx

# One entry (add --reveal to print the password)
.build/debug/fleen-cli show ~/path/to/your.kdbx "GitHub"

# Where the unlock time goes, and whether Argon2 is threading
.build/debug/fleen-cli bench ~/path/to/your.kdbx
.build/debug/fleen-cli kdf-scaling
```

None of these write to your database — the engine has no code that can.

Options: `--keyfile <path>`, `--no-password`, `--reveal`.

### What to try in the app

- Two folder layouts, chosen in **Settings › General › Display**:
  - **Outline tree** (default) — the whole hierarchy at once, folders expanding in
    place with a disclosure triangle, as KeePassXC's group tree does. Initial
    expansion follows the `IsExpanded` flags your database already stores, so it
    opens the way you left it in KeePassXC.
  - **Drill down** — one folder at a time with large rows; click to go deeper, with
    breadcrumbs back out.
- **Folders and entries appear in the order your database stores them**, not
  alphabetically. That order is your own arrangement in KeePassXC, so re-sorting
  would quietly discard it. Folders still come before entries at each level.
- Start typing and it switches to **flat ranked search across the whole database**,
  ignoring the hierarchy. Clear the search to return to the tree.
- **Expand All / Collapse All** are in the actions menu and on a folder's right-click
  menu.
- **One click opens** — a folder or a record. Anywhere on the row, not just on the
  text.
- **↑/↓** move the selection, **→** opens a folder (or steps into an open one),
  **←** closes it (or jumps to the enclosing folder), **Return** opens a folder or a
  record. All without leaving the search field.
- Opening an entry keeps the same breadcrumb, with the entry as its last crumb —
  click any folder in the trail to jump straight back to it.
- **Esc** backs out one step at a time: close entry → clear search → leave folder →
  lock.
- **Home/End** jump to the first/last row, **Page Up/Down** move a screen at a time.
- **⌥⌘C** copies the password, **⌥⌘B** the username, **⌥⌘U** the address, **⌥⌘T** the
  one-time code. **⌘L** locks, **⌘R** reloads, **⌘,** Settings, **⌘F** focuses search,
  **⌘]**/**⌘[** expand and collapse all folders. Plain **⌘C/⌘V/⌘X/⌘A/⌘Z** stay free for
  ordinary text editing.

> **Option, not Shift, and the reason is worth recording.** These were originally ⇧⌘C
> and friends, and ⇧⌘C never fired. The Edit menu is searched before the Vault menu, and
> its Copy item — key equivalent `"c"`, mask `[.command]` — matches a ⇧⌘C event too,
> swallowing it. Option avoids the collision outright.
>
> Verify any time with `FLEEN_SELFTEST=1`, which synthesises each shortcut, asks the main
> menu to handle it, and reports whether the menu *matched* it and whether a receiver
> *got* it:
>
> ```
> FLEEN_DIAG=1 FLEEN_SELFTEST=1 ./build/Fleen.app/Contents/MacOS/Fleen
> selftest Copy Password: menu matched=YES delivered=YES
> ```
>
> Those two flags separate the failure modes that look identical from the outside:
> `matched=NO` is a key-equivalent problem, `matched=YES delivered=NO` means the action
> fired into nothing.

> Fleen installs a real application menu even though it shows no menu bar. On macOS
> the main menu is what *delivers* keyboard shortcuts — without an Edit menu, ⌘A and
> ⌘C do nothing in a text field, and `.keyboardShortcut` on a SwiftUI `Menu` inside a
> transient popover fires only while that view is in the responder chain, which it
> often is not. Commands that must always work live in `MainMenu.swift`.
- **The popover is one fixed size in every state** — 380 × 400. It used to shrink to fit
  its contents, which meant the window changed height as you entered a folder, searched,
  or opened an entry, moving the controls out from under the pointer on each step. A
  short list now leaves empty space rather than resizing the window. The height is set by
  the unlock screen at its most crowded (wrong-password banner, Touch ID checkbox, key
  file row and footer together), which fits at 400 and clips at 380.
- Copy confirmations and the clipboard countdown appear as a brief toast over the
  list rather than a permanent status bar.
- The popover closes as soon as the app loses focus, so an unlocked vault is never
  left sitting open behind another window.
- Entries with a one-time code show the live TOTP in their details, with a countdown
  ring that turns red in the last five seconds. **⌘T** copies the current code from
  anywhere in the list.
- **Every field you put on an entry is listed**, under no heading, including ones left
  empty (shown as `—`). Two kinds are left out, and neither is user content: the five
  standard fields, which are already shown above in their own right, and the TOTP keys
  (`otp`, `TOTP`, `TOTP Seed`, `TOTP Settings`) — the live one-time code is displayed
  instead, and the `otpauth://` URI and seed that produce it are its ingredients, not
  information. Listing them beside the code would also be a second place to read the
  secret from.
- **Settings › General › Quick copy** makes clicking an entry copy its password instead
  of opening it. Click the same entry again within 15 seconds and it copies the one-time
  code, which is the order a login form asks for them. The toast says so (*"Password
  copied · click again for the code"*) rather than leaving you to discover that the same
  click now means something different. A third click starts over, an entry with no code
  just copies the password again, and clicking a different entry starts that entry's own
  cycle. Return and the right-click menu still open an entry without touching the
  clipboard. Off by default, because it changes what a click does.
- **Card numbers hide as `**** **** **** 1234`** rather than a generic run of dots, and
  read back in the issuer's grouping when revealed (Amex keeps its own 4-6-5). A field
  is treated as a card number when its label says so — `Card Number`, `card_number`,
  `Card No`, `PAN`, `CC Number` — and the value is a plausible 12–19 digit number. A
  vaguer label like `Number` additionally has to pass the Luhn check or match a known
  brand prefix, because masking an account number as a card would hide a field you need
  to read. Copying gives bare digits, since payment forms reject the spaces. There is no
  card layout or card type: a card is an ordinary entry, shown the ordinary way.
- **Settings › Security › Ask on click, before the window opens** makes the menu bar
  icon prompt for Touch ID the instant it is clicked, with no window behind it: touch
  the sensor and the vault opens already unlocked. Cancel and it opens the lock screen
  instead, so a cancelled prompt never leaves the click doing nothing. It needs Touch ID
  unlock switched on and a key enrolled; whenever biometrics cannot serve — nothing
  enrolled, no database chosen, vault already open — the click falls back to opening the
  window normally rather than silently swallowing itself. Unlike the automatic prompt
  below, a click is fresh intent every time, so an earlier cancel does not suppress it.
- With a saved Touch ID key, the lock screen reduces to a single fingerprint button
  and "Touch to Unlock", with the password field one link away rather than on screen.
  The prompt appears a moment after you **open the popover** — never when the vault
  locks, whether that was you choosing Lock Vault or an idle timeout. **Cancelling it is
  remembered**: the button changes to "Tap to Unlock" and Fleen stops asking until you
  tap it, pick a different database, or unlock some other way. Cancelling is an answer,
  and re-asking on every open would be nagging.
  An idle or screen lock happens while you are away from the Mac, and a Touch ID modal
  appearing unbidden at that moment is startling and useless. (`FLEEN_DIAG=1` logs every
  biometric request, so that is checkable rather than assumed.)
- Deleted entries are hidden by default. **Settings › General › Show Recycle Bin**
  lists them, marked with a trash icon.
- Copy a password and watch the status bar count down to the clipboard clearing.
- Edit the database in KeePassXC while Fleen has it open — a reload banner appears.
- Leave it idle past the auto-lock timeout, or lock the screen.

## How Phase 1 is verified

Self-consistency is not evidence — a reader and writer that share a bug agree
perfectly with each other. So correctness rests on three independent legs:

1. **Known-answer vectors** for the primitives written here: ChaCha20 against
   RFC 8439 §2.3.2 and §2.4.2, Salsa20 against eSTREAM Set 6, Argon2d/id against
   vectors from an independent binding.

2. **Real databases from another implementation.** All read fixtures are produced by
   pykeepass, covering every cipher × KDF combination, plus attachments, non-ASCII
   and XML-metacharacter content, empty fields, expiry, TOTP in both storage forms,
   and all three key file formats.

3. **The reference application agrees with what we read.** `ReaderInteropTests` runs
   `keepassxc-cli export -f csv` on each fixture — KeePassXC decrypting and parsing
   the file with its own code — and compares every username, password, URL and note
   against ours, across all six cipher/KDF combinations. For that to pass, the
   header, KDF parameters, HMAC framing, cipher and inner stream all have to be right.

> **Note on `keepassxc-cli`:** its `db-create` only emits KDBX **3.1**, so it cannot
> supply v4 fixtures — pykeepass does that. Its 3.1 output is kept as the fixture
> proving we reject v3 cleanly.

## Security notes

**All processing is local.** `KdbxCore` contains no `URLSession`, socket, or any
other network-capable symbol — verified by grep, and worth re-checking in review.
The only I/O is the database file the caller names.

**Key material.** Everything derived from the master password lives in
`SecureBytes`, a heap buffer zeroed with `memset_s` on deinit. `Data` and `[UInt8]`
are deliberately avoided for keys because both can reallocate behind your back,
stranding copies of key material on the heap.

**Where third-party code was preferred over writing our own**, per PLAN.md item 3:

| Primitive | Source | Why |
|---|---|---|
| Argon2d/id | PHC reference C, vendored unmodified | Never hand-roll a memory-hard KDF |
| SHA-256/512, HMAC | CryptoKit | Apple-maintained |
| AES-256-CBC, AES-ECB | CommonCrypto | CryptoKit has no CBC mode |
| gzip | system zlib | — |
| CSPRNG | `SecRandomCopyBytes` | — |
| **ChaCha20, Salsa20** | **written here** | **see below** |

ChaCha20 and Salsa20 are the only primitives implemented in this repo. CryptoKit
ships only `ChaChaPoly` (the AEAD), and KDBX needs the bare keystream, both as an
outer cipher and for protected field values — an AEAD cannot be coerced into
producing one. The alternative was a third-party dependency for ~40 lines of fixed
rotations with no secret-dependent branches or table lookups. **These two files are
the place to look hardest in a security review.**

### Memory hygiene, and where plaintext genuinely lives

Audited deliberately, because "keys are in `SecureBytes`" is not the whole answer.

**What is protected.** Every protected field value (passwords, TOTP seeds, protected
custom fields) is decrypted straight from the inner stream into `SecureBytes` and never
becomes a `String` unless something calls `reveal()`. `lock()` drops the database, the
credentials and the index in one operation, so every `SecureBytes` deinitialises and
`memset_s` runs. The XML parser is SAX rather than DOM specifically so no parallel tree
of secrets exists.

**What the decrypted payload buffer does *not* contain.** Protected values are stored in
the XML as base64 of inner-stream *ciphertext*, so the decrypted payload holds no
plaintext passwords — it holds titles, usernames, URLs and notes. That is still worth
zeroing (notes hold secrets in practice), and it is zeroed.

**The copy-on-write trap, found by auditing rather than by reasoning.** `Data` is
copy-on-write, and `SecureBytes.wipe` writes through `withUnsafeMutableBytes`. If any
other `Data` still shares the buffer, that call **copies first and zeroes the copy** —
the original plaintext stays in memory at an address nothing can reach again. Nothing
about the call site looks wrong. Two ways it bit here:

1. `ByteReader` holds a `Data` and `readRest()` returns a *slice* of it, so both shared
   the payload buffer.
2. More subtly, `XMLParser` **retains the `Data` it is given** and is autoreleased, so
   it outlived an ordinary Swift scope and kept the buffer shared past the wipe. A plain
   `do { }` block does not fix this; an explicit `autoreleasepool` does.

`SecureBytes.wipe` now verifies this instead of trusting it: in debug builds it compares
the buffer address across the write and traps if it moved, naming the offending call
site. `MemoryHygieneTests` demonstrates the failure mode directly and opens every fixture
with the check armed.

**Decompression no longer leaves a trail.** `Gzip.decompress` grew its output with
`append`, and every reallocation copies the plaintext to a new block and frees the old
one *without zeroing* — scattering stale partial copies of the decrypted database across
the heap. It now reserves up front from gzip's ISIZE trailer (clamped, since that field
is attacker-controlled) and zeroes its 64 KiB scratch chunk on exit.

**Known gaps, stated rather than glossed:**

| Gap | Consequence |
|---|---|
| `reveal()` returns a `String` | Copying a password, or tapping reveal, puts it in a heap `String` that cannot be zeroed. Inherent to `String` and `NSPasteboard`; the call sites are deliberately few and named |
| The unlock field is a SwiftUI `SecureField` | Its `String` is not ours to zero. It is cleared as soon as it is consumed — mitigation, not a guarantee |
| Attachments are plain `Data` | Never zeroed, and an attachment may be a key file or recovery codes |
| Nothing is `mlock`ed | Secrets can reach swap. macOS encrypts swap by default on Apple Silicon and with FileVault, which reduces but does not remove this |
| No release-build check | The COW verification is `#if DEBUG`; release builds rely on the structure being right and the tests having proven it |

**Integrity.** Header tampering is caught by its SHA-256 and by an HMAC under the
derived key; payload tampering by a per-block HMAC-SHA256 whose key is derived from
the block index. Every block is authenticated *before* its bytes reach the cipher.
All MAC and hash comparisons are constant-time.

**Untrusted input.** A `.kdbx` file may be attacker-controlled — PLAN.md's threat
model assumes it syncs through a third party. Every read is bounds-checked; Argon2
cost parameters are range-checked before allocating; gzip output is capped against
decompression bombs; XML external entity resolution is off.

**Nothing is written.** There is no encryption path, no serialiser and no save code
in the engine — see [Read-only, by construction](#read-only-by-construction). The
attack surface of a writer is absent rather than guarded.

## Phase 2: the app shell

**Menu bar app.** `NSStatusItem` with no Dock icon (`LSUIElement`). The popover's
SwiftUI hierarchy is built once at launch and reused, so the first click is as fast
as the tenth — building it lazily is the usual cause of a first-open stutter.

**Unlock.** A full-bleed lock screen: the database name, one large password field,
and a full-width Unlock button. Optional key file (choose or drag-and-drop) and
Touch ID sit below it. Cipher and KDF are not shown here — that detail belongs in
`fleen-cli info`, not in front of someone trying to get at their passwords.

**Progress that doesn't lie — quietly.** Argon2 reports nothing while it runs, so
the bar is an estimate calibrated against this Mac's measured throughput. It eases
toward 95% and stops there until the KDF genuinely finishes, so it can never claim
"done" and then sit there; tests assert it never reaches 1 on the estimate alone.
The screen shows only that bar and the word "Unlocking…" — no duration, no algorithm
name. The honesty is in how the bar behaves, not in making the user read about key
derivation.

**Touch ID stores the composite key, never the password.** The Keychain item is
protected with `.biometryCurrentSet`, so enrolling a new fingerprint invalidates it.
Unlocking with biometrics still runs the full KDF — Touch ID replaces *typing*, not
key derivation, so enabling it doesn't make the vault cheaper to attack offline. The
stored key derives byte-identically to the typed password, which
`BiometricKeyTests` pins.

> **Touch ID in an unsigned build.** macOS has two keychains. The modern
> data-protection keychain needs an `application-identifier` entitlement, which only a
> build signed with a real team has — asking for it without one fails every call with
> `errSecMissingEntitlement`, surfacing as *"a required entitlement isn't present"*.
> `Keychain.swift` therefore tries the data-protection keychain and falls back to the
> legacy one, which has no such requirement. **But the legacy keychain accepts
> `kSecAttrAccessControl` and can then ignore it**, leaving a key that reads back with
> no prompt — a Touch ID button that opens the vault instantly while protecting
> nothing. So every stored key is probed after writing, with interaction forbidden: an
> item that hands over its data unprompted is deleted and refused. Touch ID is
> disabled with an explanation rather than faked. `BiometricEnforcementTests` writes an
> unprotected key deliberately and asserts it is caught.
>
> A remaining caveat: an ad-hoc signature gives the app a new identity on every
> rebuild, which can invalidate its Keychain items. Fleen checks whether enrolment
> actually stuck and says so rather than failing silently. Sign the build to keep it
> across rebuilds.

**Auto-lock** on idle (system-wide input idleness, needing no Accessibility
permission), screen lock, and sleep — each switchable, and the lock screen explains
which one fired.

**Clipboard.** Copies are marked `org.nspasteboard.ConcealedType` so clipboard
managers skip them, and auto-clear on a timer that checks `changeCount` first, so it
only ever removes its own item.

**Search.** Pre-folded UTF-8 byte haystacks built once at unlock; per-keystroke cost
is a scan, with no debounce. Exact > prefix > substring > subsequence, weighted by
field. **Passwords are never indexed** — a search index is a plaintext copy of
whatever it holds. Tested at 10,000 entries.

**File watching.** Handles the atomic-replace case (KeePassXC and every sync client
write-then-rename, which makes a naive watcher go deaf) by re-arming on the path, and
ignores spurious events by content hash. When the file genuinely changes, Fleen
offers to reload — it has no writes of its own to reconcile.

**TOTP.** Live one-time codes (RFC 6238), verified against all three of the RFC's
vector sets — SHA-1, SHA-256 and SHA-512 — and cross-checked against `pyotp` on a
real database. Reads all three shapes KeePass stores TOTP in: an `otpauth://` URI in
the `otp` field, the same URI under `TOTP`, and KeePassXC's older `TOTP Seed` plus
`TOTP Settings` pair. Base32 decoding tolerates lowercase, padding, spaces and
dashes, because that is how secrets arrive when pasted from a website. Counter-based
HOTP URIs are refused rather than rendered as a plausible-looking code that never
works. Codes are copied as secrets — concealed and auto-cleared like a password.

**One canonical copy of the decrypted data.** `VaultSession.database` plus a
secret-free index. No parallel UI model duplicating passwords, so locking drops
everything in one operation.

## No autofill, and no auto-type

Both were built, and both were removed. Every line is gone: the
`ASCredentialProviderExtension` target, the encrypted App Group snapshot, the
credential identity store, the global hotkey, the window matcher, the keyboard-layout
inverter and the `CGEvent` keystroke synthesiser. What remains is a viewer, and
credentials leave it only through the concealed clipboard (**⌥⌘C** / **⌥⌘B**).

**The technical reason they cannot coexist**, established by direct measurement rather
than from the documentation:

| Feature | Needs | Conflict |
|---|---|---|
| System AutoFill | App Sandbox **on** + App Group + a provisioning profile | The sandbox is mandatory for an appex |
| Global auto-type | Cross-process Accessibility + `CGEvent` posting | **The sandbox blocks it outright** |

A sandboxed build asking for another app's focused window gets `kAXErrorCannotComplete`;
the same build unsandboxed reads the window fine. So one bundle cannot do both, and the
choice was between two half-features. Beyond that, each had an unresolved problem of its
own:

- **AutoFill never served a live request.** Chrome does not invoke
  `ASCredentialProviderExtension` at all, and the Safari path was never confirmed
  working end to end.
- **Auto-type required a permanent, unsandboxed Accessibility grant** — the ability to
  read any window and synthesise keystrokes anywhere — in exchange for saving a
  keystroke over ⌥⌘C. For a password vault that is a poor trade.

**The security upside is concrete.** With both gone, Fleen needs no App Group (no
plaintext-adjacent snapshot at rest while unlocked), no shared Keychain group, no
Accessibility permission, and no second process that can read the vault. Decrypted
secrets exist in exactly one process, only while it is unlocked. The absences are
enforced by the sandbox, not by our restraint — see [Entitlements](#entitlements).

If you had Fleen in **System Settings › Privacy & Security › Accessibility**, remove it
with the **−** button; it is no longer used. Likewise turn Fleen off under **General ›
Autofill & Passwords** if it is still listed there.

## Read-only, by construction

**Fleen cannot write KDBX files.** Not "will not by default" — the capability does not
exist in the code. Removed entirely: the XML encoder, the header and inner-header
serialisers, the `VariantDictionary` serialiser, the HMAC block writer, the gzip
compressor, AES-CBC encryption, `ByteWriter`, the entry editor, and every save path
through `VaultSession`. `KdbxCore` exports exactly four entry points — `open` and
`inspect`, each taking `Data` or a `URL`. `Database` has no mutating methods.

Why: a write bug in a password database costs the user their credentials, and the
safest version of that code is none of it. The read path is verified against an
independent implementation and against KeePassXC's own decryption; the write path was
far newer and had no backup-before-overwrite. KeePassXC remains the thing that writes.

Everything else works fully: browse, search, TOTP and clipboard are all read
operations.

### Deletion, specifically

There is no delete either — and never was. No API removes an entry or a group, nothing
empties or restores from the recycle bin, and nothing unlinks or moves the database.
The bin is read: it can be shown or hidden, and that is the extent of Fleen's
involvement.

Fleen writes exactly one kind of file, and it is never the database: an attachment you
explicitly export through a save panel. (Preferences and the security-scoped bookmark go
to `UserDefaults`; neither holds vault contents.)

`FileImmutabilityTests` drives a full session against a real file — select, unlock,
search, browse, read every attachment, reveal every password, generate TOTP codes,
expand the whole tree, reload, lock — then asserts the file is **byte-identical and its
modification date unchanged**. Repeated cycles and a failed unlock are checked too. If a
write path is ever reintroduced at any layer, that test goes red.

### What replaced the writer's test coverage

The old interop suite checked that KeePassXC could read what Fleen *wrote*. With no
writer, the question flips: does Fleen decode a real database to the same values the
reference application does? `ReaderInteropTests` answers it by running
`keepassxc-cli export -f csv` on each fixture — KeePassXC decrypting and parsing the
file itself — and comparing every username, password, URL and note against ours,
across all six cipher/KDF combinations, plus the XML-metacharacter entry, TOTP secrets
and a key-file database.

The gzip decompressor still handles attacker-supplied input, so it kept its coverage:
the test target now builds its own gzip data with zlib rather than having production
code compress its own test input.

## "Launchd job spawn failed" (POSIX error 163)

If `open build/Fleen.app` fails with:

```
Launch failed. … NSPOSIXErrorDomain Code=163 "Launchd job spawn failed"
```

the bundle is claiming **restricted entitlements without a provisioning profile**. App
Sandbox — and the data-protection Keychain that comes with it — may only be claimed by a
bundle carrying a profile that authorises it. Sign it without one and the signature
verifies perfectly — `codesign --verify` passes, `spctl` reports a
valid origin — while the kernel refuses to exec the binary at all.

`Scripts/build-app.sh` now only uses those entitlements when you pass
`--profile /path/to/embedded.provisionprofile`. Without it, development entitlements are
used regardless of signing identity, and the script says so. It also refuses outright
rather than producing a bundle it knows will not start.

This is worth knowing because the failure is invisible to every normal signature check:

| Check | Broken bundle |
|---|---|
| `codesign --verify --deep --strict` | **passes** |
| `spctl -a -t exec` | reports a valid signing origin |
| `open Fleen.app` | **error 163** |
| Running the binary directly | works — launchd is not involved |

That last row is why it can hide during development: `./Fleen.app/Contents/MacOS/Fleen`
bypasses launchd entirely, so a bundle that cannot be launched normally still appears to
run fine.

## A stable signing identity (read this if Touch ID "stops working")

macOS grants **Keychain** access to a *code signature*, not to a file path. An ad-hoc
signature — what you get without `--sign` — is essentially a hash of the binary, so
**every rebuild produces a new identity** and silently invalidates the grant: a Touch ID
key enrolled before a rebuild is unreadable after it. This is the single most common
reason biometric unlock appears broken.

Fix it once, and enrolment sticks across rebuilds:

1. Open **Keychain Access › Certificate Assistant › Create a Certificate…**
2. Name it **`Fleen Development`**, Identity Type *Self Signed Root*, Certificate Type
   **Code Signing**.
3. Rebuild. `Scripts/build-app.sh` finds it automatically and says
   *"Signed with Fleen Development"*.

`Scripts/diagnose.sh` and `FLEEN_DIAG=1` both report which protection level is actually
in force, rather than leaving you to infer it.

### Touch ID: what protection is actually in force

Two levels, and Settings says which one applies:

- **Enforced by the Keychain** — the data-protection keychain refuses to release the
  key without Touch ID. Needs a build signed with an Apple Developer team.
- **Enforced by Fleen** — an unsigned build cannot use that keychain at all
  (`errSecMissingEntitlement`), and the legacy keychain *accepts* a biometric policy and
  then ignores it. So the key is stored plainly and Fleen requires Touch ID itself
  before reading it. A real prompt, but enforced by the app rather than the system:
  someone running code as you could read the key without it.

The weaker mode is used rather than refusing outright, because the alternative was Touch
ID simply never working on a local build. It is never silent — Settings labels it, and
`ProtectionLevel.isCryptographicallyBound` is false, so nothing in the code can mistake
one for the other.

## Unlock performance

Measured on a 500-entry database with KeePassXC-typical settings (Argon2d, 64 MiB,
14 iterations, 2 lanes):

| | Before | After |
|---|---|---|
| Key derivation | 360 ms | **184 ms** |
| Everything else (read, decrypt, decompress, XML) | 12 ms | 14 ms |
| **Total unlock** | 372 ms | **199 ms** |

For comparison, `keepassxc-cli` opens the same file in ~220 ms wall time, which
includes process launch — so the two are now roughly at parity.

**93% of an unlock is Argon2**, and its cost is fixed by the database's own KDF
settings, not by Fleen. Everything Fleen actually controls — reading, decrypting,
decompressing, parsing the XML and building the search index — is ~14 ms. If your
unlock feels slow, that is the memory/iteration count in your database, which is a
security choice you can lower in KeePassXC's database settings.

The 2× improvement came from finding that Argon2 was running **single-threaded**: a
`.define("ARGON2_NO_THREADS", .when(platforms: []))` in `Package.swift`, written
intending a no-op, is applied unconditionally by SwiftPM. A database asking for 2
lanes was deriving its key on one core. The existing Argon2 known-answer test runs at
4 lanes, so it now also verifies that the threaded path produces identical output.

Two commands to check this on your own database:

```bash
.build/release/fleen-cli bench ~/your.kdbx     # KDF vs everything else
.build/release/fleen-cli kdf-scaling           # does Argon2 actually thread?
```

If `kdf-scaling` does not show times falling as lanes rise, threading has regressed.

Still not done, per PLAN.md: a real Instruments pass (Time Profiler + Allocations).
These numbers are wall-clock measurements, which say nothing about allocation churn.

## Known limitations

**Engine**
- **KDBX3 is not readable.** Refused with `.unsupportedVersion`, by agreed scope.
- **Twofish** is recognised but not implemented; reported by name, not "unknown".
- **YubiKey** challenge-response: `CompositeKey.addRawKey(_:)` is the hook, but no
  HID/CCID transport is wired up.
- **ARC4** inner streams are refused rather than supported.
- Entry history is parsed and shown, but `<AutoType>` elements are skipped — nothing
  here synthesises keystrokes, so the sequences would only be dead data.

**App**
- **No credential filling of any kind.** No AutoFill provider, no auto-type; use
  **⌥⌘C** and paste. See [above](#no-autofill-and-no-auto-type) for why.
- **No editing, creating or deleting** — anything that changes the database is
  KeePassXC's job. Fleen has no code that can write a `.kdbx`.
- **`SecureBytes.fromUTF8`** cannot zero the `String` it is handed. The unlock field
  is a SwiftUI `SecureField`, whose `String` we do not own; it is cleared as soon as
  it is consumed, which is mitigation, not a guarantee.
- **The entry list is SwiftUI `List`**, with results capped at 500. PLAN.md's
  NSTableView escape hatch has not been needed; if it ever is, `resultsList` in
  `VaultView.swift` is the single place to change.
- **No app icon** yet — the bundle has no `.icns`.
- **No Instruments pass.** The performance tests are regression guards only; PLAN.md
  requires a real Time Profiler and Allocations run before sign-off.

## Entitlements

Signed builds use `Resources/Fleen.entitlements`; unsigned local builds use
`Fleen.dev.entitlements`, which turns the sandbox off because an ad-hoc identity breaks
Keychain access and bookmarks between builds.

| Entitlement | Why |
|---|---|
| `com.apple.security.app-sandbox` | Required, and it is what enforces the absences below |
| `com.apple.security.files.user-selected.read-only` | Opening the `.kdbx` and key file the user picks. **Read-only** — there is no write path to authorise |
| `com.apple.security.files.bookmarks.app-scope` | Reopening that database on the next launch without re-prompting |

That is the whole list. **Deliberately absent**, each enforced by the sandbox rather
than by our own restraint:

| Not requested | Consequence |
|---|---|
| `network.client` / `.server` | Fleen cannot make a network connection, even accidentally |
| `application-groups` | No shared container, so no vault snapshot at rest anywhere |
| `keychain-access-groups` | The biometric key is readable by this app alone |
| `authentication-services.autofill-credential-provider` | Not a credential provider |
| `files.user-selected.read-write` | Cannot modify the database it opened |

Accessibility (`AXIsProcessTrusted`) is not requested either. It is a user-granted TCC
permission rather than an entitlement, and the sandbox blocks cross-process
Accessibility regardless — which is the intended state, since Fleen never reads another
app's windows or synthesises keystrokes.

A provisioning profile is needed for the sandboxed build, because App Sandbox plus the
data-protection Keychain — what gives Touch ID an OS-enforced gate — requires an
`application-identifier` entitlement that only a profile grants. Without one, pass no
`--profile` and Fleen runs unsandboxed with app-enforced Touch ID instead.
