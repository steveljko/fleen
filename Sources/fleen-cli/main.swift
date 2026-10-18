import Foundation
import KdbxCore

// A small harness for exercising the engine against a real database by hand.
// This is NOT the shipping app — that is the Fleen menu bar target. It exists so a
// KDBX file can be pointed at the engine without a UI in the way.
//
// Passwords are read with getpass(), so they never appear in argv, in shell history,
// or on screen.

let usage = """
fleen-cli — exercise the Fleen KDBX engine against a real database

USAGE
  fleen-cli info    <database.kdbx>
  fleen-cli ls      <database.kdbx> [--keyfile <path>] [--no-password]
  fleen-cli show    <database.kdbx> <title> [--keyfile <path>] [--reveal]
  fleen-cli bench   <database.kdbx> [--keyfile <path>]
  fleen-cli kdf-scaling

COMMANDS
  info     Header only: format version, cipher, KDF and its cost. No password needed.
  ls       Unlock and print the group/entry tree.
  show     Unlock and print one entry. Passwords stay masked unless --reveal.
  bench    Time the unlock, split into key derivation and everything else. Use it to
           see whether a slow unlock is the KDF (set by the database) or Fleen.
  kdf-scaling
           Time Argon2 at 1/2/4/8 lanes. If the times do not fall as lanes rise,
           Argon2 is not threading and unlocking is needlessly slow.

OPTIONS
  --keyfile <path>   Key file to combine with the password.
  --no-password      Key file only; do not prompt for a password.
  --reveal           Print protected values in clear text.
"""

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

func seconds(_ duration: Duration) -> Double {
    Double(duration.components.seconds) + Double(duration.components.attoseconds) * 1e-18
}

func promptPassword(_ prompt: String) throws -> String {
    guard let raw = getpass(prompt) else { throw CLIError("could not read a password") }
    let password = String(cString: raw)
    // getpass returns a static buffer that keeps the password until the next call.
    _ = memset_s(raw, strlen(raw), 0, strlen(raw))
    return password
}

func credentials(keyFile: String?, usePassword: Bool) throws -> CompositeKey {
    var key = CompositeKey()
    if usePassword {
        key.addPassword(try promptPassword("Master password: "))
    }
    if let keyFile {
        try key.addKeyFile(url: URL(fileURLWithPath: keyFile))
    }
    guard !key.isEmpty else { throw CLIError("no password and no key file — nothing to unlock with") }
    return key
}

/// Unlocks with a progress line, so a slow Argon2 does not look like a hang.
func unlock(_ url: URL, _ key: CompositeKey) throws -> Database {
    let info = try KdbxFile.inspect(url: url)
    FileHandle.standardError.write(Data("Deriving key (\(info.kdf.displayName))… ".utf8))

    let start = ContinuousClock.now
    let database = try KdbxFile.open(url: url, credentials: key)
    let elapsed = ContinuousClock.now - start

    FileHandle.standardError.write(Data("done in \(elapsed).\n".utf8))
    return database
}

func printTree(_ group: Group, indent: String = "") {
    print("\(indent)\(group.name)/")
    for entry in group.entries.sorted(by: { $0.title < $1.title }) {
        let flags = [
            entry.times.isExpired ? "expired" : nil,
            entry.attachments.isEmpty ? nil : "\(entry.attachments.count) attachment(s)",
            entry.totp == nil ? nil : "TOTP",
        ].compactMap { $0 }
        let suffix = flags.isEmpty ? "" : "  [\(flags.joined(separator: ", "))]"
        print("\(indent)  \(entry.title)\(suffix)")
    }
    for child in group.groups.sorted(by: { $0.name < $1.name }) {
        printTree(child, indent: indent + "  ")
    }
}

func show(_ entry: Entry, in database: Database, reveal: Bool) {
    func line(_ label: String, _ value: String) {
        guard !value.isEmpty else { return }
        print("\(label.padding(toLength: 14, withPad: " ", startingAt: 0)) \(value)")
    }

    line("Title", entry.title)
    line("UserName", entry.username)
    line("Password", entry.password.map { reveal ? $0.reveal() : "••••••••" } ?? "")
    line("URL", entry.url)
    if !entry.notes.isEmpty {
        print("Notes")
        for l in entry.notes.split(separator: "\n", omittingEmptySubsequences: false) {
            print("    \(l)")
        }
    }
    line("Tags", entry.tags.joined(separator: ", "))
    if let totp = entry.totp {
        // The live code, plus how long it lasts. Shown even without --reveal: it
        // expires in seconds and is useless to anyone reading it later.
        line("TOTP", "\(TOTP.formatted(totp.code()))  (\(totp.secondsRemaining())s left)")
    }

    // Same rule as the app: TOTP storage fields are plumbing, already shown as a
    // live code above, and empty fields are noise.
    let custom = entry.meaningfulCustomFields
    if !custom.isEmpty {
        print("Custom fields")
        for (name, value) in custom.sorted(by: { $0.key < $1.key }) {
            let shown = value.isProtected && !reveal ? "••••••••" : value.reveal()
            print("    \(name): \(shown)")
        }
    }
    if !entry.attachments.isEmpty {
        print("Attachments")
        for ref in entry.attachments {
            let size = database.attachment(for: ref)?.data.count ?? 0
            print("    \(ref.name) (\(size) bytes)")
        }
    }
}

// MARK: - Entry point

do {
    var args = Array(CommandLine.arguments.dropFirst())
    guard let command = args.first else {
        print(usage)
        exit(2)
    }
    args.removeFirst()

    func takeFlag(_ name: String) -> Bool {
        guard let index = args.firstIndex(of: name) else { return false }
        args.remove(at: index)
        return true
    }
    func takeOption(_ name: String) throws -> String? {
        guard let index = args.firstIndex(of: name) else { return nil }
        guard index + 1 < args.count else { throw CLIError("\(name) needs a value") }
        let value = args[index + 1]
        args.removeSubrange(index...(index + 1))
        return value
    }

    let keyFile = try takeOption("--keyfile")
    let noPassword = takeFlag("--no-password")
    let reveal = takeFlag("--reveal")

    if command == "kdf-scaling" {
        // Handled below; needs no database.
    }
    guard command == "kdf-scaling" || args.first != nil else {
        throw CLIError("no database path given")
    }
    let path = args.first ?? "/dev/null"
    let url = URL(fileURLWithPath: path)
    if !args.isEmpty { args.removeFirst() }

    switch command {
    case "info":
        let info = try KdbxFile.inspect(url: url)
        print("Format        KDBX \(info.majorVersion).\(info.minorVersion)")
        print("Cipher        \(info.cipher.displayName)")
        print("KDF           \(info.kdf.displayName)")
        switch info.kdf {
        case .argon2d(let m, let t, let p, let v), .argon2id(let m, let t, let p, let v):
            print("              memory \(m) KiB, iterations \(t), parallelism \(p), version 0x\(String(v, radix: 16))")
        case .aesKdf(let rounds):
            print("              \(rounds) rounds")
        }
        print("Compression   \(info.compression == .gzip ? "gzip" : "none")")

    case "ls":
        let database = try unlock(url, try credentials(keyFile: keyFile, usePassword: !noPassword))
        printTree(database.rootGroup)
        print("\n\(database.entryCount) entries")

    case "show":
        guard let title = args.first else { throw CLIError("no entry title given") }
        let database = try unlock(url, try credentials(keyFile: keyFile, usePassword: !noPassword))
        let matches = database.allEntries.filter {
            $0.title.localizedCaseInsensitiveContains(title)
        }
        guard let entry = matches.first else { throw CLIError("no entry matching “\(title)”") }
        if matches.count > 1 {
            FileHandle.standardError.write(
                Data("\(matches.count) entries matched; showing the first.\n".utf8))
        }
        show(entry, in: database, reveal: reveal)

    case "bench":
        let info = try KdbxFile.inspect(url: url)
        let key = try credentials(keyFile: keyFile, usePassword: !noPassword)

        // Time the KDF on its own, at the database's real cost, then the whole open.
        // The difference is everything Fleen controls: read, decrypt, decompress, XML.
        var kdfSamples: [Double] = []
        for _ in 0..<3 {
            let start = ContinuousClock.now
            _ = try KeyScheduleBenchmark.deriveOnly(info: info, credentials: key)
            kdfSamples.append(seconds(ContinuousClock.now - start))
        }

        var totalSamples: [Double] = []
        for _ in 0..<3 {
            let start = ContinuousClock.now
            _ = try KdbxFile.open(url: url, credentials: key)
            totalSamples.append(seconds(ContinuousClock.now - start))
        }

        let kdf = kdfSamples.min()!
        let total = totalSamples.min()!

        print("KDF           \(info.kdf.displayName)")
        switch info.kdf {
        case .argon2d(let m, let t, let p, _), .argon2id(let m, let t, let p, _):
            print("              memory \(m) KiB, iterations \(t), parallelism \(p)")
        case .aesKdf(let rounds):
            print("              \(rounds) rounds")
        }
        print(String(format: "Key derivation  %.0f ms", kdf * 1000))
        print(String(format: "Everything else %.0f ms", max(0, (total - kdf)) * 1000))
        print(String(format: "Total unlock    %.0f ms", total * 1000))
        print(String(format: "                (%.0f%% of it is the KDF, which the database’s own settings fix)",
                     kdf / total * 100))

    case "kdf-scaling":
        // Diagnostic: same total work, varying lane count. If threading is effective
        // the wall time should fall as lanes rise on a multi-core machine.
        print("Argon2d, 64 MiB, 14 iterations — wall time by lane count:")
        for lanes in [UInt32(1), 2, 4, 8] {
            var best = Double.greatestFiniteMagnitude
            for _ in 0..<2 {
                let start = ContinuousClock.now
                _ = try Argon2.hash(password: SecureBytes(Array("bench".utf8)),
                                    salt: [UInt8](repeating: 0x11, count: 16),
                                    variant: .d, version: 0x13,
                                    memoryKiB: 65536, iterations: 14, parallelism: lanes)
                best = min(best, seconds(ContinuousClock.now - start))
            }
            print(String(format: "  lanes %d: %5.0f ms", lanes, best * 1000))
        }

    case "help", "--help", "-h":
        print(usage)

    default:
        throw CLIError("unknown command “\(command)”")
    }
} catch let error as CLIError {
    FileHandle.standardError.write(Data("error: \(error.description)\n\n\(usage)\n".utf8))
    exit(2)
} catch let error as KdbxError {
    FileHandle.standardError.write(
        Data("error: \(error.errorDescription ?? String(describing: error))\n".utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
    exit(1)
}
