import AppKit
import Foundation
import FleenKit
import KdbxCore

// Fleen security-audit harness. Every secret arrives XOR-0x5A obfuscated (argv or the
// generator's .keys.json), so the harness holds no plaintext copy of its own except
// where it deliberately plays the UI's part (the typed master password).

func deobfuscate(_ hex: String) -> [UInt8] { Pattern(name: "", obfuscatedHex: hex).obfuscated.map { $0 ^ 0x5A } }

/// Builds the "typed" password String the way a text field would hand it over.
func typedPassword(_ obfHex: String) -> String { String(decoding: deobfuscate(obfHex), as: UTF8.self) }

func loadKeys(_ path: String) -> [String: String] {
    let data = try! Data(contentsOf: URL(fileURLWithPath: path))
    return try! JSONSerialization.jsonObject(with: data) as! [String: String]
}

func maxRSSMiB() -> Double {
    var usage = rusage()
    getrusage(RUSAGE_SELF, &usage)
    return Double(usage.ru_maxrss) / 1024 / 1024   // bytes on macOS
}

func scanPatterns(keysPath: String, canaries: [(String, String)]) -> [Pattern] {
    var patterns: [Pattern] = []
    for (name, obfHex) in canaries {
        patterns += Pattern.string(name, obfuscatedUTF8: Pattern(name: "", obfuscatedHex: obfHex).obfuscated)
    }
    let keys = loadKeys(keysPath)
    for name in ["composite", "transformed", "cipherKey", "hmacSeed", "innerStreamKey", "innerChaChaKey"] {
        if let hex = keys[name] { patterns.append(Pattern(name: "key:" + name, obfuscatedHex: hex)) }
    }
    return patterns
}

let args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else {
    print("usage: fleen-audit open|memscan-engine|memscan-session|precomposed|race|totp …")
    exit(2)
}

switch command {

// open <file> <pwObfHex>
case "open":
    let url = URL(fileURLWithPath: args[1])
    let start = Date()
    do {
        var key = CompositeKey()
        key.addPassword(typedPassword(args[2]))
        let db = try KdbxFile.open(url: url, credentials: key)
        let title = db.allEntries.first?.title ?? ""
        print(String(format: "OK entries=%d time=%.2fs maxRSS=%.0fMiB firstTitle(len %d)=%@",
                     db.entryCount, Date().timeIntervalSince(start), maxRSSMiB(),
                     title.count, String(title.prefix(40)).debugDescription))
    } catch {
        print(String(format: "THREW %@ time=%.2fs maxRSS=%.0fMiB",
                     String(describing: error), Date().timeIntervalSince(start), maxRSSMiB()))
    }

// memscan-engine <file> <keys.json> <pwObf> <entryPwObf> <notesObf> <commentObf>
case "memscan-engine":
    let patterns = scanPatterns(keysPath: args[2], canaries: [
        ("master password", args[3]), ("entry password", args[4]),
        ("notes (plain field)", args[5]), ("xml comment (never a String)", args[6])])
    report("baseline, before anything is opened", patterns)
    func session() {
        autoreleasepool {
            var key = CompositeKey()
            key.addPassword(typedPassword(args[3]))
            let db = try! KdbxFile.open(url: URL(fileURLWithPath: args[1]), credentials: key)
            let entry = db.allEntries.first!
            let shown = entry.password!.reveal()     // what Copy / Reveal does
            precondition(!shown.isEmpty)
            report("engine: database open, password revealed once", patterns)
        }
    }
    session()
    report("engine: database, key and revealed String all released", patterns)

// memscan-session <file> <keys.json> <pwObf> <entryPwObf> <notesObf> <commentObf>
case "memscan-session":
    let patterns = scanPatterns(keysPath: args[2], canaries: [
        ("master password", args[3]), ("entry password", args[4]),
        ("notes (plain field)", args[5]), ("xml comment (never a String)", args[6])])
    Task { @MainActor in
        let suite = "audit.fleen.\(getpid())"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let session = VaultSession(preferences: Preferences(defaults: defaults))
        try! session.select(url: URL(fileURLWithPath: args[1]))
        await session.unlock(password: typedPassword(args[3]))
        precondition(session.state == .unlocked, "unlock failed: \(session.state)")

        let board = NSPasteboard(name: .init("audit-\(UUID().uuidString)"))
        let clipboard = ClipboardService(pasteboard: board)
        // Scoped so the harness itself holds no Entry once the session locks.
        do {
            let entry = session.database!.allEntries.first!
            clipboard.copySecret(entry.password!.reveal(), clearAfter: 0)   // ⌥⌘C
        }
        print("pasteboard types: \(board.types?.map(\.rawValue) ?? [])")
        report("session: unlocked, password copied", patterns)

        session.lock()
        clipboard.clearIfStillOurs()
        board.releaseGlobally()
        try? await Task.sleep(for: .milliseconds(300))
        report("session: after lock() and clipboard clear", patterns)
        defaults.removePersistentDomain(forName: suite); exit(0)   // exit skips defer
    }
    RunLoop.main.run()

// precomposed <argon2-file> <keys.json>
// The Touch ID path: CompositeKey.precomposed(stored) → open → (reload) open again.
case "precomposed":
    let raw = SecureBytes(deobfuscate(loadKeys(args[2])["composite"]!))
    let key = CompositeKey.precomposed(raw)
    let url = URL(fileURLWithPath: args[1])
    for attempt in 1...2 {
        do {
            _ = try KdbxFile.open(url: url, credentials: key)
            print("open #\(attempt): OK")
        } catch {
            print("open #\(attempt): THREW \(error)")
        }
        let zeroed = raw.withUnsafeBytes { $0.allSatisfy { $0 == 0 } }
        print("  stored composite key all-zero after open #\(attempt): \(zeroed)")
    }

// race <slow-file> <pwObf> <mode: lock|select> [<other-file>]
case "race":
    Task { @MainActor in
        let suite = "audit.fleen.\(getpid())"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let session = VaultSession(preferences: Preferences(defaults: defaults))
        try! session.select(url: URL(fileURLWithPath: args[1]))
        let unlocking = Task { await session.unlock(password: typedPassword(args[2])) }
        try? await Task.sleep(for: .milliseconds(150))
        print("during KDF: state=\(session.state)")
        if args[3] == "lock" {
            session.lock(reason: .screenLocked)          // what screen-lock / sleep / ⌘L do
            print("after lock(.screenLocked): state=\(session.state) database=\(session.database != nil)")
        } else {
            try! session.select(url: URL(fileURLWithPath: args[4]))
            print("after select(other): state=\(session.state) url=\(session.databaseURL!.lastPathComponent)")
        }
        await unlocking.value
        print("after KDF finished: state=\(session.state) database loaded=\(session.database != nil) "
              + "url=\(session.databaseURL!.lastPathComponent) "
              + "entries=\(session.database?.allEntries.map(\.title) ?? [])")
        defaults.removePersistentDomain(forName: suite); exit(0)   // exit skips defer
    }
    RunLoop.main.run()

// stages <file> <pwObf>: which stage overflows the stack on deep nesting?
case "stages":
    nonisolated(unsafe) var db: Database?
    let t = Thread {
        var key = CompositeKey()
        key.addPassword(typedPassword(args[2]))
        db = try? KdbxFile.open(url: URL(fileURLWithPath: args[1]), credentials: key)
        print("stage 1: KdbxFile.open on a 1 GiB stack: \(db != nil ? "OK" : "threw")"); fflush(stdout)
    }
    t.stackSize = Int(ProcessInfo.processInfo.environment["STACK"] ?? "") ?? (1 << 30)
    t.start()
    while !t.isFinished { usleep(10_000) }
    print("stage 2: allEntries on the 8 MiB main stack…"); fflush(stdout)
    print("         \(db!.allEntries.count) entries"); fflush(stdout)
    print("stage 3: SearchIndex(database:) as VaultSession.adopt does…"); fflush(stdout)
    print("         \(SearchIndex(database: db!).records.count) records"); fflush(stdout)
    print("stage 4: releasing the Database on the main stack…"); fflush(stdout)
    db = nil
    print("         released")

// zero-on-free probe: does this libmalloc scrub freed blocks?
case "zerofree":
    var patterns: [Pattern] = []
    for size in [32, 200, 2_000, 40_000, 400_000] {
        let marker = "ZeroFreeProbe-\(size)-Q7"
        let obf = obfuscate(marker)
        patterns.append(Pattern(name: "freed \(size)B block", obfuscated: obf))
        let p = malloc(size)!.assumingMemoryBound(to: UInt8.self)
        memset(p, 0x41, size)
        for (k, b) in obf.enumerated() { p[size / 2 + k] = b ^ 0x5A }
        free(p)
    }
    report("after free()", patterns)

// xmlprobe: does Foundation's XMLParser leave a copy of its input behind?
case "xmlprobe":
    let marker = obfuscate("XmlParserProbeCanary-31337")
    let patterns = [Pattern(name: "xml input canary", obfuscated: marker)]
    func parseOnce(slice: Bool) {
        var bytes = Array("<?xml version=\"1.0\"?><a><!-- ".utf8)
        bytes += marker.map { $0 ^ 0x5A }
        bytes += Array(" --><b>text</b></a>".utf8)
        bytes += [UInt8](repeating: 0x20, count: 300)
        var whole = Data([0, 0, 0, 0] + bytes)
        SecureBytes.wipe(&bytes)
        autoreleasepool {
            let parser = XMLParser(data: slice ? whole[4...] : whole)
            _ = parser.parse()
        }
        SecureBytes.wipe(&whole)
    }
    parseOnce(slice: CommandLine.arguments.count > 2 && CommandLine.arguments[2] == "slice")
    report("after XMLParser(data:) released and every Swift-side buffer wiped", patterns)

// clipboard: auto-clear timing and the changeCount guard, on a private pasteboard
case "clipboard":
    Task { @MainActor in
        let board = NSPasteboard(name: .init("audit-clip-\(UUID().uuidString)"))
        defer { board.releaseGlobally() }
        let service = ClipboardService(pasteboard: board)

        service.copySecret("clip-secret-1", clearAfter: 2)
        print("after copy: types=\(board.types?.map(\.rawValue) ?? []) value=\(board.string(forType: .string) ?? "nil")")
        try? await Task.sleep(for: .milliseconds(3_200))
        print("3.2s later (timeout 2s): value=\(board.string(forType: .string) ?? "nil (cleared)")")

        service.copySecret("clip-secret-2", clearAfter: 2)
        board.clearContents(); board.setString("user copied this", forType: .string)
        try? await Task.sleep(for: .milliseconds(3_200))
        print("user overwrote it, 3.2s later: value=\(board.string(forType: .string) ?? "nil")")
        exit(0)
    }
    RunLoop.main.run()

// totp <digits>
case "totp":
    let digits = Int(args[1])!
    var entry = Entry()
    entry.fields["otp"] = .plain("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=\(digits)")
    print("parsed digits=\(entry.totp!.digits); generating code…")
    fflush(stdout)
    print("code=\(entry.totp!.code())")

default:
    print("unknown command \(command)")
    exit(2)
}
