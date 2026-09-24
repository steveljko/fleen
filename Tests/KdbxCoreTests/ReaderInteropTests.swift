import Testing
import Foundation
@testable import KdbxCore

/// Compares our reader against KeePassXC's own decryption of the same files.
///
/// This replaces the interop suite that used to check KeePassXC could read what we
/// *wrote*. With the writer gone, the question worth answering flips round: does Fleen
/// decode a real database to the same values the reference application does? So each
/// fixture is exported with `keepassxc-cli export -f csv` — KeePassXC decrypting and
/// parsing the file itself — and every field compared against ours.
///
/// Skips itself when KeePassXC is not installed.
enum KeePassXCExport {
    static let executable: URL? = {
        [
            "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli",
            "/opt/homebrew/bin/keepassxc-cli",
            "/usr/local/bin/keepassxc-cli",
        ].lazy.map(URL.init(fileURLWithPath:))
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }()

    static var isAvailable: Bool { executable != nil }

    struct Row: Equatable {
        var group = ""
        var title = ""
        var username = ""
        var password = ""
        var url = ""
        var notes = ""
        var totp = ""
    }

    /// Runs the export and returns one row per entry, keyed by title.
    static func rows(for fixture: String, password: String,
                     keyFile: String? = nil) throws -> [String: Row] {
        guard let executable else { return [:] }

        var arguments = ["export", "-q", "-f", "csv"]
        if let keyFile {
            arguments += ["--key-file", try Fixture.url(keyFile).path]
        }
        arguments.append(try Fixture.url(fixture).path)

        let process = Process()
        process.executableURL = executable
        process.arguments = arguments

        let input = Pipe(), output = Pipe(), error = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = error

        try process.run()
        input.fileHandleForWriting.write(Data((password + "\n").utf8))
        input.fileHandleForWriting.closeFile()

        let data = output.fileHandleForReading.readDataToEndOfFile()
        _ = error.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else { return [:] }
        return parse(String(decoding: data, as: UTF8.self))
    }

    /// Minimal RFC 4180 CSV reader: fields may be quoted, contain commas, embedded
    /// newlines, and doubled quotes — all of which the fixtures deliberately do.
    static func parse(_ csv: String) -> [String: Row] {
        var fields: [[String]] = []
        var field = ""
        var record: [String] = []
        var inQuotes = false
        var iterator = csv.makeIterator()
        var pending: Character?

        while let character = pending ?? iterator.next() {
            pending = nil
            if inQuotes {
                if character == "\"" {
                    if let next = iterator.next() {
                        if next == "\"" { field.append("\"") } else { inQuotes = false; pending = next }
                    } else {
                        inQuotes = false
                    }
                } else {
                    field.append(character)
                }
            } else {
                switch character {
                case "\"": inQuotes = true
                case ",": record.append(field); field = ""
                case "\n":
                    record.append(field); field = ""
                    fields.append(record); record = []
                case "\r": break
                default: field.append(character)
                }
            }
        }
        if !field.isEmpty || !record.isEmpty {
            record.append(field)
            fields.append(record)
        }

        guard fields.count > 1 else { return [:] }
        var result: [String: Row] = [:]
        for line in fields.dropFirst() where line.count >= 7 {
            var row = Row()
            row.group = line[0]
            row.title = line[1]
            row.username = line[2]
            row.password = line[3]
            row.url = line[4]
            row.notes = line[5]
            row.totp = line[6]
            result[row.title] = row
        }
        return result
    }
}

@Suite("Reader interoperability", .enabled(if: KeePassXCExport.isAvailable,
                                          "keepassxc-cli is not installed"))
struct ReaderInteropTests {

    @Test("Every field matches KeePassXC's own decryption",
          arguments: Fixture.matrix)
    func matchesKeePassXC(fixture: String) throws {
        let expected = try KeePassXCExport.rows(for: fixture, password: Fixture.password)
        try #require(!expected.isEmpty, "KeePassXC could not export \(fixture)")

        let database = try Fixture.open(fixture)

        for entry in database.allEntries {
            guard let reference = expected[entry.title] else {
                Issue.record("KeePassXC has no entry titled “\(entry.title)” in \(fixture)")
                continue
            }

            #expect(entry.username == reference.username,
                    "username mismatch for “\(entry.title)”")
            #expect((entry.password?.reveal() ?? "") == reference.password,
                    "password mismatch for “\(entry.title)”")
            #expect(entry.url == reference.url, "URL mismatch for “\(entry.title)”")
            #expect(entry.notes == reference.notes, "notes mismatch for “\(entry.title)”")
        }

        // And neither side sees entries the other does not.
        #expect(Set(database.allEntries.map(\.title)) == Set(expected.keys))
    }

    @Test("Awkward text decodes identically in both implementations")
    func matchesOnAwkwardText() throws {
        let expected = try KeePassXCExport.rows(for: "pkp-aes-argon2d.kdbx",
                                               password: Fixture.password)
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")

        let title = "Ampersand & <angle> \"quotes\" 'apos'"
        let reference = try #require(expected[title],
                                    "the XML-metacharacter entry is the one most likely to diverge")
        let ours = try #require(database.allEntries.first { $0.title == title })

        #expect(ours.username == reference.username)
        #expect(ours.password?.reveal() == reference.password)
        #expect(ours.notes == reference.notes)
        #expect(ours.url == reference.url)
    }

    @Test("TOTP secrets agree with KeePassXC")
    func matchesTOTP() throws {
        let expected = try KeePassXCExport.rows(for: "pkp-aes-argon2d.kdbx",
                                               password: Fixture.password)
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")

        for title in ["TOTP Entry", "TOTP Legacy"] {
            let reference = try #require(expected[title])
            try #require(!reference.totp.isEmpty, "KeePassXC reported no TOTP for \(title)")

            let ours = try #require(database.allEntries.first { $0.title == title }?.totp)
            let theirs = try #require(TOTP.parse(uri: reference.totp))

            // Compare generated codes rather than URI text: the two implementations
            // format the URI differently but must agree on the secret.
            let moment = Date(timeIntervalSince1970: 1_700_000_000)
            #expect(ours.code(at: moment) == theirs.code(at: moment),
                    "TOTP disagreement for \(title)")
        }
    }

    @Test("A key-file database decodes identically")
    func matchesWithKeyFile() throws {
        let expected = try KeePassXCExport.rows(for: "pkp-keyfile-raw.kdbx",
                                                password: Fixture.password,
                                                keyFile: "keyfile.key")
        try #require(!expected.isEmpty)

        let database = try Fixture.open("pkp-keyfile-raw.kdbx", keyFile: "keyfile.key")
        let reference = try #require(expected["Example Entry"])
        let ours = try #require(database.allEntries.first { $0.title == "Example Entry" })
        #expect(ours.password?.reveal() == reference.password)
        #expect(ours.username == reference.username)
    }
}
