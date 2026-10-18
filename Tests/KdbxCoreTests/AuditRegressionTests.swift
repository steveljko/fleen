import Testing
import Foundation
@testable import KdbxCore

/// Regression tests for the engine findings in SECURITY_AUDIT.md. Each test names the
/// finding it pins, so a red test points straight at the reasoning.
@Suite("Security audit regressions (engine)")
struct AuditRegressionTests {

    // MARK: - XML tokenizer (F-06, F-08)

    /// Records tokenizer events so the tests can compare them with what XMLParser
    /// produced for the same input.
    final class Recorder: KdbxXmlHandler {
        var events: [String] = []
        func startElement(_ name: String, attributes: [String: String]) throws {
            let attrs = attributes.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }
            events.append("<\(name)\(attrs.isEmpty ? "" : " " + attrs.joined(separator: " "))>")
        }
        func characters(_ text: String) { events.append("text:\(text)") }
        func endElement(_ name: String) throws { events.append("</\(name)>") }
    }

    static func tokenize(_ xml: String) throws -> [String] {
        let recorder = Recorder()
        try KdbxXmlTokenizer.parse(Data(xml.utf8), handler: recorder)
        return recorder.events
    }

    static func rejects(_ xml: String) -> Bool {
        do { _ = try tokenize(xml); return false }
        catch KdbxError.malformedXML { return true }
        catch { return false }
    }

    @Test("F-06: entities, character references, CDATA and line endings decode as XML requires")
    func decodesText() throws {
        let events = try Self.tokenize(
            "\u{FEFF}<?xml version=\"1.0\" encoding=\"utf-8\"?><!-- c --><a k=\"&quot;1&amp;2&quot;\">"
            + "&lt;x&gt; &apos;&#65;&#x42;&#233;\r\nend<![CDATA[<raw>&amp;]]><e/></a>")
        #expect(events == ["<a k=\"1&2\">", "text:<x> 'ABé\nend", "text:<raw>&amp;",
                           "<e>", "</e>", "</a>"])
    }

    @Test("F-06: a document type declaration is refused, so no entity can be expanded")
    func refusesDoctype() {
        #expect(Self.rejects("<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY x SYSTEM \"file:///etc/hosts\">]><a>&x;</a>"))
        #expect(Self.rejects("<!DOCTYPE a [<!ENTITY b \"bb\">]><a>&b;</a>"))
    }

    @Test("F-06: malformed documents throw rather than trap", arguments: [
        "", "<a>", "<a></b>", "</a>", "<a><b></a></b>", "<a>&nope;</a>", "<a>&amp</a>",
        "<a x=1></a>", "<a x=\"1></a>", "<a x=\"1\" x=\"2\"></a>", "<a>&#0;</a>", "<a>&#xD800;</a>",
        "<a></a><b></b>", "text<a></a>", "<a><!-- open</a>", "<a><![CDATA[open</a>", "<", "<a/",
    ])
    func rejectsMalformed(_ xml: String) {
        #expect(Self.rejects(xml), "accepted: \(xml.debugDescription)")
    }

    @Test("F-06: invalid UTF-8 is an error, not a silently substituted character")
    func rejectsInvalidUTF8() {
        let recorder = Recorder()
        let bytes: [UInt8] = Array("<a>".utf8) + [0xC3, 0x28] + Array("</a>".utf8)
        #expect(throws: KdbxError.self) { try KdbxXmlTokenizer.parse(Data(bytes), handler: recorder) }
    }

    static func readerXML(groups: Int = 1, historyDepth: Int = 0) -> String {
        var entry = "<Entry><String><Key>Title</Key><Value>t</Value></String></Entry>"
        for _ in 0..<historyDepth {
            entry = "<Entry><String><Key>Title</Key><Value>h</Value></String><History>\(entry)</History></Entry>"
        }
        return "<KeePassFile><Root>" + String(repeating: "<Group><Name>g</Name>", count: groups)
            + entry + String(repeating: "</Group>", count: groups) + "</Root></KeePassFile>"
    }

    static func read(_ xml: String) throws -> Group {
        let header = KdbxInnerHeader(streamID: .none, streamKey: SecureBytes(count: 0), binaries: [])
        let reader = KdbxXmlReader(innerStream: try InnerStreamCipher(header: header), binaries: [])
        return try reader.parse(Data(xml.utf8)).root
    }

    @Test("F-08: folders nested past the limit are refused instead of crashing the app")
    func limitsGroupDepth() throws {
        _ = try Self.read(Self.readerXML(groups: KdbxXmlReader.maximumGroupDepth))
        #expect(throws: KdbxError.self) {
            try Self.read(Self.readerXML(groups: KdbxXmlReader.maximumGroupDepth + 1))
        }
        // The 20,000-deep file from the audit crashed with SIGSEGV; now it is an error.
        #expect(throws: KdbxError.self) { try Self.read(Self.readerXML(groups: 20_000)) }
    }

    @Test("F-08: history inside history is refused; ordinary history still reads")
    func refusesNestedHistory() throws {
        let root = try Self.read(Self.readerXML(historyDepth: 1))
        #expect(root.allEntries().first?.history.count == 1)
        #expect(throws: KdbxError.self) { try Self.read(Self.readerXML(historyDepth: 2)) }
    }

    // MARK: - TOTP (F-07)

    @Test("F-07: a ten-digit TOTP produces a code instead of trapping")
    func tenDigitTOTP() {
        let totp = TOTP(secret: Array("12345678901234567890".utf8), digits: 10)
        let code = totp.code(at: Date(timeIntervalSince1970: 59))
        #expect(code.count == 10)
        #expect(code.allSatisfy { $0.isNumber })
        // RFC 6238's 8-digit vector at T=59 is 94287082; ten digits keeps the same
        // low-order digits because the 31-bit value is below 10^10.
        #expect(code.hasSuffix("94287082"))
    }

    // MARK: - Touch ID composite key (F-10)

    @Test("F-10: a stored composite key survives an unlock, so Reload works after Touch ID")
    func precomposedKeyIsNotConsumed() throws {
        var typed = CompositeKey()
        typed.addPassword(Fixture.password)
        let stored = typed.rawKey()
        let biometric = CompositeKey.precomposed(stored)
        let url = try Fixture.url("pkp-aes-argon2d.kdbx")

        _ = try KdbxFile.open(url: url, credentials: biometric)
        #expect(!stored.withUnsafeBytes { $0.allSatisfy { $0 == 0 } },
                "Argon2 zeroed the key the session keeps for reloading")
        _ = try KdbxFile.open(url: url, credentials: biometric)   // the Reload
    }

    // MARK: - Key files (F-16)

    @Test("F-16: a large key file is hashed in chunks to the same key as reading it whole")
    func largeKeyFileStreams() throws {
        var bytes = [UInt8](repeating: 0, count: CompositeKey.streamingThreshold * 2 + 17)
        for i in bytes.indices { bytes[i] = UInt8(truncatingIfNeeded: i &* 31 &+ 7) }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("fleen-keyfile-\(UUID().uuidString).bin")
        try Data(bytes).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        var streamed = CompositeKey()
        try streamed.addKeyFile(url: url)
        var whole = CompositeKey()
        try whole.addKeyFile(data: Data(bytes))
        #expect(streamed.rawKey().isEqual(to: whole.rawKey()))
    }

    // MARK: - mlock (F-13)

    @Test("F-13: freeing one buffer does not unpin a neighbour on the same page")
    func pinsAreReferenceCounted() throws {
        let survivor = SecureBytes(count: 32)
        try #require(survivor.isMemoryLocked)
        let page = survivor.baseAddress & ~(UInt(getpagesize()) - 1)

        // Allocate until some buffers land on the survivor's page, then free them all.
        var neighbours = (0..<256).map { _ in SecureBytes(count: 32) }
        let sharing = neighbours.filter { $0.baseAddress & ~(UInt(getpagesize()) - 1) == page }.count
        try #require(sharing > 0, "no neighbour landed on the survivor's page")
        // ≥ rather than ==: tests run in parallel and may hold buffers on this page too.
        #expect(PagePins.pinCount(containing: page) >= 1 + sharing)
        neighbours.removeAll()

        // Before the fix, the first neighbour's munlock unpinned the survivor's page.
        #expect(PagePins.pinCount(containing: page) >= 1,
                "the survivor's page must stay pinned while the survivor lives")
    }
}
