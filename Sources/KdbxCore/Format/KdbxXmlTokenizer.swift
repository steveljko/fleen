import Foundation

/// Receives the events of a `KdbxXmlTokenizer` pass.
protocol KdbxXmlHandler: AnyObject {
    func startElement(_ name: String, attributes: [String: String]) throws
    func characters(_ text: String)
    func endElement(_ name: String) throws
}

/// A streaming tokenizer for the XML that KDBX files contain, run in place over a
/// buffer the caller owns.
///
/// **Why not `XMLParser`.** Foundation's parser hands the document to libxml2, which
/// copies it into buffers of its own. The audit found one of those — the whole decrypted
/// XML: every title, username, URL and note — still in memory after the vault locked,
/// and nothing Fleen controls can reach it to wipe. This tokenizer reads the caller's
/// bytes directly and allocates only the strings it reports, so the decrypted payload
/// exists in exactly one buffer, which `KdbxFile.open` zeroes.
///
/// **Scope.** KDBX XML is a small, regular subset: UTF-8, elements, attributes, text,
/// the five predefined entities plus character references, and the occasional comment,
/// processing instruction or CDATA section. A `<!DOCTYPE` is refused outright — no KDBX
/// writer emits one, and refusing it closes off external entities and entity-expansion
/// bombs by construction rather than by configuration.
///
/// Every read is bounds-checked; malformed input throws `KdbxError.malformedXML` and
/// never traps.
struct KdbxXmlTokenizer {
    /// A guard against pathological nesting, above any depth a real database has. The
    /// reader applies tighter limits to the structures it builds recursively.
    static let maximumDepth = 4096

    private let bytes: UnsafeRawBufferPointer
    private var index = 0
    private var open: [String] = []

    static func parse(_ data: Data, handler: KdbxXmlHandler) throws {
        try data.withUnsafeBytes { buffer in
            var tokenizer = KdbxXmlTokenizer(bytes: buffer)
            try tokenizer.run(handler)
        }
    }

    private init(bytes: UnsafeRawBufferPointer) {
        self.bytes = bytes
    }

    // MARK: - Driver

    private mutating func run(_ handler: KdbxXmlHandler) throws {
        // UTF-8 byte order mark.
        if hasPrefix([0xEF, 0xBB, 0xBF]) { index = 3 }
        var sawRoot = false

        while index < bytes.count {
            if byte(at: index) == UInt8(ascii: "<") {
                if hasPrefix("<?") {
                    try skip(past: "?>", what: "processing instruction")
                } else if hasPrefix("<!--") {
                    try skip(past: "-->", what: "comment")
                } else if hasPrefix("<![CDATA[") {
                    guard !open.isEmpty else { throw Self.fail("CDATA outside the document") }
                    index += 9
                    let end = try find("]]>", what: "CDATA section")
                    handler.characters(try Self.string(bytes, index..<end))
                    index = end + 3
                } else if hasPrefix("<!") {
                    throw Self.fail("document type declarations are not allowed")
                } else if hasPrefix("</") {
                    try closeTag(handler)
                } else {
                    guard sawRoot == false || !open.isEmpty else {
                        throw Self.fail("content after the document element")
                    }
                    sawRoot = true
                    try openTag(handler)
                }
            } else {
                let end = nextTagStart()
                if open.isEmpty {
                    guard isWhitespace(index..<end) else {
                        throw Self.fail("text outside the document element")
                    }
                } else {
                    handler.characters(try Self.decode(bytes, index..<end))
                }
                index = end
            }
        }

        guard sawRoot else { throw Self.fail("no document element") }
        guard open.isEmpty else { throw Self.fail("the document ends inside <\(open.last!)>") }
    }

    // MARK: - Tags

    private mutating func openTag(_ handler: KdbxXmlHandler) throws {
        index += 1   // "<"
        let name = try readName()
        var attributes: [String: String] = [:]

        while true {
            skipWhitespace()
            guard let b = byte(at: index) else { throw Self.fail("unterminated <\(name)>") }
            if b == UInt8(ascii: ">") {
                index += 1
                try push(name, attributes, handler)
                return
            }
            if b == UInt8(ascii: "/") {
                guard byte(at: index + 1) == UInt8(ascii: ">") else {
                    throw Self.fail("malformed empty element <\(name)/>")
                }
                index += 2
                try push(name, attributes, handler)
                try pop(name, handler)
                return
            }
            let attribute = try readName()
            skipWhitespace()
            guard byte(at: index) == UInt8(ascii: "=") else {
                throw Self.fail("attribute \(attribute) has no value")
            }
            index += 1
            skipWhitespace()
            guard let quote = byte(at: index),
                  quote == UInt8(ascii: "\"") || quote == UInt8(ascii: "'") else {
                throw Self.fail("attribute \(attribute) is not quoted")
            }
            index += 1
            var end = index
            while let c = byte(at: end), c != quote {
                guard c != UInt8(ascii: "<") else { throw Self.fail("'<' in attribute \(attribute)") }
                end += 1
            }
            guard end < bytes.count else { throw Self.fail("unterminated attribute \(attribute)") }
            guard attributes[attribute] == nil else {
                throw Self.fail("attribute \(attribute) repeated")
            }
            attributes[attribute] = try Self.decode(bytes, index..<end)
            index = end + 1
        }
    }

    private mutating func closeTag(_ handler: KdbxXmlHandler) throws {
        index += 2   // "</"
        let name = try readName()
        skipWhitespace()
        guard byte(at: index) == UInt8(ascii: ">") else { throw Self.fail("malformed </\(name)>") }
        index += 1
        try pop(name, handler)
    }

    private mutating func push(_ name: String, _ attributes: [String: String],
                               _ handler: KdbxXmlHandler) throws {
        guard open.count < Self.maximumDepth else { throw Self.fail("elements nested too deeply") }
        open.append(name)
        try handler.startElement(name, attributes: attributes)
    }

    private mutating func pop(_ name: String, _ handler: KdbxXmlHandler) throws {
        guard let expected = open.last else { throw Self.fail("</\(name)> closes nothing") }
        guard expected == name else { throw Self.fail("</\(name)> does not match <\(expected)>") }
        open.removeLast()
        try handler.endElement(name)
    }

    private mutating func readName() throws -> String {
        let start = index
        while let b = byte(at: index), Self.isNameByte(b) { index += 1 }
        guard index > start else { throw Self.fail("expected a name") }
        return String(decoding: UnsafeRawBufferPointer(rebasing: bytes[start..<index]), as: UTF8.self)
    }

    private static func isNameByte(_ b: UInt8) -> Bool {
        switch b {
        case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"),
             UInt8(ascii: "_"), UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: ":"):
            return true
        default:
            return b >= 0x80   // non-ASCII name characters
        }
    }

    // MARK: - Scanning

    private func byte(at i: Int) -> UInt8? {
        i >= 0 && i < bytes.count ? bytes[i] : nil
    }

    private func hasPrefix(_ literal: StaticString) -> Bool {
        hasPrefix(Array(UnsafeBufferPointer(start: literal.utf8Start, count: literal.utf8CodeUnitCount)))
    }

    private func hasPrefix(_ literal: [UInt8]) -> Bool {
        guard index + literal.count <= bytes.count else { return false }
        for (k, b) in literal.enumerated() where bytes[index + k] != b { return false }
        return true
    }

    /// Start of the first occurrence of `terminator` at or after `index`.
    private func find(_ terminator: StaticString, what: String) throws -> Int {
        let t = Array(UnsafeBufferPointer(start: terminator.utf8Start,
                                          count: terminator.utf8CodeUnitCount))
        var i = index
        while i + t.count <= bytes.count {
            var match = true
            for k in 0..<t.count where bytes[i + k] != t[k] { match = false; break }
            if match { return i }
            i += 1
        }
        throw Self.fail("unterminated \(what)")
    }

    private mutating func skip(past terminator: StaticString, what: String) throws {
        index = try find(terminator, what: what) + terminator.utf8CodeUnitCount
    }

    private func nextTagStart() -> Int {
        guard index < bytes.count, let base = bytes.baseAddress else { return bytes.count }
        guard let hit = memchr(base + index, Int32(UInt8(ascii: "<")), bytes.count - index) else {
            return bytes.count
        }
        return base.distance(to: UnsafeRawPointer(hit))
    }

    private mutating func skipWhitespace() {
        while let b = byte(at: index), Self.isSpace(b) { index += 1 }
    }

    private func isWhitespace(_ range: Range<Int>) -> Bool {
        range.allSatisfy { Self.isSpace(bytes[$0]) }
    }

    private static func isSpace(_ b: UInt8) -> Bool {
        b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D
    }

    // MARK: - Text

    static func fail(_ detail: String) -> KdbxError { .malformedXML(detail) }

    /// Raw text (CDATA): line endings normalised, nothing else.
    private static func string(_ bytes: UnsafeRawBufferPointer, _ range: Range<Int>) throws -> String {
        var out = [UInt8]()
        defer { SecureBytes.wipe(&out) }
        out.reserveCapacity(range.count)
        var i = range.lowerBound
        while i < range.upperBound {
            let b = bytes[i]
            if b == 0x0D {
                out.append(0x0A)
                if i + 1 < range.upperBound, bytes[i + 1] == 0x0A { i += 1 }
            } else {
                out.append(b)
            }
            i += 1
        }
        return try validated(out)
    }

    /// Character data or an attribute value: entities decoded, line endings normalised
    /// as XML requires (CR LF and lone CR become LF; `&#13;` stays a CR).
    ///
    /// The scratch buffer holds plaintext — a note, a username — and is wiped before it
    /// is released; the returned `String` is the one copy the model keeps.
    static func decode(_ bytes: UnsafeRawBufferPointer, _ range: Range<Int>) throws -> String {
        var out = [UInt8]()
        defer { SecureBytes.wipe(&out) }
        out.reserveCapacity(range.count)
        var i = range.lowerBound
        while i < range.upperBound {
            let b = bytes[i]
            if b == UInt8(ascii: "&") {
                guard let semicolon = (i + 1..<min(range.upperBound, i + 12))
                        .first(where: { bytes[$0] == UInt8(ascii: ";") }) else {
                    throw fail("unterminated entity reference")
                }
                let name = String(decoding: UnsafeRawBufferPointer(rebasing: bytes[(i + 1)..<semicolon]),
                                  as: UTF8.self)
                try appendEntity(name, to: &out)
                i = semicolon + 1
                continue
            }
            if b == UInt8(ascii: "<") { throw fail("'<' in text") }
            if b == 0x0D {
                out.append(0x0A)
                if i + 1 < range.upperBound, bytes[i + 1] == 0x0A { i += 1 }
            } else {
                out.append(b)
            }
            i += 1
        }
        return try validated(out)
    }

    private static func appendEntity(_ name: String, to out: inout [UInt8]) throws {
        switch name {
        case "amp": out.append(UInt8(ascii: "&"))
        case "lt": out.append(UInt8(ascii: "<"))
        case "gt": out.append(UInt8(ascii: ">"))
        case "quot": out.append(UInt8(ascii: "\""))
        case "apos": out.append(UInt8(ascii: "'"))
        default:
            let value: UInt32?
            if name.hasPrefix("#x") || name.hasPrefix("#X") {
                value = UInt32(name.dropFirst(2), radix: 16)
            } else if name.hasPrefix("#") {
                value = UInt32(name.dropFirst(), radix: 10)
            } else {
                throw fail("unknown entity &\(name);")
            }
            // XML forbids most control characters even as references.
            guard let value, value != 0, let scalar = Unicode.Scalar(value),
                  value >= 0x20 || value == 0x09 || value == 0x0A || value == 0x0D else {
                throw fail("invalid character reference &\(name);")
            }
            out.append(contentsOf: Array(String(Character(scalar)).utf8))
        }
    }

    /// Rejects invalid UTF-8 rather than silently substituting U+FFFD, which would
    /// change a value (a password, a URL) without anyone noticing.
    private static func validated(_ bytes: [UInt8]) throws -> String {
        let invalid = transcode(bytes.makeIterator(), from: UTF8.self, to: UTF8.self,
                                stoppingOnError: true, into: { _ in })
        guard !invalid else { throw fail("text is not valid UTF-8") }
        return String(decoding: bytes, as: UTF8.self)
    }
}
