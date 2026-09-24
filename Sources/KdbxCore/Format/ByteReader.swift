import Foundation

/// Bounds-checked little-endian cursor over a `Data`.
///
/// Every read is checked. A KDBX file is attacker-controllable input — a database
/// synced through a third-party service is exactly the threat model in PLAN.md —
/// so there is no unchecked path from file bytes to a buffer length anywhere here.
struct ByteReader {
    let data: Data
    private(set) var offset: Int

    init(_ data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    var remaining: Int { data.endIndex - offset }
    var consumed: Int { offset - data.startIndex }

    mutating func read(_ count: Int) throws -> Data {
        guard count >= 0, remaining >= count else {
            throw KdbxError.malformedHeader("unexpected end of file")
        }
        defer { offset += count }
        return data[offset..<(offset + count)]
    }

    mutating func readBytes(_ count: Int) throws -> [UInt8] {
        [UInt8](try read(count))
    }

    mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else { throw KdbxError.malformedHeader("unexpected end of file") }
        defer { offset += 1 }
        return data[offset]
    }

    mutating func readUInt16() throws -> UInt16 {
        let b = try read(2)
        return b.withUnsafeBytes { UInt16(littleEndian: $0.loadUnaligned(as: UInt16.self)) }
    }

    mutating func readUInt32() throws -> UInt32 {
        let b = try read(4)
        return b.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
    }

    mutating func readUInt64() throws -> UInt64 {
        let b = try read(8)
        return b.withUnsafeBytes { UInt64(littleEndian: $0.loadUnaligned(as: UInt64.self)) }
    }

    mutating func readInt32() throws -> Int32 { Int32(bitPattern: try readUInt32()) }
    mutating func readInt64() throws -> Int64 { Int64(bitPattern: try readUInt64()) }

    mutating func readRest() -> Data {
        defer { offset = data.endIndex }
        return data[offset...]
    }
}

extension UUID {
    /// KDBX stores UUIDs as raw big-endian 16-byte blobs, not as strings.
    init?(kdbxBytes bytes: [UInt8]) {
        guard bytes.count == 16 else { return nil }
        self.init(uuid: (bytes[0], bytes[1], bytes[2], bytes[3],
                         bytes[4], bytes[5], bytes[6], bytes[7],
                         bytes[8], bytes[9], bytes[10], bytes[11],
                         bytes[12], bytes[13], bytes[14], bytes[15]))
    }

    var kdbxBytes: [UInt8] {
        let u = self.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
                u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }
}
