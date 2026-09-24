import Foundation

/// KDBX4's typed key/value blob, used to carry KDF parameters.
///
/// Version is `major.minor`; a reader must reject an unknown *major* but tolerate an
/// unknown minor, which is how KeePass keeps the format forward-compatible.
struct VariantDictionary {
    enum Value: Equatable {
        case uint32(UInt32)
        case uint64(UInt64)
        case bool(Bool)
        case int32(Int32)
        case int64(Int64)
        case string(String)
        case bytes([UInt8])
    }

    private(set) var values: [String: Value] = [:]

    init() {}

    init(parsing data: Data) throws {
        var reader = ByteReader(data)
        let version = try reader.readUInt16()
        guard version >> 8 <= 1 else {
            throw KdbxError.malformedHeader("unsupported VariantDictionary version \(version >> 8)")
        }

        while true {
            let type = try reader.readUInt8()
            if type == 0 { break }   // end of dictionary
            let nameLength = try reader.readUInt32()
            let nameBytes = try reader.read(Int(nameLength))
            guard let name = String(data: nameBytes, encoding: .utf8) else {
                throw KdbxError.malformedHeader("VariantDictionary key is not valid UTF-8")
            }
            let valueLength = Int(try reader.readUInt32())
            let raw = try reader.read(valueLength)

            switch type {
            case 0x04:
                guard valueLength == 4 else { throw KdbxError.malformedHeader("bad UInt32 in \(name)") }
                values[name] = .uint32(raw.withUnsafeBytes {
                    UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) })
            case 0x05:
                guard valueLength == 8 else { throw KdbxError.malformedHeader("bad UInt64 in \(name)") }
                values[name] = .uint64(raw.withUnsafeBytes {
                    UInt64(littleEndian: $0.loadUnaligned(as: UInt64.self)) })
            case 0x08:
                guard valueLength == 1 else { throw KdbxError.malformedHeader("bad Bool in \(name)") }
                values[name] = .bool(raw.first != 0)
            case 0x0C:
                guard valueLength == 4 else { throw KdbxError.malformedHeader("bad Int32 in \(name)") }
                values[name] = .int32(raw.withUnsafeBytes {
                    Int32(littleEndian: $0.loadUnaligned(as: Int32.self)) })
            case 0x0D:
                guard valueLength == 8 else { throw KdbxError.malformedHeader("bad Int64 in \(name)") }
                values[name] = .int64(raw.withUnsafeBytes {
                    Int64(littleEndian: $0.loadUnaligned(as: Int64.self)) })
            case 0x18:
                guard let s = String(data: raw, encoding: .utf8) else {
                    throw KdbxError.malformedHeader("VariantDictionary string \(name) is not UTF-8")
                }
                values[name] = .string(s)
            case 0x42:
                values[name] = .bytes([UInt8](raw))
            default:
                throw KdbxError.malformedHeader("unknown VariantDictionary type 0x\(String(type, radix: 16))")
            }
        }
    }

    subscript(key: String) -> Value? {
        get { values[key] }
        set { values[key] = newValue }
    }

    func uint32(_ key: String) -> UInt32? {
        if case .uint32(let v) = values[key] { return v }
        return nil
    }

    func uint64(_ key: String) -> UInt64? {
        if case .uint64(let v) = values[key] { return v }
        if case .uint32(let v) = values[key] { return UInt64(v) }
        return nil
    }

    func bytes(_ key: String) -> [UInt8]? {
        if case .bytes(let v) = values[key] { return v }
        return nil
    }
}
