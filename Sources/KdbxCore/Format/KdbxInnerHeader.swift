import Foundation

/// The KDBX4 inner header, which sits inside the encrypted payload ahead of the XML.
///
/// It carries the inner-stream cipher used for protected field values, and the
/// attachment pool — in KDBX4 binaries moved out of the XML and into here, which is
/// why attachments cost nothing in parse time until actually read.
struct KdbxInnerHeader {
    enum InnerStreamID: UInt32 {
        case none = 0
        case arc4 = 1      // recognised and refused: ARC4 is broken
        case salsa20 = 2
        case chacha20 = 3
    }

    var streamID: InnerStreamID
    var streamKey: SecureBytes
    var binaries: [Attachment]

    private enum FieldID: UInt8 {
        case end = 0
        case innerRandomStreamID = 1
        case innerRandomStreamKey = 2
        case binary = 3
    }

    static func parse(_ reader: inout ByteReader) throws -> KdbxInnerHeader {
        var streamID: InnerStreamID?
        var streamKey: SecureBytes?
        var binaries: [Attachment] = []

        loop: while true {
            let rawID = try reader.readUInt8()
            let length = Int(try reader.readUInt32())
            let payload = try reader.read(length)

            guard let field = FieldID(rawValue: rawID) else { continue }

            switch field {
            case .end:
                break loop
            case .innerRandomStreamID:
                guard length == 4 else { throw KdbxError.malformedHeader("bad inner stream ID") }
                let raw = payload.withUnsafeBytes {
                    UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
                guard let id = InnerStreamID(rawValue: raw) else {
                    throw KdbxError.malformedHeader("unknown inner stream ID \(raw)")
                }
                guard id != .arc4 else {
                    throw KdbxError.malformedHeader("this database uses ARC4 for protected values, which is not secure")
                }
                streamID = id
            case .innerRandomStreamKey:
                streamKey = SecureBytes(payload)
            case .binary:
                // First byte is a flags byte; bit 0 means "protected in memory".
                guard length >= 1 else { throw KdbxError.malformedHeader("empty binary field") }
                let flags = payload[payload.startIndex]
                let content = payload[(payload.startIndex + 1)...]
                binaries.append(Attachment(data: Data(content), isProtected: flags & 0x01 != 0))
            }
        }

        guard let streamID else { throw KdbxError.malformedHeader("no inner stream ID") }
        guard let streamKey else { throw KdbxError.malformedHeader("no inner stream key") }
        return KdbxInnerHeader(streamID: streamID, streamKey: streamKey, binaries: binaries)
    }

}

/// Applies the inner random stream to protected field values.
///
/// Critical ordering property: this is a *stream* cipher over the concatenation of
/// every protected value in document order. Values must be fed through in exactly
/// the order they appear in the XML, on both read and write, or everything after the
/// first mismatch decrypts to garbage.
final class InnerStreamCipher {
    private enum Engine {
        case none
        case salsa20(Salsa20)
        case chacha20(ChaCha20)
    }

    private var engine: Engine

    init(header: KdbxInnerHeader) throws {
        switch header.streamID {
        case .none:
            engine = .none
        case .arc4:
            throw KdbxError.malformedHeader("ARC4 protected values are not supported")
        case .salsa20:
            // Salsa20 key is SHA-256 of the stream key; nonce is fixed by the format.
            let key = header.streamKey.withUnsafeBytes { buf -> [UInt8] in
                var hasher = SHA256Wrapper()
                hasher.update(buf)
                return hasher.finalize()
            }
            engine = .salsa20(Salsa20(key: key, nonce: Salsa20.kdbxNonce))
        case .chacha20:
            // ChaCha20 key/nonce are the first 32 and next 12 bytes of SHA-512(streamKey).
            let digest = header.streamKey.withUnsafeBytes { buf -> [UInt8] in
                var hasher = SHA512Wrapper()
                hasher.update(buf)
                return hasher.finalize()
            }
            let key = SecureBytes(Array(digest[0..<32]))
            let nonce = Array(digest[32..<44])
            engine = key.withUnsafeBytes { .chacha20(ChaCha20(key: $0, nonce: nonce)) }
        }
    }

    func process(_ bytes: inout [UInt8]) {
        switch engine {
        case .none:
            break
        case .salsa20(var s):
            s.process(&bytes)
            engine = .salsa20(s)
        case .chacha20(var c):
            c.process(&bytes)
            engine = .chacha20(c)
        }
    }
}
