import Foundation
import zlib

/// gzip via the system zlib. KDBX uses gzip framing (window bits 15 + 16).
enum Gzip {
    /// Guards against a decompression bomb: a small encrypted payload must not be
    /// able to expand without limit. 512 MiB is far beyond any real database.
    static let maxDecompressedSize = 512 * 1024 * 1024

    static func decompress(_ input: Data) throws -> Data {
        guard !input.isEmpty else { return Data() }

        var stream = z_stream()
        guard inflateInit2_(&stream, 15 + 16, ZLIB_VERSION,
                            Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw KdbxError.payloadCorrupted("could not start decompression")
        }
        defer { inflateEnd(&stream) }

        var output = Data()
        let chunkSize = 64 * 1024
        var chunk = [UInt8](repeating: 0, count: chunkSize)
        // The scratch chunk holds decrypted plaintext on every pass, so it is zeroed
        // before the allocation is handed back to the heap.
        defer { SecureBytes.wipe(&chunk) }
        var input = input

        // Reserve up front from gzip's ISIZE trailer. Growing a `Data` by `append`
        // reallocates, and a reallocation copies the plaintext to a new block and frees
        // the old one *without zeroing it* — leaving a trail of stale partial copies of
        // the decrypted database across the heap that nothing can find again to wipe.
        // ISIZE is attacker-controlled, so it is only a hint: clamped low enough that a
        // lie cannot exhaust memory, while covering any realistic database in one
        // allocation. The real bound stays the maxDecompressedSize check below.
        if let hint = Self.declaredSize(of: input) {
            output.reserveCapacity(min(hint, 64 * 1024 * 1024))
        }

        let status: Int32 = try input.withUnsafeMutableBytes { inBuf -> Int32 in
            stream.next_in = inBuf.baseAddress?.assumingMemoryBound(to: Bytef.self)
            stream.avail_in = uInt(inBuf.count)

            while true {
                let result: Int32 = chunk.withUnsafeMutableBufferPointer { outBuf -> Int32 in
                    stream.next_out = outBuf.baseAddress
                    stream.avail_out = uInt(chunkSize)
                    return inflate(&stream, Z_NO_FLUSH)
                }

                switch result {
                case Z_OK, Z_STREAM_END, Z_BUF_ERROR:
                    let produced = chunkSize - Int(stream.avail_out)
                    if produced > 0 {
                        guard output.count + produced <= maxDecompressedSize else {
                            throw KdbxError.payloadCorrupted("decompressed contents are implausibly large")
                        }
                        output.append(contentsOf: chunk[0..<produced])
                    }
                    if result == Z_STREAM_END { return Z_STREAM_END }
                    if result == Z_BUF_ERROR && produced == 0 { return Z_BUF_ERROR }
                default:
                    return result
                }
            }
        }

        guard status == Z_STREAM_END else {
            SecureBytes.wipe(&output)
            throw KdbxError.payloadCorrupted("the compressed contents are damaged")
        }
        return output
    }

    /// gzip records the uncompressed length mod 2^32 in the last four bytes.
    /// Untrusted, so callers must treat it as a hint and clamp it.
    static func declaredSize(of input: Data) -> Int? {
        guard input.count >= 4 else { return nil }
        let tail = input.suffix(4)
        var size: UInt32 = 0
        for (i, byte) in tail.enumerated() { size |= UInt32(byte) << (8 * UInt32(i)) }
        return Int(size)
    }
}
