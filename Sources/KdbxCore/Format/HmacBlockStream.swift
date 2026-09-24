import Foundation
import CryptoKit

/// KDBX4's authenticated framing for the encrypted payload.
///
/// The payload is a sequence of `HMAC-SHA256(32) ‖ length(UInt32 LE) ‖ data`, each
/// block MAC'd under its own key derived from the block index. A zero-length block
/// terminates the stream.
///
/// This is what makes KDBX4 tamper-evident, so the verification here is strict:
/// every block is authenticated *before* its contents are handed on to the cipher,
/// and a truncated stream (one missing its terminating block) is rejected rather
/// than silently returning a short payload.
enum HmacBlockStream {
    /// Upper bound on a single block, enforced on read as an allocation guard: a forged
    /// length field must not be able to ask for an arbitrarily large buffer. We *write*
    /// 1 MiB blocks (see `write`), but accept up to 16 MiB so a database produced by
    /// another implementation with larger blocks still opens.
    static let maxBlockSize = 1024 * 1024 * 16

    static func read(_ reader: inout ByteReader, schedule: KeySchedule) throws -> Data {
        var output = Data()
        var index: UInt64 = 0

        while true {
            let storedMac = try reader.readBytes(32)
            let blockSize = try reader.readUInt32()

            guard Int(blockSize) <= maxBlockSize else {
                throw KdbxError.payloadCorrupted("block \(index) declares an implausible size")
            }
            let blockData = try reader.read(Int(blockSize))

            let key = schedule.blockKey(index: index)
            var mac = key.withUnsafeBytes {
                HMAC<SHA256>(key: SymmetricKey(data: Data($0)))
            }
            withUnsafeBytes(of: index.littleEndian) { mac.update(data: Data($0)) }
            withUnsafeBytes(of: blockSize.littleEndian) { mac.update(data: Data($0)) }
            mac.update(data: blockData)

            let computed = Array(mac.finalize())
            guard timingSafeCompare(computed, storedMac) else {
                // On the first block this is almost always a wrong password; later it
                // means real corruption or tampering. We cannot tell the difference
                // with certainty, so the caller decides how to phrase it.
                throw index == 0 ? KdbxError.invalidCredentials
                                 : KdbxError.payloadCorrupted("block \(index) failed authentication")
            }

            if blockSize == 0 { return output }   // terminator
            output.append(blockData)
            index += 1
        }
    }

    /// The header's own HMAC, under the reserved block index.
    static func headerMac(header: Data, schedule: KeySchedule) -> [UInt8] {
        let key = schedule.blockKey(index: KeySchedule.headerBlockIndex)
        let mac = key.withUnsafeBytes {
            HMAC<SHA256>.authenticationCode(for: header, using: SymmetricKey(data: Data($0)))
        }
        return Array(mac)
    }
}
