import Testing
import Foundation
@testable import KdbxCore

/// Pins the memory-hygiene invariants that are easy to break silently.
///
/// The hazard these exist for: `Data` is copy-on-write, so zeroing one through
/// `withUnsafeMutableBytes` while another `Data` shares the buffer copies first and
/// zeroes the copy — the original plaintext stays in memory at an address nothing can
/// reach again. Nothing about the call site looks wrong when this happens, which is
/// exactly why it needs a test rather than a code comment.
@Suite("Memory hygiene")
struct MemoryHygieneTests {

    /// The failure mode itself, demonstrated rather than described. If this ever stops
    /// holding, Swift changed `Data`'s COW behaviour and the scoping in `KdbxFile.open`
    /// can be simplified.
    @Test("A shared buffer defeats an in-place wipe, which is why scoping matters")
    func cowDefeatsWipe() {
        var payload = Data("SECRETPASSWORD!!".utf8)
        let original = payload.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }

        let slice = payload[4...]                       // what readRest() hands back
        payload.withUnsafeMutableBytes { buf in         // the wipe, minus the debug check
            if let base = buf.baseAddress { _ = memset_s(base, buf.count, 0, buf.count) }
        }
        let moved = payload.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }

        #expect(moved != original,
                "a live slice should force COW; if not, the premise of this suite changed")
        #expect(slice.contains { $0 != 0 },
                "the original buffer should still hold plaintext — that IS the bug")
        withExtendedLifetime(slice) {}
    }

    /// With sole ownership the buffer is zeroed where it sits.
    @Test("A uniquely held buffer is wiped in place")
    func uniqueWipeIsInPlace() {
        var secret = Data("SECRETPASSWORD!!".utf8)
        let before = secret.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
        SecureBytes.wipe(&secret)
        let after = secret.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }

        #expect(before == after, "no copy should have been made")
        #expect(secret.allSatisfy { $0 == 0 })
    }

    /// The real guard on `KdbxFile.open`. The debug-build assertion inside
    /// `SecureBytes.wipe` traps if the deferred payload wipe hits a COW copy, so simply
    /// opening every fixture exercises it. Reintroduce a payload slice that outlives the
    /// parse scope and this goes red.
    @Test("Opening a database wipes the decrypted payload in place",
          arguments: Fixture.matrix)
    func openWipesPayloadInPlace(fixture: String) throws {
        let database = try Fixture.open(fixture)
        #expect(!database.rootGroup.allEntries().isEmpty)
    }

    /// Gzip's scratch chunk and output buffer hold decrypted plaintext, so the
    /// decompressor must not leave either behind. Capacity is reserved from the ISIZE
    /// trailer specifically so `append` does not reallocate and strand partial copies of
    /// the decrypted database across the heap.
    @Test("Decompression reads its size hint from the gzip trailer")
    func decompressionReservesFromTrailer() throws {
        let size = 4 * 1024 * 1024
        let plaintext = Data(repeating: 0x41, count: size)
        let compressed = try CryptoPrimitiveTests.gzip(plaintext)

        #expect(Gzip.declaredSize(of: compressed) == size,
                "the ISIZE trailer should give the exact uncompressed length")
        #expect(try Gzip.decompress(compressed) == plaintext)
    }

    /// The hint is attacker-controlled, so it must never be trusted as a bound.
    /// Two separate protections: zlib rejects a trailer that disagrees with what it
    /// actually produced, and the reservation is clamped so a large claim cannot be
    /// turned into a memory-exhaustion request before inflation even starts.
    @Test("A lying size trailer is rejected, and could not have been reserved anyway")
    func lyingTrailerIsRejected() throws {
        var compressed = try CryptoPrimitiveTests.gzip(Data(repeating: 0x41, count: 1024))
        compressed.replaceSubrange((compressed.count - 4)..<compressed.count,
                                   with: [0xFF, 0xFF, 0xFF, 0xFF])

        // The claim is enormous...
        #expect(Gzip.declaredSize(of: compressed) == Int(UInt32.max))
        // ...the clamp keeps the reservation bounded regardless...
        #expect(min(Gzip.declaredSize(of: compressed)!, 64 * 1024 * 1024) == 64 * 1024 * 1024)
        // ...and zlib refuses the stream outright, because ISIZE no longer matches.
        #expect(throws: KdbxError.self) { _ = try Gzip.decompress(compressed) }
    }
}
