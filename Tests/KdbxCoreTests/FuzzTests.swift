import Testing
import Foundation
import CryptoKit
@testable import KdbxCore

/// Fuzzing the parsers that run on attacker-controlled bytes.
///
/// PLAN.md's threat model assumes the `.kdbx` may be hostile — it syncs through a third
/// party, and a shared vault is a file someone else made. Every bounds check in
/// `ByteReader`, the header TLVs and the `VariantDictionary` was hand-audited, which is
/// the same method that produced the bugs those audits later found.
///
/// The contract under test is narrow and absolute: **for any input, the engine either
/// returns a database or throws a `KdbxError`.** It must never trap, never hang, and
/// never allocate without bound. A Swift trap takes the process down, so a crash is a
/// failed run rather than a failed expectation — which is the point.
///
/// Mutation is deterministic: every case is reproducible from its seed, so a failure can
/// be replayed instead of hunted.
///
/// An ordinary `swift test` runs a small smoke pass — enough that a regression in bounds
/// checking shows up, cheap enough not to disturb the wall-clock performance guards. The
/// real run is explicit:
///
///     FLEEN_FUZZ_ITERATIONS=20000 swift test --filter Fuzzing
///
/// which additionally enables the tiers that run the KDF or allocate heavily.
@Suite("Fuzzing")
struct FuzzTests {

    /// Reproducible, and independent of whatever Swift's stdlib RNG does next release.
    struct SeededGenerator: RandomNumberGenerator {
        private var state: UInt64
        init(seed: UInt64) { state = seed == 0 ? 0x9E3779B97F4A7C15 : seed }

        mutating func next() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }
    }

    /// Kept small by default so `swift test` stays a few seconds: enough that a
    /// regression in bounds checking shows up on an ordinary run, not enough to call a
    /// real soak. `FLEEN_FUZZ_ITERATIONS=20000 swift test --filter Fuzzing` is the soak.
    static var iterations: Int {
        ProcessInfo.processInfo.environment["FLEEN_FUZZ_ITERATIONS"].flatMap(Int.init) ?? 20
    }

    /// Tiers that run the KDF cost ~0.2s per case, so they get their own, smaller budget
    /// unless a soak is explicitly asked for.
    static var kdfIterations: Int {
        ProcessInfo.processInfo.environment["FLEEN_FUZZ_ITERATIONS"].flatMap(Int.init) ?? 15
    }

    /// The 600 MiB bomb case allocates enough to be worth skipping on a normal run.
    static var runsExpensiveCases: Bool {
        ProcessInfo.processInfo.environment["FLEEN_FUZZ_ITERATIONS"] != nil
    }

    /// One mutation, chosen at random. Named so a failure says what was done.
    enum Mutation: CaseIterable {
        case flipBit, setByte, zeroRun, fillRun, truncate, extend, duplicateChunk, swapChunks
    }

    static func mutate(_ input: Data, using rng: inout SeededGenerator) -> (Data, Mutation) {
        var bytes = [UInt8](input)
        let mutation = Mutation.allCases.randomElement(using: &rng)!
        guard !bytes.isEmpty else { return (input, mutation) }

        func index() -> Int { Int.random(in: 0..<bytes.count, using: &rng) }
        func runLength() -> Int { Int.random(in: 1...max(1, min(64, bytes.count)), using: &rng) }

        switch mutation {
        case .flipBit:
            let i = index()
            bytes[i] ^= 1 << UInt8.random(in: 0...7, using: &rng)
        case .setByte:
            bytes[index()] = UInt8.random(in: 0...255, using: &rng)
        case .zeroRun:
            let i = index(), n = min(runLength(), bytes.count - i)
            for k in i..<(i + n) { bytes[k] = 0 }
        case .fillRun:
            let i = index(), n = min(runLength(), bytes.count - i)
            for k in i..<(i + n) { bytes[k] = 0xFF }
        case .truncate:
            bytes = Array(bytes.prefix(index()))
        case .extend:
            // Bounded: this is about parser robustness, not about exhausting the machine.
            bytes.append(contentsOf: (0..<min(runLength(), 1024)).map { _ in
                UInt8.random(in: 0...255, using: &rng) })
        case .duplicateChunk:
            let i = index(), n = min(runLength(), bytes.count - i)
            bytes.insert(contentsOf: bytes[i..<(i + n)], at: i)
        case .swapChunks:
            let a = index(), b = index()
            bytes.swapAt(a, b)
        }
        return (Data(bytes), mutation)
    }

    /// Any outcome is acceptable except a trap, a hang, or an error of the wrong type.
    static func expectSurvives(_ data: Data, label: String) {
        let start = Date()
        do {
            _ = try KdbxFile.open(data: data, credentials: Fixture.credentials())
        } catch is KdbxError {
            // The documented outcome for bad input.
        } catch {
            Issue.record("\(label): threw a non-KdbxError: \(error)")
        }
        let elapsed = Date().timeIntervalSince(start)
        #expect(elapsed < 10, "\(label): took \(elapsed)s — a parser should fail fast")
    }

    // MARK: - Tier 1: raw bytes, before any authentication

    /// This is the surface an attacker reaches with no credentials at all: header
    /// parsing happens before the key is derived or anything is authenticated.
    @Test("Random mutations of a real database never crash the parser",
          arguments: Fixture.matrix)
    func rawMutations(fixture: String) throws {
        let original = try Data(contentsOf: Fixture.url(fixture))
        var rng = SeededGenerator(seed: 0xFEE1_600D)

        for iteration in 0..<Self.iterations {
            let (mutant, mutation) = Self.mutate(original, using: &rng)
            Self.expectSurvives(mutant, label: "\(fixture) #\(iteration) \(mutation)")
        }
    }

    /// Garbage with no relationship to the format at all.
    @Test("Arbitrary noise is rejected rather than parsed")
    func randomNoise() {
        var rng = SeededGenerator(seed: 0xDEAD_BEEF)
        for iteration in 0..<Self.iterations {
            let length = Int.random(in: 0...4096, using: &rng)
            let noise = Data((0..<length).map { _ in UInt8.random(in: 0...255, using: &rng) })
            Self.expectSurvives(noise, label: "noise #\(iteration) (\(length) bytes)")
        }
    }

    /// Truncation at every offset through the header, which is where length-prefixed
    /// TLV parsing is most likely to read past the end.
    @Test("Truncation at any offset is handled", arguments: Fixture.matrix)
    func truncationSweep(fixture: String) throws {
        let original = try Data(contentsOf: Fixture.url(fixture))
        let limit = min(original.count, Self.runsExpensiveCases ? 512 : 48)
        for cut in 0..<limit {
            Self.expectSurvives(original.prefix(cut), label: "\(fixture) truncated to \(cut)")
        }
    }

    // MARK: - Tier 2: past the integrity check

    /// A random mutation almost always dies at the header's SHA-256, which means the
    /// deeper parsers — `VariantDictionary`, the KDF parameters, cipher selection —
    /// would never be reached. An attacker crafting a file would of course recompute
    /// that hash, so the fuzzer does too.
    /// Opted in rather than always-on: every case here runs a full Argon2, which
    /// saturates the machine and makes the wall-clock performance guards elsewhere in
    /// the suite fail for reasons that have nothing to do with them.
    @Test("Mutations with a repaired header hash reach the deeper parsers")
    func repairedHeaderMutations() throws {
        guard Self.runsExpensiveCases else { return }
        let fixture = "pkp-aes-argon2d.kdbx"
        let original = try Data(contentsOf: Fixture.url(fixture))

        var reader = ByteReader(original)
        let header = try KdbxHeader.parse(&reader)
        let headerLength = header.rawBytes.count
        try #require(headerLength > 12 && headerLength + 32 <= original.count)

        var rng = SeededGenerator(seed: 0xC0FF_EE00)
        for iteration in 0..<Self.kdfIterations {
            var bytes = [UInt8](original)

            // Mutate inside the header only, leaving the file's shape intact.
            let target = Int.random(in: 12..<headerLength, using: &rng)
            bytes[target] = UInt8.random(in: 0...255, using: &rng)

            // Repair the SHA-256 so parsing proceeds past the integrity check.
            let repaired = Data(SHA256.hash(data: Data(bytes[0..<headerLength])))
            bytes.replaceSubrange(headerLength..<(headerLength + 32), with: repaired)

            Self.expectSurvives(Data(bytes), label: "\(fixture) repaired #\(iteration) @\(target)")
        }
    }

    // MARK: - Component fuzzing, behind the cipher

    /// gzip runs on bytes that were encrypted, so reaching it needs the password — the
    /// shared-vault case, where the file came from someone else. It is also the one
    /// component with an explicit bomb guard, so the guard is checked rather than
    /// assumed.
    @Test("Decompression survives arbitrary input")
    func gzipFuzzing() throws {
        var rng = SeededGenerator(seed: 0x6217_0001)
        let valid = try CryptoPrimitiveTests.gzip(Data(repeating: 0x41, count: 4096))

        for iteration in 0..<Self.iterations {
            let (mutant, mutation) = Self.mutate(valid, using: &rng)
            do {
                let out = try Gzip.decompress(mutant)
                #expect(out.count <= Gzip.maxDecompressedSize)
            } catch is KdbxError {
                // Expected for damaged input.
            } catch {
                Issue.record("gzip #\(iteration) \(mutation): non-KdbxError \(error)")
            }
        }
    }

    /// The XML arrives decrypted, so malformed XML is reachable by anyone who can hand
    /// you a database you have the password for.
    @Test("The XML reader survives malformed documents")
    func xmlFuzzing() throws {
        let sample = """
        <KeePassFile><Meta><DatabaseName>x</DatabaseName></Meta><Root><Group>\
        <Name>G</Name><Entry><String><Key>Title</Key><Value>T</Value></String>\
        </Entry></Group></Root></KeePassFile>
        """
        var rng = SeededGenerator(seed: 0x584D_4C00)
        let base = Data(sample.utf8)

        for iteration in 0..<Self.iterations {
            let (mutant, mutation) = Self.mutate(base, using: &rng)
            let innerHeader = KdbxInnerHeader(streamID: .chacha20,
                                              streamKey: SecureBytes([UInt8](repeating: 7, count: 64)),
                                              binaries: [])
            do {
                let stream = try InnerStreamCipher(header: innerHeader)
                let reader = KdbxXmlReader(innerStream: stream, binaries: [])
                _ = try reader.parse(mutant)
            } catch is KdbxError {
                // Expected.
            } catch {
                Issue.record("xml #\(iteration) \(mutation): non-KdbxError \(error)")
            }
        }
    }

    /// The decompression bomb guard, stated as a test rather than trusted as a comment.
    @Test("A decompression bomb is refused rather than expanded")
    func decompressionBombIsCapped() throws {
        // Skipped unless a soak was asked for: building the bomb allocates 600 MiB.
        guard Self.runsExpensiveCases else { return }
        // Highly compressible: ~600 MiB of zeroes, past the 512 MiB cap.
        let huge = Data(repeating: 0, count: 600 * 1024 * 1024)
        let bomb = try CryptoPrimitiveTests.gzip(huge)
        #expect(bomb.count < 1024 * 1024, "the bomb should be small on disk")

        #expect(throws: KdbxError.self) { _ = try Gzip.decompress(bomb) }
    }
}
