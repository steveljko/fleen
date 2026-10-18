import Darwin
import Foundation

/// Scans this process's own readable memory for byte patterns.
///
/// Patterns are held XOR-0x5A obfuscated and compared byte-by-byte on the fly, so the
/// scanner itself never materialises the plaintext it is looking for — a hit is
/// therefore a copy made by the code under test, not by the harness.
struct Pattern {
    let name: String
    let obfuscated: [UInt8]

    init(name: String, obfuscatedHex: String) {
        self.name = name
        var out: [UInt8] = []
        var i = obfuscatedHex.startIndex
        while i < obfuscatedHex.endIndex {
            let j = obfuscatedHex.index(i, offsetBy: 2)
            out.append(UInt8(obfuscatedHex[i..<j], radix: 16)!)
            i = j
        }
        self.obfuscated = out
    }

    init(name: String, obfuscated: [UInt8]) {
        self.name = name
        self.obfuscated = obfuscated
    }

    /// UTF-8 and UTF-16LE variants of an obfuscated string.
    static func string(_ name: String, obfuscatedUTF8: [UInt8]) -> [Pattern] {
        var utf16: [UInt8] = []
        for b in obfuscatedUTF8 { utf16.append(b); utf16.append(0x5A) }   // 0x00 ^ 0x5A
        return [Pattern(name: name + " [utf8]", obfuscated: obfuscatedUTF8),
                Pattern(name: name + " [utf16]", obfuscated: utf16)]
    }
}

func obfuscate(_ s: String) -> [UInt8] { Array(s.utf8).map { $0 ^ 0x5A } }

func tagName(_ tag: UInt32) -> String {
    switch tag {
    case 1: return "MALLOC"
    case 2: return "MALLOC_SMALL"
    case 3: return "MALLOC_LARGE"
    case 4: return "MALLOC_HUGE"
    case 7: return "MALLOC_TINY"
    case 8: return "MALLOC_LARGE_REUSABLE"
    case 9: return "MALLOC_LARGE_REUSED"
    case 11: return "MALLOC_NANO"
    case 30: return "STACK"
    case 0: return "untagged"
    default: return "tag\(tag)"
    }
}

/// Whether a hit lies inside a block malloc still considers allocated (a live copy
/// someone holds) or not (freed memory that was never zeroed, or non-malloc memory).
func liveness(_ address: UInt) -> String {
    var start = address & ~UInt(15)
    for _ in 0..<65536 {
        if let ptr = UnsafeRawPointer(bitPattern: start), malloc_zone_from_ptr(ptr) != nil {
            let size = malloc_size(ptr)
            if size > 0 && start + UInt(size) > address {
                return " [LIVE block +0x\(String(address - start, radix: 16)) of \(size)B]"
            }
        }
        if start < 16 { break }
        start -= 16
    }
    return " [not in a live malloc block]"
}

/// Returns pattern name → list of "tag@address" hits.
func scanSelf(_ patterns: [Pattern]) -> [String: [String]] {
    let task = mach_task_self_
    let scratchSize = 4 << 20
    let scratch = mmap(nil, scratchSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)!
    let scratchLo = UInt(bitPattern: scratch), scratchHi = scratchLo + UInt(scratchSize)
    defer { memset(scratch, 0, scratchSize); munmap(scratch, scratchSize) }
    let buf = scratch.assumingMemoryBound(to: UInt8.self)

    var hits: [String: [String]] = [:]
    var address: mach_vm_address_t = 0
    var depth: natural_t = 0

    while true {
        var size: mach_vm_size_t = 0
        var info = vm_region_submap_info_data_64_t()
        var count = mach_msg_type_number_t(MemoryLayout<vm_region_submap_info_data_64_t>.size / 4)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: Int32.self, capacity: Int(count)) {
                mach_vm_region_recurse(task, &address, &size, &depth, $0, &count)
            }
        }
        if kr != KERN_SUCCESS { break }
        if info.is_submap != 0 { depth += 1; continue }

        // Secrets end up in heap and stack, which are writable; the read-only shared
        // cache and mapped binaries cannot hold runtime copies, and walking them is
        // what makes a naive scan take minutes.
        let readable = (info.protection & VM_PROT_READ) != 0
            && (info.protection & VM_PROT_WRITE) != 0
            && info.pages_resident + info.pages_swapped_out > 0
        let lo = UInt(address), hi = UInt(address + size)
        let overlapsScratch = lo < scratchHi && scratchLo < hi
        if readable && !overlapsScratch {
            var offset: mach_vm_size_t = 0
            while offset < size {
                let chunk = min(mach_vm_size_t(scratchSize), size - offset)
                var got: mach_vm_size_t = 0
                let r = mach_vm_read_overwrite(task, address + offset, chunk,
                                               mach_vm_address_t(scratchLo), &got)
                if r == KERN_SUCCESS {
                    for p in patterns {
                        let n = p.obfuscated.count
                        let first = p.obfuscated[0] ^ 0x5A
                        var i = 0
                        let limit = Int(got) - n
                        while i <= limit {
                            guard let found = memchr(buf + i, Int32(first), limit - i + 1) else { break }
                            i = buf.distance(to: found.assumingMemoryBound(to: UInt8.self))
                            var j = 1
                            while j < n && buf[i + j] == (p.obfuscated[j] ^ 0x5A) { j += 1 }
                            if j == n {
                                let at = address + offset + mach_vm_size_t(i)
                                hits[p.name, default: []].append(
                                    "\(tagName(info.user_tag))@0x\(String(at, radix: 16))\(liveness(UInt(at)))")
                            }
                            i += 1
                        }
                    }
                    memset(scratch, 0, Int(got))
                }
                offset += chunk
            }
        }
        address += size
    }
    return hits
}

func report(_ title: String, _ patterns: [Pattern]) {
    let hits = scanSelf(patterns)
    print("── \(title)")
    for p in patterns {
        let h = hits[p.name] ?? []
        let mark = h.isEmpty ? "  clean " : "  FOUND "
        let detail = h.isEmpty ? "" : " ×\(h.count)  " + h.prefix(4).joined(separator: ", ")
        print("\(mark) \(p.name)\(detail)")
    }
}
