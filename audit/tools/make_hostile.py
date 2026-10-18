#!/usr/bin/env python3
"""Generates hostile .kdbx files for the parser/KDF/decompression fuzz pass.

Each file is written to <outdir>/hostile-<name>.kdbx. Valid-credential files use the
password "pw" so the harness reaches the deepest parsers.
"""
import json, os, struct, sys, hashlib

sys.path.insert(0, os.path.dirname(__file__))
import kdbxgen

out = sys.argv[1]
os.makedirs(out, exist_ok=True)


def write(name, spec):
    data, _ = kdbxgen.build(spec)
    open(f"{out}/hostile-{name}.kdbx", "wb").write(data)
    return data


base = {"password": "pw", "kdf": {"type": "aeskdf", "rounds": 10},
        "entries": [{"fields": {"Title": "t"}, "protected": {"Password": "p"}}]}

# --- KDF cost extremes (header is parsed before anything is authenticated) -------
fast = dict(base, skip_kdf=True)
write("argon2-max-allowed-p1", dict(fast, kdf={"type": "argon2d", "m": 1 << 30, "i": 64, "p": 1}))
write("argon2-max-allowed-p64", dict(fast, kdf={"type": "argon2d", "m": 1 << 30, "i": 64, "p": 64}))
write("argon2-over-memory", dict(fast, kdf={"type": "argon2d", "m": (1 << 30) + 1024, "i": 1, "p": 1}))
write("argon2-4GiB-header-limit", dict(fast, kdf={"type": "argon2d", "m": 4 << 30, "i": 1, "p": 1}))
write("argon2-huge-iter", dict(fast, kdf={"type": "argon2d", "m": 8192, "i": 1 << 40, "p": 1}))
write("argon2-p0", dict(fast, kdf={"type": "argon2d", "m": 65536, "i": 1, "p": 0}))
write("aeskdf-max-allowed", dict(fast, kdf={"type": "aeskdf", "rounds": 100_000_000}))
write("aeskdf-2^64", dict(fast, kdf={"type": "aeskdf", "rounds": (1 << 64) - 1}))

# --- decompression / XML bombs (valid credentials, so they reach the parsers) ----
write("gzip-bomb-1GiB", dict(base, gzip_bomb_mib=1024))
write("gzip-bomb-500MiB", dict(base, gzip_bomb_mib=500))
laughs = ('<!DOCTYPE KeePassFile [<!ENTITY a "aaaaaaaaaa">'
          + "".join(f'<!ENTITY {chr(98 + i)} "{("&" + chr(97 + i) + ";") * 10}">' for i in range(9))
          + "]>")
xml_bomb = ('<?xml version="1.0"?>' + laughs + '<KeePassFile><Meta></Meta><Root><Group><Name>Root</Name>'
            '<Entry><String><Key>Title</Key><Value>&j;</Value></String></Entry></Group></Root></KeePassFile>')
write("xml-billion-laughs", dict(base, raw_xml=xml_bomb))
xxe = ('<?xml version="1.0"?><!DOCTYPE KeePassFile [<!ENTITY x SYSTEM "file:///etc/hosts">]>'
       '<KeePassFile><Meta></Meta><Root><Group><Name>Root</Name><Entry><String><Key>Title</Key>'
       '<Value>XXE[&x;]</Value></String></Entry></Group></Root></KeePassFile>')
write("xml-xxe-file", dict(base, raw_xml=xxe))
deep = 200_000
nest = ('<?xml version="1.0"?><KeePassFile><Meta></Meta><Root>' + "<Group><Name>g</Name>" * deep
        + "</Group>" * deep + "</Root></KeePassFile>")
write("xml-deep-groups-200k", dict(base, raw_xml=nest))
deep_ok = 2_000
nest_ok = ('<?xml version="1.0"?><KeePassFile><Meta></Meta><Root>' + "<Group><Name>g</Name>" * deep_ok
           + "<Entry><String><Key>Title</Key><Value>bottom</Value></String></Entry>"
           + "</Group>" * deep_ok + "</Root></KeePassFile>")
write("xml-deep-groups-2k", dict(base, raw_xml=nest_ok))
many = dict(base, entries=[{"fields": {"Title": f"e{i}", "UserName": "u"}, "protected": {"Password": "p"}}
                           for i in range(100_000)])
write("entries-100k", many)
write("totp-digits-10", dict(base, entries=[{"fields": {
    "Title": "totp", "otp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10"}}]))
write("bad-protected-base64", dict(base, raw_xml='<?xml version="1.0"?><KeePassFile><Root><Group><Entry>'
      '<String><Key>Password</Key><Value Protected="True">!!!not-base64</Value></String></Entry></Group>'
      '</Root></KeePassFile>'))
write("history-nesting", dict(base, raw_xml='<?xml version="1.0"?><KeePassFile><Root><Group>'
      + "<Entry><History>" * 50_000 + "</History></Entry>" * 50_000 + "</Group></Root></KeePassFile>"))
write("url-file-scheme", dict(base, entries=[{"fields": {
    "Title": "evil", "URL": "file:///System/Applications/Calculator.app"}}]))

# --- structural damage to an otherwise valid file ----------------------------------
good = write("valid", base)
hdr_end = good.index(b"\x00\x04\x00\x00\x00\r\n\r\n") + 9
for cut in [0, 4, 8, 11, 12, 20, hdr_end - 1, hdr_end, hdr_end + 31, hdr_end + 63, hdr_end + 64, hdr_end + 99]:
    open(f"{out}/hostile-trunc-{cut}.kdbx", "wb").write(good[:cut])
# A header field claiming 0xFFFFFFFF bytes, and a payload block claiming 0xFFFFFFFF.
open(f"{out}/hostile-hdr-len-max.kdbx", "wb").write(good[:12] + bytes([2]) + b"\xff\xff\xff\xff" + good[17:])
blk = bytearray(good)
struct.pack_into("<I", blk, hdr_end + 64 + 32, 0xFFFFFFFF)
open(f"{out}/hostile-block-len-max.kdbx", "wb").write(bytes(blk))
print("ok")
