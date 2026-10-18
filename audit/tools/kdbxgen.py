#!/usr/bin/env python3
"""Minimal KDBX 4.0 writer for the Fleen security audit.

Independent of Fleen's code, so it can produce files Fleen's own tests never would:
hostile KDF parameters, decompression bombs, entity bombs, deep nesting, and
databases seeded with canary strings for memory-residue scans.

Every derived key is written to a sidecar JSON *XOR-obfuscated with 0x5A*, so the
Swift harness can search memory for the real bytes without ever holding them itself.

Usage: kdbxgen.py <spec.json> <out.kdbx>
"""
import base64, gzip, hashlib, hmac, io, json, os, struct, sys, uuid, zlib

from argon2.low_level import hash_secret_raw, Type
from Cryptodome.Cipher import AES, ChaCha20

AES_UUID = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
CHACHA_UUID = bytes.fromhex("d6038a2b8b6f4cb5a524339a31dbb59a")
AESKDF_UUID = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")
ARGON2D_UUID = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
ARGON2ID_UUID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")


def vd(items):
    out = struct.pack("<H", 0x0100)
    for typ, key, val in items:
        k = key.encode()
        if typ == 0x04: v = struct.pack("<I", val)
        elif typ == 0x05: v = struct.pack("<Q", val)
        elif typ == 0x42: v = val
        else: raise ValueError(typ)
        out += struct.pack("<BI", typ, len(k)) + k + struct.pack("<I", len(v)) + v
    return out + b"\x00"


def field(fid, data):
    return struct.pack("<BI", fid, len(data)) + data


def obf(b):
    return bytes(x ^ 0x5A for x in b).hex()


def build(spec):
    pw = spec.get("password", "")
    seed = os.urandom(32)
    salt = os.urandom(32)
    cipher = spec.get("cipher", "aes")
    iv = os.urandom(16 if cipher == "aes" else 12)
    kdf = spec.get("kdf", {"type": "aeskdf", "rounds": 1000})

    if kdf["type"] == "aeskdf":
        kdf_items = [(0x42, "$UUID", AESKDF_UUID), (0x05, "R", kdf["rounds"]), (0x42, "S", salt)]
    else:
        u = ARGON2D_UUID if kdf["type"] == "argon2d" else ARGON2ID_UUID
        kdf_items = [(0x42, "$UUID", u), (0x42, "S", salt), (0x04, "P", kdf.get("p", 2)),
                     (0x05, "M", kdf.get("m", 1024 * 1024)), (0x05, "I", kdf.get("i", 2)),
                     (0x04, "V", 0x13)]
    kdf_items += [(t, k, v) for t, k, v in spec.get("extra_kdf_items", [])]

    header = struct.pack("<IIHH", 0x9AA2D903, 0xB54BFB67, 0, 4)
    header += field(2, AES_UUID if cipher == "aes" else CHACHA_UUID)
    header += field(3, struct.pack("<I", 1 if spec.get("gzip", True) else 0))
    header += field(4, seed)
    header += field(7, iv)
    header += field(11, vd(kdf_items))
    header += field(0, b"\r\n\r\n")

    composite = hashlib.sha256(hashlib.sha256(pw.encode()).digest()).digest()
    if spec.get("skip_kdf"):
        transformed = b"\x00" * 32  # header-only fuzz files: HMAC will simply fail
    elif kdf["type"] == "aeskdf":
        c = AES.new(salt, AES.MODE_ECB)
        t = composite
        for _ in range(kdf["rounds"]):
            t = c.encrypt(t)
        transformed = hashlib.sha256(t).digest()
    else:
        transformed = hash_secret_raw(composite, salt, kdf.get("i", 2), kdf.get("m", 1048576) // 1024,
                                      kdf.get("p", 2), 32,
                                      Type.D if kdf["type"] == "argon2d" else Type.ID, version=0x13)
    cipher_key = hashlib.sha256(seed + transformed).digest()
    hmac_seed = hashlib.sha512(seed + transformed + b"\x01").digest()

    def block_key(i):
        return hashlib.sha512(struct.pack("<Q", i) + hmac_seed).digest()

    header_mac = hmac.new(block_key(0xFFFFFFFFFFFFFFFF), header, hashlib.sha256).digest()

    # Inner stream: ChaCha20 (id 3).
    stream_key = os.urandom(64)
    d = hashlib.sha512(stream_key).digest()
    inner = ChaCha20.new(key=d[:32], nonce=d[32:44])

    def protect(s):
        return base64.b64encode(inner.encrypt(s.encode())).decode()

    xml = spec.get("raw_xml")
    if xml is None:
        xml = render_xml(spec, protect)
    xml_bytes = xml.encode() if isinstance(xml, str) else xml

    inner_header = field(1, struct.pack("<I", 3)) + field(2, stream_key)
    for att in spec.get("attachments", []):
        inner_header += field(3, b"\x01" + att.encode())
    inner_header += field(0, b"")
    plain = inner_header + xml_bytes

    if spec.get("raw_payload_b64"):
        plain = base64.b64decode(spec["raw_payload_b64"])
    if spec.get("gzip", True):
        level = spec.get("gzip_level", 6)
        co = zlib.compressobj(level, zlib.DEFLATED, 31)
        payload = co.compress(plain) + co.flush()
        if spec.get("gzip_bomb_mib"):
            payload = gzip_bomb(spec["gzip_bomb_mib"])
    else:
        payload = plain

    if cipher == "aes":
        pad = 16 - len(payload) % 16
        ct = AES.new(cipher_key, AES.MODE_CBC, iv).encrypt(payload + bytes([pad]) * pad)
    else:
        ct = ChaCha20.new(key=cipher_key, nonce=iv).encrypt(payload)

    body = b""
    bs = 1024 * 1024
    chunks = [ct[i:i + bs] for i in range(0, len(ct), bs)] + [b""]
    for i, chunk in enumerate(chunks):
        m = hmac.new(block_key(i), struct.pack("<Q", i) + struct.pack("<I", len(chunk)) + chunk,
                     hashlib.sha256).digest()
        body += m + struct.pack("<I", len(chunk)) + chunk

    out = header + hashlib.sha256(header).digest() + header_mac + body
    keys = {"composite": obf(composite), "transformed": obf(transformed),
            "cipherKey": obf(cipher_key), "hmacSeed": obf(hmac_seed),
            "innerStreamKey": obf(stream_key), "innerChaChaKey": obf(d[:32])}
    return out, keys


def gzip_bomb(mib):
    """A gzip member that inflates to `mib` MiB of zeros, built without holding it."""
    co = zlib.compressobj(9, zlib.DEFLATED, 31)
    chunk = b"\x00" * (1024 * 1024)
    parts = [co.compress(chunk) for _ in range(mib)]
    return b"".join(parts) + co.flush()


def b64uuid():
    return base64.b64encode(uuid.uuid4().bytes).decode()


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_xml(spec, protect):
    entries = []
    for e in spec.get("entries", []):
        fields = ""
        for k, v in e.get("fields", {}).items():
            fields += f"<String><Key>{esc(k)}</Key><Value>{esc(v)}</Value></String>"
        for k, v in e.get("protected", {}).items():
            fields += f'<String><Key>{esc(k)}</Key><Value Protected="True">{protect(v)}</Value></String>'
        entries.append(f"<Entry><UUID>{b64uuid()}</UUID>{fields}</Entry>")
    pre = spec.get("xml_prefix", "")
    comment = f"<!-- {spec['comment']} -->" if spec.get("comment") else ""
    return (f'<?xml version="1.0" encoding="utf-8" standalone="yes"?>{pre}'
            f"<KeePassFile>{comment}<Meta><Generator>audit</Generator></Meta><Root>"
            f"<Group><UUID>{b64uuid()}</UUID><Name>Root</Name>{''.join(entries)}</Group>"
            f"</Root></KeePassFile>")


if __name__ == "__main__":
    spec = json.load(open(sys.argv[1]))
    data, keys = build(spec)
    open(sys.argv[2], "wb").write(data)
    json.dump(keys, open(sys.argv[2] + ".keys.json", "w"))
    print(f"wrote {sys.argv[2]} ({len(data)} bytes)")
