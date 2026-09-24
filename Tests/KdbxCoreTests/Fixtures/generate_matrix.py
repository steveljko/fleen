"""Generates the cipher/KDF matrix fixtures plus the content edge cases.

Uses pykeepass (an independent KDBX implementation) so that a shared bug with
KeePassXC would still show up as a cross-implementation disagreement.
"""
import os
import uuid as _uuid
from construct import Container
from lxml.etree import SubElement
from pykeepass import create_database

# pykeepass exposes cipher/KDF as read-only properties, so the matrix is produced by
# editing the parsed header directly before `save()` re-encrypts with it.
PW = "correct horse battery staple"
HERE = os.path.dirname(os.path.abspath(__file__))

CIPHERS = {"aes256": 16, "chacha20": 12}
KDF_UUID = {
    "argon2d":  _uuid.UUID("ef636ddf-8c29-444b-91f7-a9a403e30a0c").bytes,
    "argon2id": _uuid.UUID("9e298b19-56db-4773-b23d-fc3ec6f0a1e6").bytes,
    "aeskdf":   _uuid.UUID("c9d9f39a-628a-4460-bf74-0d08c18a4fea").bytes,
}


def _relink(d):
    """Repairs pykeepass's `next_byte` chain after the dictionary is edited.

    Its VariantDictionary parser stores, on each entry, the type byte of the entry
    that *follows* it, with 0 on the last one. Adding or removing keys without
    rebuilding that chain produces a header KeePassXC rejects outright.
    """
    items = list(d.values())
    for i, item in enumerate(items):
        item.next_byte = items[i + 1].type if i + 1 < len(items) else 0


def retarget(kp, cipher, kdf):
    dh = kp.kdbx.header.value.dynamic_header
    dh.cipher_id.data = cipher
    dh.encryption_iv.data = os.urandom(CIPHERS[cipher])

    d = dh.kdf_parameters.data.dict
    d["$UUID"].value = KDF_UUID[kdf]
    if kdf == "aeskdf":
        for k in ("I", "M", "P", "V"):
            d.pop(k, None)
        d["S"] = Container(type=66, key="S", value=os.urandom(32), next_byte=0)
        # Kept low so the suite stays fast; real databases use millions of rounds,
        # which the reader handles identically, just slowly.
        d["R"] = Container(type=5, key="R", value=6000, next_byte=0)
    else:
        d.pop("R", None)
        d["I"] = Container(type=5, key="I", value=2, next_byte=0)
        d["M"] = Container(type=5, key="M", value=1 << 20, next_byte=0)
        d["P"] = Container(type=4, key="P", value=2, next_byte=0)
        d["S"] = Container(type=66, key="S", value=os.urandom(32), next_byte=0)
        d["V"] = Container(type=4, key="V", value=0x13, next_byte=0)
    _relink(d)


MATRIX = [
    ("pkp-aes-argon2d.kdbx",       "aes256",   "argon2d"),
    ("pkp-aes-argon2id.kdbx",      "aes256",   "argon2id"),
    ("pkp-chacha20-argon2d.kdbx",  "chacha20", "argon2d"),
    ("pkp-chacha20-argon2id.kdbx", "chacha20", "argon2id"),
    ("pkp-aes-aeskdf.kdbx",        "aes256",   "aeskdf"),
    ("pkp-chacha20-aeskdf.kdbx",   "chacha20", "aeskdf"),
]


def populate(kp):
    """Content chosen to exercise the parser's awkward corners."""
    group = kp.add_group(kp.root_group, "Personal")
    sub = kp.add_group(group, "Nested → Gruppe")

    e = kp.add_entry(group, "Example Entry", "alice@example.com",
                     "s3cret-pass-value", url="https://example.com",
                     notes="Line one\nLine two")
    e.tags = ["work", "email"]
    # Custom fields, one protected and one not.
    e.set_custom_property("API Token", "tok_live_abc123", protect=True)
    e.set_custom_property("Account ID", "12345", protect=False)

    # XML metacharacters and non-BMP characters in both plain and protected fields.
    # Created under a plain title first: pykeepass runs a duplicate-lookup XPath on
    # every add_entry and that XPath cannot cope with quotes, so the awkward strings
    # are assigned afterwards.
    meta = kp.add_entry(sub, "metachars", "placeholder", "placeholder")
    meta.title = "Ampersand & <angle> \"quotes\" 'apos'"
    meta.username = "u<ser>&"
    meta.password = "p&ss<w>\"o'rd"
    meta.url = "https://example.com/?a=1&b=2"
    meta.notes = "emoji \U0001F511 and \u00e4\u00f6\u00fc \u4e2d\u6587"

    # An entry with an empty password and empty username.
    kp.add_entry(group, "Empty Fields", "", "")

    # TOTP, in the otp-URI form KeePassXC writes.
    t = kp.add_entry(group, "TOTP Entry", "totpuser", "totppass")
    # "otp" is a reserved key in pykeepass, so the field is appended to the XML
    # directly — this is the shape KeePassXC itself writes.
    string = SubElement(t._element, "String")
    SubElement(string, "Key").text = "otp"
    SubElement(string, "Value").text = (
        "otpauth://totp/TOTP%20Entry?secret=JBSWY3DPEHPK3PXP&period=30&digits=6")

    # The older KeePassXC pair-of-fields form, which the reader composes into a URI.
    t2 = kp.add_entry(group, "TOTP Legacy", "legacyuser", "legacypass")
    t2.set_custom_property("TOTP Seed", "JBSWY3DPEHPK3PXP", protect=True)
    t2.set_custom_property("TOTP Settings", "30;6", protect=False)

    # Expiry.
    import datetime
    x = kp.add_entry(group, "Expired Entry", "old", "oldpass")
    x.expires = True
    x.expiry_time = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)

    # Attachment, including binary (non-UTF-8) content.
    att_id = kp.add_binary(bytes(range(256)) * 8)
    e.add_attachment(att_id, "bytes.bin")
    txt_id = kp.add_binary("hello attachment\n".encode("utf-8"))
    e.add_attachment(txt_id, "notes.txt")


for filename, cipher, kdf in MATRIX:
    path = os.path.join(HERE, filename)
    kp = create_database(path, password=PW)
    populate(kp)
    retarget(kp, cipher, kdf)
    kp.save()
    print(f"  {filename:32s} {cipher:9s} {kdf}")

# A database with a populated recycle bin, for the "show deleted entries" setting.
# pykeepass creates the bin on the first trash operation and points Meta at it, which
# is exactly the shape a real KeePassXC database has.
path = os.path.join(HERE, "pkp-recyclebin.kdbx")
kp = create_database(path, password=PW)
live = kp.add_group(kp.root_group, "Live")
kp.add_entry(live, "Keeper", "keeper@example.com", "keep-me")
doomed = kp.add_entry(live, "Deleted Entry", "gone@example.com", "deleted-pass")
extra = kp.add_entry(live, "Also Deleted", "gone2@example.com", "deleted-pass-2")
kp.trash_entry(doomed)
kp.trash_entry(extra)
retarget(kp, "aes256", "argon2d")
kp.save()
print(f"  pkp-recyclebin.kdbx              1 live entry, 2 trashed")

# Key file variants, as KDBX4 this time. pykeepass reads both key file formats,
# so the raw 32-byte file and the KeePassXC-generated v2 XML file both get a
# database to unlock.
for filename, keyfile, password in [
    ("pkp-keyfile-raw.kdbx", "keyfile.key", PW),
    ("pkp-keyfile-xml.kdbx", "keyfile-v2.keyx", PW),
    ("pkp-keyfile-only.kdbx", "keyfile.key", None),
]:
    path = os.path.join(HERE, filename)
    kp = create_database(path, password=password,
                         keyfile=os.path.join(HERE, keyfile))
    kp.add_entry(kp.root_group, "Example Entry", "alice@example.com",
                 "s3cret-pass-value", url="https://example.com")
    retarget(kp, "aes256", "argon2d")
    kp.save()
    print(f"  {filename:32s} keyfile={keyfile} password={'yes' if password else 'no'}")

# A deliberately larger database, for the search/parse performance test.
big = os.path.join(HERE, "pkp-large.kdbx")
kp = create_database(big, password=PW)
g = kp.add_group(kp.root_group, "Bulk")
for i in range(2000):
    kp.add_entry(g, f"Entry {i:05d}", f"user{i}@example.com", f"password-{i}",
                 url=f"https://site{i % 250}.example.com")
retarget(kp, "aes256", "argon2d")
kp.save()
print(f"  pkp-large.kdbx                   2000 entries")
