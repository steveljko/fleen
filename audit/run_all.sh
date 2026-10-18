#!/bin/bash
# Re-runs every dynamic check from SECURITY_AUDIT.md. Throwaway passwords only.
#   python3 -m venv .venv && .venv/bin/pip install pykeepass==4.1.1.post1
set -uo pipefail
cd "$(dirname "$0")"
PY="${PY:-.venv/bin/python}"
B=Harness/.build/release/fleen-audit
o() { python3 -c "import sys;print(bytes(b^0x5A for b in sys.argv[1].encode()).hex())" "$1"; }

# Clean first: SwiftPM does not reliably notice edits inside a path dependency, and a
# stale harness silently tests the old engine.
(cd Harness && swift package clean && swift build -c release 2>&1 | grep -E "error|Build complete")
mkdir -p out/hostile

for v in "aes-aeskdf-gz:aes:aeskdf:true" "chacha-argon2d-gz:chacha:argon2d:true" \
         "aes-aeskdf-plain:aes:aeskdf:false" "chacha-aeskdf-gz:chacha:aeskdf:true"; do
  IFS=: read -r name cipher kdf gz <<<"$v"
  "$PY" - "$name" "$cipher" "$kdf" "$gz" <<'EOF'
import json, sys
name, cipher, kdf, gz = sys.argv[1:]
s = json.load(open("specs/canary-base.json"))
s["cipher"] = cipher; s["gzip"] = gz == "true"
s["kdf"] = {"type": "aeskdf", "rounds": 20000} if kdf == "aeskdf" else {"type": "argon2d", "m": 16 << 20, "i": 2, "p": 2}
json.dump(s, open(f"specs/canary-{name}.json", "w"))
EOF
  "$PY" tools/kdbxgen.py "specs/canary-$name.json" "out/canary-$name.kdbx" >/dev/null
done
"$PY" tools/kdbxgen.py specs/slow.json out/slow.kdbx >/dev/null
"$PY" tools/kdbxgen.py specs/other.json out/other.kdbx >/dev/null
"$PY" tools/make_hostile.py out/hostile >/dev/null

PW=$(o FleenAuditCanary-91827); EP=$(o FleenEntryCanary-40417)
NO=$(o FleenNotesCanary-55031); CM=$(o FleenXmlCommentCanary-77123)

echo "#### zero-on-free probe";       $B zerofree
echo "#### XMLParser residue";        $B xmlprobe whole
for n in aes-aeskdf-gz aes-aeskdf-plain chacha-argon2d-gz; do
  echo "#### engine memscan $n"
  $B memscan-engine "out/canary-$n.kdbx" "out/canary-$n.kdbx.keys.json" "$PW" "$EP" "$NO" "$CM" | grep -E "──|FOUND"
  echo "#### session memscan $n"
  $B memscan-session "out/canary-$n.kdbx" "out/canary-$n.kdbx.keys.json" "$PW" "$EP" "$NO" "$CM" | grep -E "──|FOUND|types"
done
echo "#### F-10 precomposed";  $B precomposed out/canary-chacha-argon2d-gz.kdbx out/canary-chacha-argon2d-gz.kdbx.keys.json
echo "#### F-03 race lock";    $B race out/slow.kdbx "$PW" lock
echo "#### F-03 race select";  $B race out/slow.kdbx "$PW" select out/other.kdbx
echo "#### F-05 clipboard";    $B clipboard
echo "#### F-07 totp";         for d in 9 10; do $B totp $d; echo "exit=$?"; done
echo "#### fuzz (password 'pw')"
P=$(o pw)
for f in out/hostile/*.kdbx; do
  r=$(perl -e 'alarm shift; exec @ARGV' 180 "$B" open "$f" "$P" 2>&1 | tail -1); ec=${PIPESTATUS[0]}
  printf "%-40s exit=%-3s %s\n" "$(basename "$f" .kdbx)" "$ec" "${r:0:150}"
done
rm -f ~/Library/Preferences/audit.fleen.*.plist   # harness test-defaults stubs
