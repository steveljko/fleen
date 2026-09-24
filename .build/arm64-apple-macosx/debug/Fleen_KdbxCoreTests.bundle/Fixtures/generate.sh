#!/bin/bash
# Regenerates the test fixtures. Run from the repo root:
#     KP_VENV=/path/to/venv Tests/KdbxCoreTests/Fixtures/generate.sh
#
# How the two generators are used, and why:
#
#  * pykeepass writes the KDBX4 read fixtures. It is an independent implementation,
#    so a bug we share with it would still have to be a bug both projects made.
#    It is the only one of the two that can emit KDBX4 at all from a script.
#
#  * keepassxc-cli's db-create only produces KDBX 3.1, so it cannot supply v4 read
#    fixtures. Its authoritative role is on the *write* side instead: the interop
#    test in KdbxInteropTests hands it a database our writer produced and checks it
#    reads back the right values. That exercises header, KDF parameters, HMAC
#    framing, cipher and inner stream in one go, against the reference app.
#    Its 3.1 output is kept here as the fixture proving we reject v3 cleanly.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/Applications/KeePassXC.app/Contents/MacOS:$PATH"
PW="correct horse battery staple"
VENV="${KP_VENV:?set KP_VENV to the pykeepass virtualenv}"

rm -f ./*.kdbx ./*.key ./*.keyx

echo "==> keepassxc-cli: KDBX 3.1, kept as the 'unsupported version' fixture"
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create -q -p -t 100 kdbx3-legacy.kdbx

echo "==> key files"
# Raw 32-byte key file.
head -c 32 /dev/urandom > keyfile.key
# KeePassXC generates a v2 XML key file when pointed at a path that does not exist.
# The database it makes alongside is 3.1 and thrown away; the key file is the point.
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create -q -p -t 100 \
    --set-key-file keyfile-v2.keyx _throwaway.kdbx
rm -f _throwaway.kdbx

echo "==> pykeepass: KDBX4 matrix, key file variants, content edge cases"
"$VENV/bin/python" ./generate_matrix.py

# FleenKitTests needs a couple of these too (the recycle bin setting is tested against
# a real database). Copy rather than share a directory, so SwiftPM resource bundling
# stays simple and each test target declares what it uses.
echo "==> Syncing the fixtures FleenKitTests borrows"
mkdir -p ../../FleenKitTests/Fixtures
cp pkp-recyclebin.kdbx pkp-aes-argon2d.kdbx ../../FleenKitTests/Fixtures/

ls -la ./*.kdbx ./*.key ./*.keyx
