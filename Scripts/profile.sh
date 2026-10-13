#!/bin/bash
# Profiles the engine: timing, peak memory, leaks, and a Time Profiler trace.
#
# PLAN.md asks for an Instruments pass before a phase is called done, because wall-clock
# numbers say nothing about allocation churn — the specific worry being redundant copies
# of decrypted data.
#
# Profiling needs its own entry point: `fleen-cli` reads passwords with getpass(), which
# cannot be driven unattended, and deliberately offers no other way in.
set -euo pipefail
cd "$(dirname "$0")/.."

FIXTURE="${1:-Tests/KdbxCoreTests/Fixtures/pkp-aes-argon2d.kdbx}"
ROUNDS="${2:-400}"
HARNESS=".build/profile-harness"

mkdir -p "$HARNESS/Sources/profile"
cat > "$HARNESS/Package.swift" <<PKG
// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "profile",
    platforms: [.macOS(.v14)],
    dependencies: [.package(path: "$(pwd)")],
    targets: [.executableTarget(name: "profile",
                                dependencies: [.product(name: "KdbxCore", package: "fleen")])]
)
PKG
cat > "$HARNESS/Sources/profile/main.swift" <<'MAIN'
import Foundation
import KdbxCore

// The fixture's password is public test data, so it can be inline here.
let path = CommandLine.arguments.dropFirst().first ?? ""
let rounds = CommandLine.arguments.dropFirst(2).first.flatMap(Int.init) ?? 400

var credentials = CompositeKey()
credentials.addPassword("correct horse battery staple")
let data = try Data(contentsOf: URL(fileURLWithPath: path))

var total = 0.0
for _ in 0..<rounds {
    let start = Date()
    let database = try KdbxFile.open(data: data, credentials: credentials)
    total += Date().timeIntervalSince(start)
    precondition(database.allEntries.count >= 0)   // keep the parse alive
}
print(String(format: "%d opens, mean %.2f ms", rounds, total / Double(rounds) * 1000))
MAIN

echo "==> Building the harness (release)"
(cd "$HARNESS" && swift build -c release >/dev/null)
BIN="$(cd "$HARNESS" && swift build -c release --show-bin-path)/profile"

echo "==> Timing and peak memory"
/usr/bin/time -l "$BIN" "$FIXTURE" "$ROUNDS" 2>&1 \
    | grep -E "opens, mean|maximum resident" \
    | sed 's/^ */    /' \
    | sed 's/\([0-9]*\)  maximum resident set size/peak RSS: \1 bytes/'

echo "==> Leak check"
leaks --atExit -- "$BIN" "$FIXTURE" 50 2>&1 | grep -E "leaks for" | sed 's/^/    /'

echo "==> Recording a Time Profiler trace"
TRACE="build/unlock.trace"
rm -rf "$TRACE"
mkdir -p build
xcrun xctrace record --template "Time Profiler" --output "$TRACE" \
    --launch -- "$BIN" "$FIXTURE" "$ROUNDS" 2>&1 | tail -1

echo
echo "Open the flame graph with:  open $TRACE"
