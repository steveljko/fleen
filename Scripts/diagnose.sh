#!/bin/bash
# Answers "is it actually running?" for an app that has no Dock icon and no window.
set -uo pipefail
cd "$(dirname "$0")/.."

echo "== Fleen diagnostics =="
echo

if [[ ! -d build/Fleen.app ]]; then
    echo "✗ build/Fleen.app does not exist — run Scripts/build-app.sh first"
    exit 1
fi
echo "✓ build/Fleen.app exists"

if codesign --verify --deep --strict build/Fleen.app 2>/dev/null; then
    echo "✓ signature valid"
else
    echo "✗ signature invalid — re-run Scripts/build-app.sh"
fi

PID="$(pgrep -f 'Fleen.app/Contents/MacOS/Fleen' | head -1)"
if [[ -n "$PID" ]]; then
    echo "✓ running (pid $PID)"
    echo
    echo "It IS running. Fleen has no Dock icon by design — look for a key icon"
    echo "in the menu bar, top right. If the menu bar is crowded (or you are on a"
    echo "MacBook with a notch), the icon may be hidden: quit some other menu bar"
    echo "apps, or run with a Dock icon instead:"
    echo
    echo "    defaults write com.fleen.Fleen showInDock -bool true"
    echo "    pkill -f Fleen.app && open build/Fleen.app"
else
    echo "✗ not running"
    echo
    echo "Launching with diagnostics; press Ctrl-C to stop:"
    echo
    FLEEN_DIAG=1 ./build/Fleen.app/Contents/MacOS/Fleen
fi
