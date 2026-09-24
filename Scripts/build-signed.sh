#!/bin/bash
# Builds the fully provisioned app: sandboxed, with Touch ID enforced by the Keychain.
#
# The provisioning profile is what makes the data-protection Keychain available, which is
# what gives the biometric gate real OS enforcement rather than app-level enforcement.
#
#     Scripts/build-signed.sh            build
#     Scripts/build-signed.sh --run      build, then launch it
#
# Override any of these with environment variables if they change.
set -euo pipefail
cd "$(dirname "$0")/.."

IDENTITY="${FLEEN_IDENTITY:-Apple Development: vekstevic@icloud.com (SJF6JX9J6F)}"
# Looked for in a stable location first, then the browser's download folder. Keeping it
# only in ~/Downloads meant a tidy-up silently broke the signed build — and, because the
# script exits non-zero while `build/Fleen.app` still holds the previous build, the next
# careless `ditto` installs a stale app that looks fine.
PROFILE_CANDIDATES=(
    "${FLEEN_PROFILE:-}"
    "$HOME/Library/Developer/Fleen/Fleen_macOS.provisionprofile"
    "$HOME/Downloads/Fleen_macOS.provisionprofile"
)
APP_PROFILE=""
for candidate in "${PROFILE_CANDIDATES[@]}"; do
    [[ -n "$candidate" && -f "$candidate" ]] || continue
    APP_PROFILE="$candidate"
    break
done

if [[ -z "$APP_PROFILE" ]]; then
    echo "ERROR: no provisioning profile found. Looked in:" >&2
    for candidate in "${PROFILE_CANDIDATES[@]}"; do
        [[ -n "$candidate" ]] && echo "         $candidate" >&2
    done
    echo "       A copy is embedded in any previously signed build; recover it with:" >&2
    echo "         mkdir -p ~/Library/Developer/Fleen && \\" >&2
    echo "           cat /Applications/Fleen.app/Contents/embedded.provisionprofile \\" >&2
    echo "           > ~/Library/Developer/Fleen/Fleen_macOS.provisionprofile" >&2
    exit 2
fi
echo "==> Profile: $APP_PROFILE"

Scripts/build-app.sh --release \
    --sign "$IDENTITY" \
    --profile "$APP_PROFILE"

if [[ "${1:-}" == "--run" ]]; then
    pkill -f 'Fleen.app/Contents/MacOS/Fleen' 2>/dev/null || true
    sleep 1
    open build/Fleen.app
    echo "Launched. Look for the key icon in the menu bar."
fi
