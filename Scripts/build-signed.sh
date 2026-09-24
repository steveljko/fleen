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
APP_PROFILE="${FLEEN_PROFILE:-$HOME/Downloads/Fleen_macOS.provisionprofile}"

[[ -f "$APP_PROFILE" ]] || { echo "missing provisioning profile: $APP_PROFILE" >&2; exit 2; }

Scripts/build-app.sh --release \
    --sign "$IDENTITY" \
    --profile "$APP_PROFILE"

if [[ "${1:-}" == "--run" ]]; then
    pkill -f 'Fleen.app/Contents/MacOS/Fleen' 2>/dev/null || true
    sleep 1
    open build/Fleen.app
    echo "Launched. Look for the key icon in the menu bar."
fi
