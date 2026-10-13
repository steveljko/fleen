#!/bin/bash
# Notarises and staples a release build, producing a .zip that opens cleanly on any Mac.
#
#     Scripts/notarize.sh                       # uses the stored keychain profile
#     Scripts/notarize.sh --profile fleen-notary
#
# WHY THIS IS SEPARATE FROM SIGNING
#   Signing proves who built the app. Notarisation is Apple scanning it and recording the
#   result, and without it Gatekeeper on *another* Mac refuses the app with "cannot be
#   opened because the developer cannot be verified" — even though the signature is
#   perfectly valid. On the machine that built it the quarantine bit is never set, so the
#   failure is invisible until someone else tries.
#
# ONE-TIME SETUP
#   Notarisation needs an app-specific password, stored in the keychain so it never
#   appears in a command line or in this file:
#
#     xcrun notarytool store-credentials fleen-notary \
#         --apple-id you@example.com --team-id 94WY2HW4JW --password <app-specific-password>
#
#   Create the app-specific password at appleid.apple.com, not your Apple ID password.
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE="${FLEEN_NOTARY_PROFILE:-fleen-notary}"
APP="build/Fleen.app"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) PROFILE="${2:?--profile needs a notarytool keychain profile}"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[[ -d "$APP" ]] || { echo "ERROR: $APP not found — run Scripts/build-signed.sh first" >&2; exit 2; }

# Notarisation requires a Developer ID signature and the hardened runtime. An Apple
# Development certificate is accepted by Gatekeeper locally but rejected by the service,
# so the mismatch is worth catching here rather than after a five-minute upload.
IDENTITY="$(codesign -dvv "$APP" 2>&1 | sed -n 's/^Authority=//p' | head -1)"
echo "==> Signed by: ${IDENTITY:-unknown}"
if [[ "$IDENTITY" != Developer\ ID\ Application* ]]; then
    echo "ERROR: notarisation needs a \"Developer ID Application\" certificate." >&2
    echo "       This bundle is signed with: ${IDENTITY:-nothing}" >&2
    echo "       Build it with: Scripts/build-app.sh --release --profile <profile> \\" >&2
    echo "                        --sign \"Developer ID Application: Name (TEAMID)\"" >&2
    exit 2
fi

if ! codesign -d --entitlements - "$APP" 2>/dev/null | grep -q "com.apple.security.app-sandbox"; then
    echo "WARNING: this bundle is not sandboxed — it was built without --profile." >&2
fi

echo "==> Zipping (ditto preserves the signature; zip(1) does not)"
ARCHIVE="build/Fleen-notarize.zip"
rm -f "$ARCHIVE"
/usr/bin/ditto -c -k --keepParent "$APP" "$ARCHIVE"

echo "==> Submitting to Apple (this usually takes a few minutes)"
xcrun notarytool submit "$ARCHIVE" --keychain-profile "$PROFILE" --wait

echo "==> Stapling the ticket to the bundle"
# Stapling matters: without it the app only passes on a Mac that can reach Apple to ask.
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

echo "==> Verifying the way Gatekeeper will see it"
spctl --assess --type execute --verbose=2 "$APP"

echo "==> Repacking the stapled bundle for distribution"
rm -f "$ARCHIVE"
/usr/bin/ditto -c -k --keepParent "$APP" "build/Fleen.zip"

echo
echo "Notarised and stapled: build/Fleen.zip"
