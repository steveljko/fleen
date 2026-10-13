#!/bin/bash
# Assembles Fleen.app from the SwiftPM products and signs it.
#
#   Scripts/build-app.sh                       debug, dev-signed, development entitlements
#   Scripts/build-app.sh --release
#   Scripts/build-app.sh --release --sign "Apple Development: …" \
#       --profile ~/Downloads/Fleen_macOS.provisionprofile
#
# Fleen is a single sandboxed read-only app: one binary, no extensions, no helper
# tools. Browsing, search, TOTP and clipboard copy all work from an unsigned build;
# a provisioning profile is needed only for the App Sandbox plus data-protection
# Keychain combination that gives Touch ID an OS-enforced gate.
set -euo pipefail
# pipefail matters here: codesign output is piped through sed, and without it a
# signing failure would be masked by sed succeeding.
cd "$(dirname "$0")/.."

CONFIG=debug
IDENTITY="-"
SIGNED=0
PROFILE="${FLEEN_PROFILE:-}"

# A stable signing identity matters more than it looks. macOS ties Keychain access to
# a *code signature*, not to a path. An ad-hoc signature ("-") is just a hash of the
# binary, so every rebuild produces a new identity and silently invalidates the grant:
# a Touch ID key enrolled before a rebuild is unreadable after it. Signing with a
# certificate, even a self-signed one, keeps the identity stable across rebuilds.
#
# Create one once (Keychain Access › Certificate Assistant › Create a Certificate…,
# name "Fleen Development", type "Code Signing", self-signed), then it is picked up
# automatically here. See the README.
DEV_IDENTITY="${FLEEN_SIGN_IDENTITY:-Fleen Development}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release) CONFIG=release; shift ;;
        --debug)   CONFIG=debug;   shift ;;
        --sign)
            IDENTITY="${2:?--sign needs an identity}"
            SIGNED=1
            shift 2 ;;
        --profile)
            PROFILE="${2:?--profile needs a path to a .provisionprofile}"
            shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

BUNDLE_ID="com.fleen.Fleen"

# Prefer a local development certificate over ad-hoc when one exists.
if [[ $SIGNED -eq 0 ]] && security find-identity -v -p codesigning 2>/dev/null \
        | grep -qF "$DEV_IDENTITY"; then
    IDENTITY="$DEV_IDENTITY"
    STABLE_IDENTITY=1
else
    STABLE_IDENTITY=0
fi

mkdir -p build/entitlements

# App Sandbox and the data-protection Keychain are *restricted* entitlements: they may
# only be claimed by a bundle carrying a matching provisioning profile. Sign them
# without one and the signature verifies fine while launchd refuses to spawn the app:
#
#     Launch failed. … NSPOSIXErrorDomain Code=163 "Launchd job spawn failed"
#
# So they are used only when a profile is supplied. Otherwise the development
# entitlements are used regardless of signing identity, which always launches.
validate_profile() {
    local path="$1"
    local plist="build/entitlements/profile.plist"
    if ! security cms -D -i "$path" -o "$plist" 2>/dev/null; then
        echo "ERROR: could not read provisioning profile: $path" >&2
        exit 2
    fi
    # Match the application-identifier exactly rather than grepping for the bundle id:
    # a profile for "com.fleen.Fleen.AutoFill" *contains* "com.fleen.Fleen", so a
    # substring test would accept a profile for a different bundle and hand back an
    # app that launchd refuses to start.
    local app_id
    app_id="$(plutil -extract 'Entitlements.com\.apple\.application-identifier' raw \
        -o - "$plist" 2>/dev/null || true)"
    if [[ -z "$app_id" ]]; then
        echo "ERROR: profile has no application-identifier: $path" >&2
        exit 2
    fi
    # Strip the leading team id prefix ("TEAMID.com.fleen.Fleen").
    if [[ "${app_id#*.}" != "$BUNDLE_ID" ]]; then
        echo "ERROR: profile is for '${app_id#*.}', not $BUNDLE_ID" >&2
        exit 2
    fi
    echo "==> Validated profile: $(basename "$path") ($app_id)"
}

USE_FULL_ENTITLEMENTS=0
if [[ -n "$PROFILE" ]]; then
    [[ -f "$PROFILE" ]] || { echo "provisioning profile not found: $PROFILE" >&2; exit 2; }
    validate_profile "$PROFILE"
    USE_FULL_ENTITLEMENTS=1
fi

echo "==> Building ($CONFIG)"
swift build -c "$CONFIG" --product Fleen

BIN_PATH="$(swift build -c "$CONFIG" --show-bin-path)"
APP="build/Fleen.app"

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_PATH/Fleen" "$APP/Contents/MacOS/Fleen"

# The icon is committed as a built .icns; Scripts/make-icon.swift regenerates it from
# code, so it can be changed without a design tool in the loop.
if [[ -f Resources/Fleen.icns ]]; then
    cp Resources/Fleen.icns "$APP/Contents/Resources/Fleen.icns"
else
    echo "    NOTE: Resources/Fleen.icns missing — building without an app icon." >&2
fi

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Fleen</string>
    <key>CFBundleDisplayName</key><string>Fleen</string>
    <key>CFBundleExecutable</key><string>Fleen</string>
    <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleSignature</key><string>????</string>
    <key>CFBundleSupportedPlatforms</key>
    <array><string>MacOSX</string></array>

    <!-- Menu bar utility: no Dock icon, no app switcher entry. -->
    <key>LSUIElement</key><true/>

    <!-- Shown in the Touch ID prompt when unlocking with biometrics. -->
    <key>NSFaceIDUsageDescription</key>
    <string>Fleen uses biometrics to unlock your password vault.</string>

    <key>CFBundleIconFile</key><string>Fleen</string>

    <key>NSHumanReadableCopyright</key><string>Local-only KeePass client.</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

if [[ $USE_FULL_ENTITLEMENTS -eq 1 ]]; then
    cp Resources/Fleen.entitlements build/entitlements/app.plist
    cat "$PROFILE" > "$APP/Contents/embedded.provisionprofile"
else
    cp Resources/Fleen.dev.entitlements build/entitlements/app.plist
fi

echo "==> Signing (identity: $IDENTITY)"
codesign --force --sign "$IDENTITY" \
    --entitlements build/entitlements/app.plist \
    --options runtime --timestamp=none "$APP" 2>&1 | sed 's/^/    /'

# Catch the unlaunchable combination before the user discovers it as error 163.
if [[ $USE_FULL_ENTITLEMENTS -eq 0 ]] \
   && codesign -d --entitlements - "$APP" 2>/dev/null \
        | grep -q "com.apple.security.app-sandbox"; then
    echo "ERROR: the bundle claims restricted entitlements with no provisioning" >&2
    echo "       profile embedded. launchd would refuse to start it." >&2
    exit 1
fi

echo
echo "Built $APP"
if [[ $SIGNED -eq 1 && $USE_FULL_ENTITLEMENTS -eq 0 ]]; then
    echo
    echo "  NOTE: signed with '$IDENTITY', but using DEVELOPMENT entitlements."
    echo "        The App Sandbox requires a provisioning profile; without one macOS"
    echo "        refuses to launch the app with “Launchd job spawn failed”"
    echo "        (POSIX error 163). Touch ID then falls back to app-enforced mode."
    echo "        Pass --profile /path/to/embedded.provisionprofile to enable them."
fi
if [[ $SIGNED -eq 0 ]]; then
    if [[ $STABLE_IDENTITY -eq 1 ]]; then
        echo "  Signed with '$DEV_IDENTITY' - Keychain items survive rebuilds."
    else
        echo
        echo "  NOTE: ad-hoc signed. macOS ties Keychain access to the code signature, and an"
        echo "        ad-hoc signature changes on every rebuild — so a Touch ID key enrolled"
        echo "        now will not be readable after the next rebuild."
        echo
        echo "        Fix it once: Keychain Access › Certificate Assistant › Create a"
        echo "        Certificate…, name it \"Fleen Development\", set Certificate Type to"
        echo "        \"Code Signing\", self-signed. This script then uses it automatically."
    fi
fi
echo
echo "Run it with:  open $APP"
