#!/bin/bash
# Build Heimdall.app (and the heimdall-scan CLI) with SwiftPM. No Xcode project, no root.
#   scripts/build-app.sh            # release build into ./build/Heimdall.app
#   scripts/build-app.sh --install  # …and copy it to ~/Applications
#
# Optional, for builds you hand to other people:
#   HEIMDALL_VERSION=1.2.0        stamp CFBundleShortVersionString (CFBundleVersion = git commit count)
#   DEVELOPER_ID="Developer ID Application: Name (TEAMID)"   sign with that identity instead of ad hoc
#   NOTARY_PROFILE=heimdall       also notarize and staple, using a profile saved with
#                                 `xcrun notarytool store-credentials heimdall`
# A signed build also writes build/Heimdall-<version>.zip for a GitHub release.
set -euo pipefail
cd "$(dirname "$0")/.."

swift build -c release
BIN="$(swift build -c release --show-bin-path)"
APP=build/Heimdall.app

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/Heimdall" "$APP/Contents/MacOS/Heimdall"
cp "$BIN/heimdall-scan" build/heimdall-scan
cp Resources/Info.plist "$APP/Contents/Info.plist"
if [ -n "${HEIMDALL_VERSION:-}" ]; then
  plutil -replace CFBundleShortVersionString -string "${HEIMDALL_VERSION#v}" "$APP/Contents/Info.plist"
  plutil -replace CFBundleVersion -string "$(git rev-list --count HEAD 2>/dev/null || echo 1)" "$APP/Contents/Info.plist"
fi
cp Resources/AppIcon.png Resources/AppIconAlert.png "$APP/Contents/Resources/"   # normal + red (something exploited) Dock icons

# App icon from the 1024 px master.
if [ -f Resources/AppIcon.png ]; then
  ICONSET="$(mktemp -d)/AppIcon.iconset"
  mkdir -p "$ICONSET"
  for s in 16 32 128 256 512; do
    sips -z $s $s Resources/AppIcon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    sips -z $((s*2)) $((s*2)) Resources/AppIcon.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
fi

# Hardened runtime, no entitlements: Heimdall isn't sandboxed (it has to run `brew` and read
# your home folder) and asks for no special permissions. Ad hoc unless DEVELOPER_ID is set.
if [ -n "${DEVELOPER_ID:-}" ]; then
  codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp "$APP"
  codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp build/heimdall-scan
  codesign --verify --strict --deep "$APP"
else
  codesign --force --sign - --options runtime --timestamp=none "$APP"
  codesign --force --sign - --options runtime --timestamp=none build/heimdall-scan
fi

if [ -n "${DEVELOPER_ID:-}" ]; then
  VERSION="$(plutil -extract CFBundleShortVersionString raw "$APP/Contents/Info.plist")"
  ZIP="build/Heimdall-$VERSION.zip"
  rm -f "$ZIP"
  ditto -c -k --keepParent "$APP" "$ZIP"
  if [ -n "${NOTARY_PROFILE:-}" ]; then
    xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$APP"
    rm -f "$ZIP"; ditto -c -k --keepParent "$APP" "$ZIP"   # re-zip with the ticket stapled
    spctl --assess --type execute --verbose "$APP"
  fi
  echo "Release archive: $ZIP"
fi

echo "Built $APP and build/heimdall-scan"
if [ "${1:-}" = "--install" ]; then
  mkdir -p "$HOME/Applications"
  rm -rf "$HOME/Applications/Heimdall.app"
  cp -R "$APP" "$HOME/Applications/"
  echo "Installed to ~/Applications/Heimdall.app"
fi
