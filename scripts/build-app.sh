#!/bin/bash
# Build Heimdall.app (and the heimdall-scan CLI) with SwiftPM. No Xcode project, no root.
#   scripts/build-app.sh            # release build into ./build/Heimdall.app
#   scripts/build-app.sh --install  # …and copy it to ~/Applications
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

# Ad-hoc signature with the hardened runtime. No entitlements: Heimdall isn't sandboxed
# (it has to run `brew` and read your home folder) and asks for no special permissions.
codesign --force --sign - --options runtime --timestamp=none "$APP"
codesign --force --sign - --options runtime --timestamp=none build/heimdall-scan

echo "Built $APP and build/heimdall-scan"
if [ "${1:-}" = "--install" ]; then
  mkdir -p "$HOME/Applications"
  rm -rf "$HOME/Applications/Heimdall.app"
  cp -R "$APP" "$HOME/Applications/"
  echo "Installed to ~/Applications/Heimdall.app"
fi
