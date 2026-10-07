#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${TUNNELDECK_APP_PATH:-$HOME/Applications/TunnelDeck.app}"
INFO_PLIST="$ROOT/Sources/TunnelDeck/Resources/Info.plist"

cd "$ROOT"

echo "== Tests =="
swift test

echo
echo "== Release build =="
swift build -c release

BINARY="$ROOT/.build/release/TunnelDeck"

if [[ ! -x "$BINARY" ]]; then
  echo "Release binary was not produced at $BINARY"
  exit 3
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/TunnelDeck.local.app.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources"

cp "$BINARY" "$STAGE/Contents/MacOS/TunnelDeck"
cp "$INFO_PLIST" "$STAGE/Contents/Info.plist"

chmod 0755 "$STAGE/Contents/MacOS/TunnelDeck"

/usr/bin/codesign \
  --force \
  --deep \
  --sign - \
  --timestamp=none \
  "$STAGE" >/dev/null

/usr/bin/pkill -x TunnelDeck 2>/dev/null || true

mkdir -p "$(dirname "$TARGET")"
rm -rf "$TARGET"

/usr/bin/ditto "$STAGE" "$TARGET"

echo
echo "Installed local TunnelDeck build to:"
echo "$TARGET"

open "$TARGET"
