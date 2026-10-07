#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${TUNNELDECK_APP_PATH:-$HOME/Applications/TunnelDeck.app}"
INFO_PLIST="$ROOT/Sources/TunnelDeck/Resources/Info.plist"

cd "$ROOT"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "TunnelDeck source tree has local changes; refusing to overwrite them."
  exit 2
fi

git switch main
git pull --ff-only origin main

swift build -c release

BINARY="$ROOT/.build/release/TunnelDeck"
if [[ ! -x "$BINARY" ]]; then
  echo "Release binary was not produced at $BINARY"
  exit 3
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/TunnelDeck.app.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources"
cp "$BINARY" "$STAGE/Contents/MacOS/TunnelDeck"
cp "$INFO_PLIST" "$STAGE/Contents/Info.plist"
chmod 0755 "$STAGE/Contents/MacOS/TunnelDeck"

/usr/bin/codesign --force --deep --sign - --timestamp=none "$STAGE" >/dev/null

/usr/bin/pkill -x TunnelDeck 2>/dev/null || true
mkdir -p "$(dirname "$TARGET")"
rm -rf "$TARGET"
/usr/bin/ditto "$STAGE" "$TARGET"

# Old repository-local app bundles are build artifacts, not installed copies.
rm -rf "$ROOT/dist/TunnelDeck.app"

echo "Installed latest TunnelDeck to: $TARGET"
open "$TARGET"
