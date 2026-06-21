#!/usr/bin/env bash
# pull_btsnoop.sh - grab the Android Bluetooth HCI snoop log via adb (no root).
#
# Requires: adb (android-platform-tools) on PATH, USB debugging enabled on the
# phone. Runs `adb bugreport`, extracts the btsnoop log, and drops it in
# captures/. Usage:
#     tools/pull_btsnoop.sh [output_name]
# e.g. tools/pull_btsnoop.sh btsnoop_fresh.log
set -euo pipefail

OUT="${1:-btsnoop_fresh.log}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$HERE/captures/$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

command -v adb >/dev/null || { echo "adb not found. Install android-platform-tools."; exit 1; }
echo "[adb] devices:"; adb devices

echo "[adb] taking bugreport (this can take a minute)..."
adb bugreport "$TMP/bugreport.zip"

echo "[extract] looking for btsnoop_hci.log inside the bugreport..."
# The log lives at FS/data/misc/bluetooth/logs/btsnoop_hci.log (path varies).
ENTRY="$(unzip -Z1 "$TMP/bugreport.zip" | grep -i 'btsnoop_hci.log' | head -1 || true)"
if [ -z "$ENTRY" ]; then
  echo "[extract] no btsnoop_hci.log in the bugreport."
  echo "          Make sure 'Bluetooth HCI snoop log' was ENABLED during capture,"
  echo "          and that you toggled Bluetooth off/on after enabling it."
  exit 1
fi
unzip -p "$TMP/bugreport.zip" "$ENTRY" > "$DEST"
echo "[done] wrote $DEST ($(wc -c < "$DEST") bytes)"
echo "[next] python tools/jabra_hci_parse.py captures/$OUT"
