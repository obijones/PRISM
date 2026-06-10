#!/usr/bin/env bash
# CARVER Risk Assessment Tool — local launcher
#
# Usage: bash start_carver.sh
#   (or make it executable once: chmod +x start_carver.sh && ./start_carver.sh)
#
# The script locates the virtual environment Python, starts Flask in the
# foreground, and opens a browser tab automatically.  Closing the terminal
# window (or pressing Ctrl+C) stops the server cleanly.

set -euo pipefail
cd "$(dirname "$0")"

# ── Locate venv Python ────────────────────────────────────────────────────────
# Prefer the .venv subfolder; fall back to a root-level venv (bin/python3).
if   [ -f ".venv/bin/python3" ]; then PYTHON=".venv/bin/python3"
elif [ -f "bin/python3" ];       then PYTHON="bin/python3"
else
    echo ""
    echo "  [ERROR] No virtual environment found."
    echo "  Expected: .venv/bin/python3  or  bin/python3"
    echo ""
    echo "  Create one with:"
    echo "    python3 -m venv .venv"
    echo "    .venv/bin/pip install -r requirements.txt"
    echo ""
    exit 1
fi

PORT=5000
URL="http://127.0.0.1:${PORT}"

echo ""
echo "  CARVER Risk Assessment Tool"
echo "  ──────────────────────────────────────────"
echo "  URL     : ${URL}"
echo "  Database: $(pwd)/data/carver.db"
echo "  Stop    : Use the Shut Down button in the app, or Ctrl+C"
echo ""

# Open the browser after a short delay without blocking Flask startup.
# Tries xdg-open (Linux), then open (macOS); silently skips if neither found.
(sleep 2 && \
    if   command -v xdg-open &>/dev/null; then xdg-open "$URL" >/dev/null 2>&1
    elif command -v open     &>/dev/null; then open     "$URL" >/dev/null 2>&1
    fi
) &

# exec replaces this shell with Python so Ctrl+C / window-close kills it directly.
exec "$PYTHON" app.py
