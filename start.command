#!/usr/bin/env bash
# ==============================================================================
#  SHADOW CAT — macOS 1-Click Desktop Launcher
#  Double-click in Finder to start SHADOW CAT and open browser automatically.
# ==============================================================================

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "[*] Initializing SHADOW CAT Launcher..."
exec ./run.sh "$@"
