#!/usr/bin/env bash
# ==============================================================================
#  SHADOW CAT — Startup & Execution Manager
# ==============================================================================

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}"
echo "=========================================================="
echo "[+] Starting SHADOW CAT — Cyber Operations Suite"
echo "=========================================================="
echo -e "${NC}"

# 1. Resolve Python venv
PYTHON_BIN=""
if [ -f "$SCRIPT_DIR/backend/venv/bin/python3" ]; then
    PYTHON_BIN="$SCRIPT_DIR/backend/venv/bin/python3"
elif command -v python3 &>/dev/null; then
    echo -e "${YELLOW}[!] backend/venv not found — falling back to system python3.${NC}"
    echo    "    Run ./install.sh to create an isolated environment with all dependencies."
    PYTHON_BIN="python3"
else
    echo "[!] Python 3 not found. Please run ./install.sh first."
    exit 1
fi

echo "[*] Using Python: $PYTHON_BIN"

# Terminate any stale processes on port 8000 (and 5173 if running)
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
if [[ "$*" == *"--dev"* ]]; then
    lsof -ti:5173 | xargs kill -9 2>/dev/null || true
fi

# Cleanup handler on exit
cleanup() {
    echo ""
    echo "[!] Stopping SHADOW CAT services..."
    kill $(jobs -p) 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 2. Resolve Host Binding (Default: 127.0.0.1 for strict Air-Gap & Local Security)
BIND_HOST="127.0.0.1"
if [[ "$*" == *"--lan"* ]] || [[ "$*" == *"--public"* ]]; then
    BIND_HOST="0.0.0.0"
    echo -e "${YELLOW}[!] Warning: Binding to 0.0.0.0 — Exposed to local network interfaces.${NC}"
else
    echo "[*] Secure local binding: 127.0.0.1 (Pass --lan to expose to local network)"
fi

# 3. Launch Backend (FastAPI on Port 8000)
# FastAPI serves both API routes and static Single-Port Web UI
echo "[*] Launching SHADOW CAT Core (http://localhost:8000)..."
cd "$SCRIPT_DIR/backend"
$PYTHON_BIN -m uvicorn main:app --host "$BIND_HOST" --port 8000 --reload &
BACKEND_PID=$!
cd "$SCRIPT_DIR"

# 4. Optional Dev Mode (Vite React HMR on 5173)
if [[ "$*" == *"--dev"* ]]; then
    echo "[*] Developer flag detected. Launching Vite HMR Frontend (http://localhost:5173)..."
    cd "$SCRIPT_DIR/frontend"
    npm run dev -- --host &
    FRONTEND_PID=$!
    cd "$SCRIPT_DIR"
fi

# Wait for server to become responsive
sleep 1.5

echo -e "${GREEN}=========================================================="
echo "[OK] SHADOW CAT is LIVE & OPERATIONAL!"
if [[ "$*" == *"--dev"* ]]; then
    echo "   - Web UI (Dev HMR): http://localhost:5173"
fi
echo "   - Web UI & Platform: http://localhost:8000"
echo "   - Interactive API Docs: http://localhost:8000/docs"
echo "==========================================================${NC}"
echo "Press Ctrl+C to stop the platform."

# Open browser automatically if not in headless environment
if command -v open &>/dev/null; then
    open "http://localhost:8000" 2>/dev/null || true
elif command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:8000" 2>/dev/null || true
fi

wait
