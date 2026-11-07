#!/usr/bin/env bash
# ==============================================================================
#  SHADOW CAT — Remote Web/Terminal One-Liner Bootstrap Installer
#  Usage: curl -fsSL https://thanakorn30006.github.io/get.sh | bash
# ==============================================================================
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

INSTALL_DIR="$HOME/shadowcat"
REPO_URL="https://github.com/thanakorn30006/shadowcat.git" # Change to your actual repository URL

echo -e "${CYAN}"
echo "  ____  _   _    _    ____   _____        __   ____    _  _____ "
echo " / ___|| | | |  / \  |  _ \ / _ \ \      / /  / ___|  / \|_   _|"
echo " \___ \| |_| | / _ \ | | | | | | \ \ /\ / /  | |     / _ \ | |  "
echo "  ___) |  _  |/ ___ \| |_| | |_| |\ V  V /   | |___ / ___ \| |  "
echo " |____/|_| |_/_/   \_\____/ \___/  \_/\_/     \____/_/   \_\_|  "
echo -e "${NC}"
echo -e "${GREEN}[+] Fetching SHADOW CAT Cyber Operations Suite...${NC}\n"

# 1. Check prerequisites
if ! command -v git &>/dev/null; then
    echo -e "${RED}[!] Git is not installed. Please install git first.${NC}"
    exit 1
fi

if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo -e "${RED}[!] Python 3 is required. Please install Python 3.9+ first.${NC}"
    exit 1
fi

# 2. Clone or Update Repository
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "[*] Existing installation found at ${CYAN}$INSTALL_DIR${NC}. Updating..."
    cd "$INSTALL_DIR"
    git pull --quiet
else
    echo -e "[*] Cloning SHADOW CAT into ${CYAN}$INSTALL_DIR${NC}..."
    git clone "$REPO_URL" "$INSTALL_DIR" --quiet
    cd "$INSTALL_DIR"
fi

# 3. Run Self-Installation
echo -e "[*] Configuring Python virtual environment & dependencies..."
chmod +x ./install.sh ./run.sh

# Run install non-interactively
export DEBIAN_FRONTEND=noninteractive
./install.sh <<< "n" 2>/dev/null || ./install.sh

# 4. Launch Application
echo -e "\n${GREEN}==========================================================${NC}"
echo -e "${GREEN}[OK] Installation Complete! Starting SHADOW CAT...${NC}"
echo -e "${GREEN}==========================================================${NC}"

exec ./run.sh
