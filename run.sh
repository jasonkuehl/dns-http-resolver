#!/bin/bash
# DNS HTTP Resolver - Local Development Runner
# Usage: ./run.sh [port]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${1:-60200}"
VENV_DIR="${SCRIPT_DIR}/venv"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🌐 DNS HTTP Resolver${NC}"
echo "================================"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 is not installed${NC}"
    exit 1
fi

# Find or create virtual environment
if [ -f "$HOME/.venv/bin/activate" ]; then
    VENV_DIR="$HOME/.venv"
    echo -e "${GREEN}Using system venv at $VENV_DIR${NC}"
elif [ -f "$VENV_DIR/bin/activate" ]; then
    echo -e "${GREEN}Using local venv${NC}"
else
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv "$VENV_DIR" || {
        echo -e "${RED}Could not create virtual environment${NC}"
        echo "Install python3-venv: sudo apt install python3-venv"
        exit 1
    }
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source "$VENV_DIR/bin/activate"

# Install/upgrade dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install -q -r requirements.txt

# Copy .env.sample to .env if .env doesn't exist
if [ ! -f ".env" ]; then
    if [ -f ".env.sample" ]; then
        echo -e "${YELLOW}Creating .env from .env.sample...${NC}"
        cp .env.sample .env
    fi
fi

# Check if port is already in use
if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    echo -e "${RED}Port $PORT is already in use${NC}"
    echo "Try: ./run.sh 5001"
    exit 1
fi

echo ""
echo -e "${GREEN}Starting server on port $PORT...${NC}"
echo -e "Open: ${GREEN}http://localhost:${PORT}${NC}"
echo -e "Health: ${GREEN}http://localhost:${PORT}/health${NC}"
echo ""
echo "Press Ctrl+C to stop"
echo "================================"

# Run with gunicorn if available, otherwise use Flask dev server
if command -v gunicorn &> /dev/null || pip show gunicorn &> /dev/null; then
    exec gunicorn --bind "0.0.0.0:${PORT}" --workers 2 --timeout 30 app:app
else
    export PORT="$PORT"
    exec python app.py
fi
