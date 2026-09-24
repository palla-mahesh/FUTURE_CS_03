#!/bin/bash
# One-click launcher for Kali API Security Analyzer

set -e

echo "======================================"
echo "  🛡️  API Security Analyzer Launcher"
echo "======================================"

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Python3 not found. Install it first."
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "[*] Installing dependencies..."
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet

echo "[*] Starting server on http://127.0.0.1:5000"
echo "[*] Press CTRL+C to stop"
python api_sec_tool.py
