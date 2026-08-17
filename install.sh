#!/usr/bin/env bash
set -e
BASE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
python3 -m venv "$BASE/.venv"
"$BASE/.venv/bin/python" -m pip install --upgrade pip
if command -v clang++ >/dev/null 2>&1; then
  clang++ -std=c++17 -O2 "$BASE/cpp/fast_hash.cpp" -o "$BASE/build/cfhash" || true
fi
chmod +x "$BASE/cyberforge"
echo "[+] CyberForge v5 installed. Install Nmap separately for the Nmap module."
