#!/data/data/com.termux/files/usr/bin/bash
set -e
BASE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
pkg update -y
pkg install -y python clang
pkg install -y nmap || true
python3 -m venv "$BASE/.venv"
"$BASE/.venv/bin/python" -m pip install --upgrade pip
clang++ -std=c++17 -O2 "$BASE/cpp/fast_hash.cpp" -o "$BASE/build/cfhash" || true
chmod +x "$BASE/cyberforge"
echo "[+] CyberForge v5 installed. Run: ./cyberforge"
