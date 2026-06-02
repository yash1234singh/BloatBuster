#!/usr/bin/env bash
# buildPkg.sh — build a standalone bloatbuster binary with all Python dependencies
#
# Produces: dist/bloatbuster (single ELF executable, no Python required on target)
#
# Dependencies bundled:
#   scapy    — required for --owd (TCP-TSval OWD measurement)
#   requests — required for traffic-gen.py HTTP/HTTPS clients
#   h2       — required for traffic-gen.py HTTP/2 clients
#
# twamp_owd.py uses stdlib only (socket, struct) — no extra packages needed.
#
# Runtime requirements on target machine:
#   - Linux kernel (executable is Linux ELF)
#   - 'traceroute' binary: apt install traceroute
#   - Root / CAP_NET_RAW if using --owd (Scapy raw socket)
#   - --twamp does NOT require root
#
# Usage:
#   bash buildPkg.sh
#   dist/bloatbuster -T 8.8.8.8 --twamp
#   sudo dist/bloatbuster -T 8.8.8.8 --owd

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_DIR="$SCRIPT_DIR/python"
VENV_DIR="$HOME/.cache/bb_build_venv"
DIST_DIR="$SCRIPT_DIR/dist"
BUILD_DIR="$SCRIPT_DIR/build"

echo "========================================================"
echo "  BloatBuster — PyInstaller package builder"
echo "========================================================"
echo ""
echo "  Source dir : $PYTHON_DIR"
echo "  Output     : $DIST_DIR/bloatbuster"
echo ""

# Verify required source files exist
for f in userbufferTest.py tcp_owd.py twamp_owd.py traffic-gen.py; do
    if [[ ! -f "$PYTHON_DIR/$f" ]]; then
        echo "[ERROR] Required file not found: $PYTHON_DIR/$f"
        exit 1
    fi
done

# ── Step 1: Create / reuse an isolated build venv ──────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    echo "[1/4] Creating isolated build venv at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
else
    echo "[1/4] Reusing existing build venv at $VENV_DIR"
    echo "      (delete $VENV_DIR to force a clean rebuild)"
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# ── Step 2: Install runtime + build dependencies ───────────────────────────
echo ""
echo "[2/4] Installing/updating dependencies ..."
pip install --quiet --upgrade pip
pip install --quiet pyinstaller scapy requests h2

echo "      Installed packages:"
pip list --format=columns | grep -E "^(PyInstaller|scapy|requests|h2|cryptography|pyzmq)" \
    | sed 's/^/        /'

# ── Step 3: Run PyInstaller ─────────────────────────────────────────────────
echo ""
echo "[3/4] Running PyInstaller (this may take 1-3 minutes) ..."

# Clean old build artefacts so we get a fresh bundle
rm -rf "$BUILD_DIR" "$DIST_DIR/bloatbuster"

pyinstaller \
    --onefile \
    --name bloatbuster \
    --distpath "$DIST_DIR" \
    --workpath "$BUILD_DIR" \
    --specpath "$BUILD_DIR" \
    --collect-all scapy \
    --add-data "$PYTHON_DIR/tcp_owd.py:." \
    --add-data "$PYTHON_DIR/twamp_owd.py:." \
    --add-data "$PYTHON_DIR/traffic-gen.py:." \
    --hidden-import scapy.layers.inet \
    --hidden-import scapy.layers.l2 \
    --hidden-import scapy.arch.linux \
    "$PYTHON_DIR/userbufferTest.py" \
    2>&1 | grep -v "^INFO:" || true   # suppress verbose INFO lines; keep WARN/ERROR

deactivate

# ── Step 4: Verify and report ───────────────────────────────────────────────
echo ""
if [[ -f "$DIST_DIR/bloatbuster" ]]; then
    SIZE=$(du -sh "$DIST_DIR/bloatbuster" | cut -f1)
    echo "[4/4] Build complete."
    echo ""
    echo "  Binary : $DIST_DIR/bloatbuster"
    echo "  Size   : $SIZE"
    echo ""
    echo "  Usage examples:"
    echo "    $DIST_DIR/bloatbuster -T 8.8.8.8 --twamp"
    echo "    $DIST_DIR/bloatbuster -T 8.8.8.8 --twamp --twamp-server 34.209.241.130 --twamp-port 4200"
    echo "    sudo $DIST_DIR/bloatbuster -T 8.8.8.8 --owd"
    echo "    sudo $DIST_DIR/bloatbuster -T 8.8.8.8 --owd --twamp -b 30 -s 120 -o results.csv"
    echo ""
    echo "  NOTE: 'traceroute' must be installed on the target machine:"
    echo "          apt install traceroute  (Debian/Ubuntu)"
    echo "          yum install traceroute  (RHEL/CentOS)"
else
    echo "[ERROR] Build failed — dist/bloatbuster not found."
    echo "        Check PyInstaller output above for errors."
    exit 1
fi
