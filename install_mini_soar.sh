#!/usr/bin/env bash
set -euo pipefail

# ---- Config ----
TARGET_DIR="/opt/mini-soar"
SERVICE_USER="root"   # change if you later run as a dedicated user
SERVICE_GROUP="root"

# ---- Resolve source directory robustly (works from anywhere) ----
SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           MINI-SOAR - ONE-TIME INSTALLATION SCRIPT            ║"
echo "║     Copies project to /opt, creates venv, installs deps       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# ---- Root check ----
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "❌ Run as root:"
  echo "   sudo bash $0"
  exit 1
fi

# ---- Sanity check: required files in source ----
REQ_FILES=("ioc_fetcher.py" "ioc_blocker.py" "dashboard_enhanced.py" "master_run.sh")
missing=0
for f in "${REQ_FILES[@]}"; do
  if [[ ! -f "$SRC_DIR/$f" ]]; then
    echo "❌ Missing required file in source folder: $SRC_DIR/$f"
    missing=1
  fi
done
if [[ $missing -eq 1 ]]; then
  echo ""
  echo "Source folder detected as: $SRC_DIR"
  echo "Place install_mini_soar.sh in the project root (same dir as master_run.sh)."
  exit 1
fi

echo "✓ Source project: $SRC_DIR"
echo "✓ Target install: $TARGET_DIR"
echo ""

# ---- If already installed, refuse to re-copy (safe) ----
if [[ -d "$TARGET_DIR" ]] && [[ -f "$TARGET_DIR/master_run.sh" ]]; then
  echo "⚠️  Looks like MINI-SOAR is already installed at: $TARGET_DIR"
  echo "   Not copying again to avoid overwriting."
  echo ""
  echo "You can run it with:"
  echo "   sudo bash $TARGET_DIR/master_run.sh"
  exit 0
fi

# ---- Install system deps (Debian/Ubuntu) ----
echo "[1/6] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq python3 python3-venv python3-pip nftables curl rsync >/dev/null 2>&1
echo "✓ System dependencies installed"
echo ""

# ---- Create target dir ----
echo "[2/6] Creating target directory..."
mkdir -p "$TARGET_DIR"
echo "✓ Created: $TARGET_DIR"
echo ""

# ---- Copy project into /opt/mini-soar (safe copy) ----
# We COPY first (safer), then optionally delete source if you want.
echo "[3/6] Copying project files into $TARGET_DIR ..."
rsync -a --delete \
  --exclude 'venv/' \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude 'logs/' \
  "$SRC_DIR/" "$TARGET_DIR/"
mkdir -p "$TARGET_DIR/logs"
echo "✓ Copied files"
echo ""

# ---- Create venv + install python deps ----
echo "[4/6] Creating venv & installing Python dependencies..."
cd "$TARGET_DIR"
if [[ ! -d "venv" ]]; then
  python3 -m venv venv
fi
./venv/bin/pip -q install --upgrade pip

if [[ -f "requirements.txt" ]]; then
  ./venv/bin/pip -q install -r requirements.txt
  echo "✓ Installed from requirements.txt"
else
  ./venv/bin/pip -q install requests flask cryptography
  echo "✓ Installed: requests flask cryptography"
fi
echo ""

# ---- Create .env if missing ----
echo "[5/6] Creating .env (only if missing)..."
if [[ ! -f ".env" ]]; then
  cat > ".env" <<'EOF'
# ===== MINI-SOAR CONFIG =====

# nftables objects
NFT_TABLE="ioc_blocker"
NFT_SET="blocked_ips"

# Dashboard
DASHBOARD_PORT="5000"

# Logs (relative to /opt/mini-soar)
FETCHER_LOG="logs/fetcher.log"
BLOCKER_LOG="logs/blocker.log"
DASHBOARD_LOG="logs/dashboard.log"
EOF
  chmod 600 ".env"
  echo "✓ Created: $TARGET_DIR/.env"
else
  echo "✓ Found existing .env (not overwritten)"
fi
echo ""

# ---- Install the NEW master_run.sh (recommended) ----
echo "[6/6] Writing robust master_run.sh into $TARGET_DIR ..."
cat > "$TARGET_DIR/master_run.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Always operate from the script directory
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

# Load configuration
if [[ -f ".env" ]]; then
  # shellcheck disable=SC1091
  source ".env"
else
  echo "❌ .env file not found in $BASE_DIR"
  exit 1
fi

VENV_PY="$BASE_DIR/venv/bin/python3"
if [[ ! -x "$VENV_PY" ]]; then
  echo "❌ venv python missing: $VENV_PY"
  echo "   Run installer again or create venv:"
  echo "   python3 -m venv venv && venv/bin/pip install -r requirements.txt"
  exit 1
fi

mkdir -p "$BASE_DIR/logs"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║              MINI-SOAR - STARTING SERVICES                    ║"
echo "║        IOC Fetcher / Blocker / Dashboard (venv safe)           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "[1/5] Stopping any existing services..."
pkill -f "ioc_fetcher.py" 2>/dev/null || true
pkill -f "ioc_blocker.py" 2>/dev/null || true
pkill -f "dashboard_enhanced.py" 2>/dev/null || true
sleep 2
echo "✓ Cleaned up old processes"

echo ""
echo "[2/5] Setting up nftables..."
# If running as root, no sudo needed
nft add table inet "$NFT_TABLE" 2>/dev/null || true
nft add set inet "$NFT_TABLE" "$NFT_SET" '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
nft add chain inet "$NFT_TABLE" input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
nft add rule inet "$NFT_TABLE" input ip daddr @"$NFT_SET" drop 2>/dev/null || true
echo "✓ nftables configured: table=$NFT_TABLE set=$NFT_SET"

echo ""
echo "[3/5] Starting IOC Fetcher Daemon..."
nohup "$VENV_PY" "$BASE_DIR/ioc_fetcher.py" > "$BASE_DIR/$FETCHER_LOG" 2>&1 &
FETCH_PID=$!
sleep 2
echo "📌 Fetcher PID: $FETCH_PID"

echo ""
echo "[4/5] Starting IOC Blocker Daemon..."
nohup "$VENV_PY" "$BASE_DIR/ioc_blocker.py" > "$BASE_DIR/$BLOCKER_LOG" 2>&1 &
BLOCK_PID=$!
sleep 2
echo "📌 Blocker PID: $BLOCK_PID"

echo ""
echo "[5/5] Starting Web Dashboard..."
nohup "$VENV_PY" "$BASE_DIR/dashboard_enhanced.py" > "$BASE_DIR/$DASHBOARD_LOG" 2>&1 &
DASH_PID=$!
sleep 3
echo "📌 Dashboard PID: $DASH_PID"

# Status
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    ✅ SERVICES STATUS                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 IOC Fetcher Daemon   $(ps -p "$FETCH_PID" >/dev/null 2>&1 && echo '✓ RUNNING' || echo '❌ STOPPED')"
echo "📊 IOC Blocker Daemon   $(ps -p "$BLOCK_PID" >/dev/null 2>&1 && echo '✓ RUNNING' || echo '❌ STOPPED')"
echo "🌐 Web Dashboard        $(ps -p "$DASH_PID"  >/dev/null 2>&1 && echo '✓ RUNNING' || echo '❌ STOPPED')"
echo ""
echo "🌐 DASHBOARD ACCESS:"
echo "   → http://127.0.0.1:$DASHBOARD_PORT"
echo "   → http://localhost:$DASHBOARD_PORT"
echo ""
echo "📝 LOGS:"
echo "   Fetcher:    tail -f $BASE_DIR/$FETCHER_LOG"
echo "   Blocker:    tail -f $BASE_DIR/$BLOCKER_LOG"
echo "   Dashboard:  tail -f $BASE_DIR/$DASHBOARD_LOG"
echo ""
echo "🛡️  VERIFY BLOCKING:"
echo "   nft list set inet $NFT_TABLE $NFT_SET | wc -l"
echo ""
echo "🛑 STOP SERVICES:"
echo "   pkill -f 'ioc_fetcher.py' ; pkill -f 'ioc_blocker.py' ; pkill -f 'dashboard_enhanced.py'"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

# Follow logs (optional)
echo "Monitoring fetcher + blocker logs (Ctrl+C to exit)..."
tail -f "$BASE_DIR/$FETCHER_LOG" "$BASE_DIR/$BLOCKER_LOG"
EOF

chmod 700 "$TARGET_DIR/master_run.sh"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$TARGET_DIR"
chmod 750 "$TARGET_DIR"
chmod -R 750 "$TARGET_DIR/logs"

echo "✓ Installed robust master_run.sh"
echo ""

# ---- OPTIONAL: Move vs copy (safe default is copy) ----
echo "✅ Installation complete."
echo ""
echo "Run from /opt any time using:"
echo "  sudo bash $TARGET_DIR/master_run.sh"
echo ""
echo "NOTE: This installer COPIED the project from:"
echo "  $SRC_DIR"
echo "If you want to delete the old source folder manually, you can."
