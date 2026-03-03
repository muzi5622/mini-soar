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
