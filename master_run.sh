#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")"

# Source configuration
if [ -f .env ]; then
    source .env
else
    echo "❌ .env file not found!"
    exit 1
fi

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         IOC BLOCKER PRO - STARTING SERVICES                  ║"
echo "║        Advanced Threat Intelligence & Blocking System         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "❌ Virtual environment not found! Run installer first."
    exit 1
fi

mkdir -p logs

echo "[1/5] Stopping any existing services..."
pkill -f "ioc_fetcher.py" 2>/dev/null || true
pkill -f "ioc_blocker.py" 2>/dev/null || true
pkill -f "dashboard_enhanced.py" 2>/dev/null || true
sleep 2
echo "✓ Cleaned up old processes"

echo ""
echo "[2/5] Setting up nftables..."
sudo nft add table inet $NFT_TABLE 2>/dev/null || true
sudo nft add set inet $NFT_TABLE $NFT_SET '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
sudo nft add chain inet $NFT_TABLE input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
sudo nft add rule inet $NFT_TABLE input ip daddr @$NFT_SET drop 2>/dev/null || true
echo "✓ nftables configured"

echo ""
echo "[3/5] Starting IOC Fetcher Daemon..."
nohup python3 ioc_fetcher.py > $FETCHER_LOG 2>&1 &
FETCH_PID=$!
sleep 2
if ps -p $FETCH_PID > /dev/null 2>&1; then
    echo "✓ IOC Fetcher running (PID: $FETCH_PID)"
else
    echo "❌ IOC Fetcher failed to start"
fi

echo ""
echo "[4/5] Starting IOC Blocker Daemon..."
nohup python3 ioc_blocker.py > $BLOCKER_LOG 2>&1 &
BLOCK_PID=$!
sleep 2
if ps -p $BLOCK_PID > /dev/null 2>&1; then
    echo "✓ IOC Blocker running (PID: $BLOCK_PID)"
else
    echo "❌ IOC Blocker failed to start"
fi

echo ""
echo "[5/5] Starting Web Dashboard..."
# Kill any existing dashboard
pkill -f "dashboard_enhanced.py" 2>/dev/null || true
sleep 1

# Start dashboard in background with proper output
nohup python3 dashboard_enhanced.py > $DASHBOARD_LOG 2>&1 &
DASH_PID=$!
sleep 3

# Verify dashboard is running
if ps -p $DASH_PID > /dev/null 2>&1; then
    echo "✓ Dashboard running (PID: $DASH_PID)"
    DASH_RUNNING=1
else
    echo "❌ Dashboard failed to start - checking logs..."
    echo "Log output:"
    tail -20 $DASHBOARD_LOG
    DASH_RUNNING=0
fi

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    ✅ SERVICES STATUS                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 IOC Fetcher Daemon       $(ps -p $FETCH_PID > /dev/null 2>&1 && echo '✓ RUNNING' || echo '❌ STOPPED')"
echo "📊 IOC Blocker Daemon       $(ps -p $BLOCK_PID > /dev/null 2>&1 && echo '✓ RUNNING' || echo '❌ STOPPED')"
echo "🌐 Web Dashboard            $([ $DASH_RUNNING -eq 1 ] && echo '✓ RUNNING' || echo '❌ STOPPED')"
echo ""
echo "🌐 DASHBOARD ACCESS:"
echo "   → http://localhost:$DASHBOARD_PORT"
echo "   → http://0.0.0.0:$DASHBOARD_PORT"
echo ""
echo "   If not working, try:"
echo "   → http://127.0.0.1:$DASHBOARD_PORT"
echo ""
echo "📝 LOGS:"
echo "   Fetcher: tail -f $FETCHER_LOG"
echo "   Blocker: tail -f $BLOCKER_LOG"
echo "   Dashboard: tail -f $DASHBOARD_LOG"
echo ""
echo "🛡️  VERIFY BLOCKING:"
echo "   sudo nft list set inet $NFT_TABLE $NFT_SET | wc -l"
echo ""
echo "🛑 STOP SERVICES:"
echo "   pkill -f 'ioc_fetcher.py'"
echo "   pkill -f 'ioc_blocker.py'"
echo "   pkill -f 'dashboard_enhanced.py'"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

# Keep script running and show logs
if [ $DASH_RUNNING -eq 1 ]; then
    echo "Services are running. Monitoring logs (Press Ctrl+C to stop)..."
    echo ""
    tail -f $FETCHER_LOG &
    FETCHER_TAIL_PID=$!
    tail -f $BLOCKER_LOG &
    BLOCKER_TAIL_PID=$!
    
    # Wait for any process to exit
    wait
else
    echo "⚠️  Dashboard did not start. Check the log above for errors."
    echo ""
    echo "Trying alternative startup method..."
    echo ""
    
    # Try to run dashboard directly
    python3 dashboard_enhanced.py
fi
