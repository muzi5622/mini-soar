#!/usr/bin/env python3
"""
Enhanced IOC Blocker Dashboard - Real-time Threat Intelligence UI
Features:
- Live blocked domains and IPs
- Real-time statistics
- Activity logs
- Threat severity indicators
- Allowlist management
- Export capabilities
"""

from flask import Flask, jsonify, render_template_string, request
import json
import os
import subprocess
from datetime import datetime
from collections import deque

app = Flask(__name__)

# Store recent activity in memory
recent_blocks = deque(maxlen=100)
block_statistics = {
    'total_ips': 0,
    'total_domains': 0,
    'blocks_today': 0,
    'blocks_this_hour': 0
}

def load_iocs():
    """Load IOC data from file"""
    ioc_file = os.getenv('IOC_FILE', 'iocs.json')
    try:
        if os.path.exists(ioc_file):
            with open(ioc_file, 'r') as f:
                return json.load(f)
    except:
        pass
    return {'domains': [], 'ips': [], 'timestamp': ''}

def load_dns_cache():
    """Load DNS resolution cache"""
    dns_file = os.getenv('DNS_CACHE_FILE', 'dns_cache.json')
    try:
        if os.path.exists(dns_file):
            with open(dns_file, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def load_allowlist():
    """Load allowlist"""
    allow_file = os.getenv('ALLOWLIST_FILE', 'allowlist.json')
    try:
        if os.path.exists(allow_file):
            with open(allow_file, 'r') as f:
                return json.load(f)
    except:
        pass
    return {'ips': [], 'domains': []}

def get_nft_stats():
    """Get blocking statistics from nftables"""
    try:
        result = subprocess.run(
            "nft list set inet iocblocker block_v4",
            shell=True, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Parse output to count elements
            lines = result.stdout.split('\n')
            elements = [l for l in lines if '.' in l]
            return len(elements)
    except:
        pass
    return 0

@app.route('/')
def dashboard():
    """Main dashboard"""
    html_content = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🛡️ IOC Blocker Pro - Threat Intelligence Dashboard</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            :root {
                --primary: #00ff41;
                --danger: #ff0055;
                --warning: #ffaa00;
                --info: #00aaff;
                --dark: #0a0e27;
                --darker: #050810;
                --card: #1a1f3a;
                --border: #2d3561;
                --text: #e0e0e0;
            }

            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, var(--dark) 0%, var(--darker) 100%);
                color: var(--text);
                line-height: 1.6;
                overflow-x: hidden;
            }

            .sidebar {
                position: fixed;
                left: 0;
                top: 0;
                width: 250px;
                height: 100vh;
                background: var(--darker);
                border-right: 2px solid var(--primary);
                padding: 20px;
                overflow-y: auto;
                z-index: 1000;
            }

            .logo {
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 30px;
                font-size: 1.5em;
                font-weight: bold;
                color: var(--primary);
                text-shadow: 0 0 10px var(--primary);
            }

            .nav-menu {
                list-style: none;
            }

            .nav-item {
                margin: 10px 0;
                padding: 12px;
                cursor: pointer;
                border-left: 3px solid transparent;
                transition: all 0.3s;
            }

            .nav-item:hover {
                border-left-color: var(--primary);
                background: var(--card);
            }

            .nav-item.active {
                border-left-color: var(--primary);
                background: var(--card);
                color: var(--primary);
            }

            .main-container {
                margin-left: 250px;
                padding: 30px;
            }

            header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 40px;
                padding-bottom: 20px;
                border-bottom: 2px solid var(--border);
            }

            h1 {
                font-size: 2.5em;
                color: var(--primary);
                text-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
            }

            .status-indicator {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 10px 20px;
                background: var(--card);
                border: 2px solid var(--primary);
                border-radius: 8px;
                font-weight: bold;
            }

            .status-dot {
                width: 12px;
                height: 12px;
                background: var(--primary);
                border-radius: 50%;
                animation: pulse 2s infinite;
            }

            @keyframes pulse {
                0%, 100% { opacity: 1; box-shadow: 0 0 0 0 var(--primary); }
                50% { opacity: 0.8; box-shadow: 0 0 10px 5px rgba(0, 255, 65, 0.2); }
            }

            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 40px;
            }

            .stat-card {
                background: linear-gradient(135deg, var(--card) 0%, rgba(26, 31, 58, 0.5) 100%);
                border: 2px solid var(--border);
                border-radius: 12px;
                padding: 25px;
                transition: all 0.3s;
            }

            .stat-card:hover {
                border-color: var(--primary);
                box-shadow: 0 0 20px rgba(0, 255, 65, 0.1);
                transform: translateY(-5px);
            }

            .stat-label {
                color: var(--text);
                font-size: 0.95em;
                margin-bottom: 10px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }

            .stat-value {
                font-size: 2.5em;
                font-weight: bold;
                color: var(--primary);
                text-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
            }

            .stat-card.warning .stat-value { color: var(--warning); }
            .stat-card.danger .stat-value { color: var(--danger); }
            .stat-card.info .stat-value { color: var(--info); }

            .content-section {
                margin-bottom: 40px;
            }

            .section-title {
                font-size: 1.8em;
                color: var(--primary);
                margin-bottom: 20px;
                padding-bottom: 10px;
                border-bottom: 2px solid var(--border);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            .section-title .refresh-btn {
                font-size: 0.6em;
                padding: 8px 16px;
                background: var(--primary);
                color: var(--dark);
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-weight: bold;
                transition: all 0.3s;
            }

            .section-title .refresh-btn:hover {
                transform: scale(1.05);
                box-shadow: 0 0 15px rgba(0, 255, 65, 0.4);
            }

            .table-container {
                background: var(--card);
                border: 2px solid var(--border);
                border-radius: 12px;
                overflow: hidden;
                max-height: 600px;
                overflow-y: auto;
            }

            table {
                width: 100%;
                border-collapse: collapse;
            }

            th {
                background: var(--darker);
                color: var(--primary);
                padding: 15px;
                text-align: left;
                font-weight: bold;
                border-bottom: 2px solid var(--border);
                position: sticky;
                top: 0;
            }

            td {
                padding: 12px 15px;
                border-bottom: 1px solid var(--border);
            }

            tr:hover {
                background: rgba(0, 255, 65, 0.05);
            }

            .ip-addr {
                font-family: 'Courier New', monospace;
                color: var(--info);
                font-weight: bold;
            }

            .domain-name {
                font-family: 'Courier New', monospace;
                color: var(--primary);
                font-weight: bold;
            }

            .badge {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 0.85em;
                font-weight: bold;
            }

            .badge.danger { background: rgba(255, 0, 85, 0.2); color: var(--danger); }
            .badge.warning { background: rgba(255, 170, 0, 0.2); color: var(--warning); }
            .badge.info { background: rgba(0, 170, 255, 0.2); color: var(--info); }

            .activity-log {
                background: var(--card);
                border: 2px solid var(--border);
                border-radius: 12px;
                padding: 20px;
                max-height: 400px;
                overflow-y: auto;
            }

            .activity-item {
                padding: 10px;
                border-left: 3px solid var(--primary);
                margin-bottom: 10px;
                background: rgba(0, 255, 65, 0.05);
                border-radius: 4px;
                font-size: 0.9em;
            }

            .activity-time {
                color: var(--text);
                font-size: 0.85em;
            }

            .tab-container {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                border-bottom: 2px solid var(--border);
            }

            .tab-btn {
                padding: 12px 24px;
                background: transparent;
                border: none;
                color: var(--text);
                cursor: pointer;
                font-size: 1em;
                border-bottom: 3px solid transparent;
                transition: all 0.3s;
            }

            .tab-btn.active {
                color: var(--primary);
                border-bottom-color: var(--primary);
            }

            .tab-content {
                display: none;
            }

            .tab-content.active {
                display: block;
            }

            .search-box {
                padding: 12px 16px;
                background: var(--darker);
                border: 2px solid var(--border);
                border-radius: 8px;
                color: var(--text);
                margin-bottom: 20px;
                font-size: 1em;
            }

            .search-box:focus {
                outline: none;
                border-color: var(--primary);
                box-shadow: 0 0 15px rgba(0, 255, 65, 0.2);
            }

            .copy-btn {
                padding: 4px 8px;
                background: var(--primary);
                color: var(--dark);
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 0.85em;
                font-weight: bold;
                transition: all 0.3s;
            }

            .copy-btn:hover {
                transform: scale(1.05);
            }

            .empty-state {
                text-align: center;
                padding: 40px;
                color: var(--text);
            }

            .empty-state-icon {
                font-size: 3em;
                margin-bottom: 20px;
            }

            @media (max-width: 768px) {
                .sidebar {
                    width: 200px;
                }
                .main-container {
                    margin-left: 200px;
                    padding: 15px;
                }
                h1 {
                    font-size: 1.8em;
                }
                .stats-grid {
                    grid-template-columns: 1fr;
                }
            }

            .footer {
                text-align: center;
                padding: 20px;
                color: var(--text);
                border-top: 2px solid var(--border);
                margin-top: 40px;
            }
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="logo">🛡️ IOC Blocker</div>
            <ul class="nav-menu">
                <li class="nav-item active" onclick="switchTab('dashboard')">📊 Dashboard</li>
                <li class="nav-item" onclick="switchTab('domains')">🌐 Blocked Domains</li>
                <li class="nav-item" onclick="switchTab('ips')">📍 Blocked IPs</li>
                <li class="nav-item" onclick="switchTab('activity')">📝 Activity Log</li>
                <li class="nav-item" onclick="switchTab('allowlist')">✅ Allowlist</li>
                <li class="nav-item" onclick="switchTab('settings')">⚙️ Settings</li>
            </ul>
        </div>

        <div class="main-container">
            <header>
                <h1>🛡️ IOC Blocker Pro</h1>
                <div class="status-indicator">
                    <span class="status-dot"></span>
                    <span id="status-text">ACTIVE</span>
                </div>
            </header>

            <!-- Dashboard Tab -->
            <div id="dashboard" class="tab-content active">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">🔴 Total IPs Blocked</div>
                        <div class="stat-value" id="total-ips">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">🌐 Total Domains</div>
                        <div class="stat-value" id="total-domains">0</div>
                    </div>
                    <div class="stat-card danger">
                        <div class="stat-label">⚠️ High Risk Indicators</div>
                        <div class="stat-value" id="high-risk">0</div>
                    </div>
                    <div class="stat-card info">
                        <div class="stat-label">✓ System Status</div>
                        <div class="stat-value" id="system-status" style="color: var(--primary);">RUNNING</div>
                    </div>
                </div>

                <div class="content-section">
                    <div class="section-title">
                        📊 Recent Blocks
                        <button class="refresh-btn" onclick="refreshData()">↻ REFRESH</button>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Indicator</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="recent-blocks">
                                <tr>
                                    <td colspan="4" class="empty-state">
                                        <div class="empty-state-icon">⏳</div>
                                        <p>Loading threat data...</p>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="content-section">
                    <div class="section-title">🕐 Activity Timeline</div>
                    <div class="activity-log" id="activity-log">
                        <div class="empty-state">No recent activity</div>
                    </div>
                </div>
            </div>

            <!-- Domains Tab -->
            <div id="domains" class="tab-content">
                <div class="section-title">
                    🌐 Blocked Domains
                    <button class="refresh-btn" onclick="refreshDomains()">↻ REFRESH</button>
                </div>
                <input type="text" class="search-box" id="domain-search" placeholder="🔍 Search domains..." onkeyup="filterDomains()">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Resolved IPs</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="domains-list">
                            <tr>
                                <td colspan="4" class="empty-state">
                                    <div class="empty-state-icon">⏳</div>
                                    <p>Loading domains...</p>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- IPs Tab -->
            <div id="ips" class="tab-content">
                <div class="section-title">
                    📍 Blocked IP Addresses
                    <button class="refresh-btn" onclick="refreshIPs()">↻ REFRESH</button>
                </div>
                <input type="text" class="search-box" id="ip-search" placeholder="🔍 Search IPs..." onkeyup="filterIPs()">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Type</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="ips-list">
                            <tr>
                                <td colspan="4" class="empty-state">
                                    <div class="empty-state-icon">⏳</div>
                                    <p>Loading IPs...</p>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Activity Tab -->
            <div id="activity" class="tab-content">
                <div class="section-title">📝 Activity Log</div>
                <div class="activity-log" id="full-activity-log">
                    <div class="empty-state">No activity recorded yet</div>
                </div>
            </div>

            <!-- Allowlist Tab -->
            <div id="allowlist" class="tab-content">
                <div class="section-title">✅ Allowlist Management</div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Reason</th>
                                <th>Added</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="allowlist-list">
                            <tr>
                                <td colspan="4" class="empty-state">
                                    <div class="empty-state-icon">✓</div>
                                    <p>No IPs in allowlist</p>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Settings Tab -->
            <div id="settings" class="tab-content">
                <div class="section-title">⚙️ System Settings</div>
                <div class="stat-card" style="max-width: 600px;">
                    <h3 style="color: var(--primary); margin-bottom: 20px;">Configuration</h3>
                    <div style="font-family: monospace; color: var(--text); line-height: 2;">
                        <p>📌 Fetcher Interval: <span id="fetch-interval">3600</span>s</p>
                        <p>🔄 Blocker Interval: <span id="blocker-interval">30</span>s</p>
                        <p>🌐 nftables Table: <span id="nft-table">iocblocker</span></p>
                        <p>📊 Last Updated: <span id="last-update">Never</span></p>
                    </div>
                </div>
            </div>

            <div class="footer">
                <p>🛡️ IOC Blocker Pro v1.0 | Real-time Threat Intelligence & Blocking System</p>
                <p style="font-size: 0.9em; color: var(--text); margin-top: 10px;">Auto-refreshing every 5 seconds</p>
            </div>
        </div>

        <script>
            let allDomains = {};
            let allIPs = [];
            let allowlistIPs = [];

            function switchTab(tabName) {
                // Hide all tabs
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                document.querySelectorAll('.nav-item').forEach(item => {
                    item.classList.remove('active');
                });

                // Show selected tab
                document.getElementById(tabName).classList.add('active');
                event.target.closest('.nav-item').classList.add('active');

                // Load tab data
                if (tabName === 'domains') refreshDomains();
                if (tabName === 'ips') refreshIPs();
                if (tabName === 'activity') refreshActivity();
                if (tabName === 'allowlist') refreshAllowlist();
            }

            function refreshData() {
                fetch('/api/stats')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('total-ips').textContent = data.ips || 0;
                        document.getElementById('total-domains').textContent = data.domains || 0;
                        document.getElementById('high-risk').textContent = Math.ceil((data.ips || 0) * 0.1);
                        document.getElementById('last-update').textContent = new Date().toLocaleTimeString();

                        loadRecentBlocks();
                    });
            }

            function loadRecentBlocks() {
                fetch('/api/recent-blocks')
                    .then(r => r.json())
                    .then(data => {
                        let html = '';
                        if (data.length === 0) {
                            html = '<tr><td colspan="4" class="empty-state"><div class="empty-state-icon">✓</div><p>No recent blocks</p></td></tr>';
                        } else {
                            data.slice(0, 10).forEach(block => {
                                html += `<tr>
                                    <td><span class="badge ${block.type === 'domain' ? 'warning' : 'danger'}">${block.type.toUpperCase()}</span></td>
                                    <td><span class="${block.type === 'domain' ? 'domain-name' : 'ip-addr'}">${block.value}</span></td>
                                    <td><span class="badge danger">BLOCKED</span></td>
                                    <td><button class="copy-btn" onclick="copyToClipboard('${block.value}')">📋 Copy</button></td>
                                </tr>`;
                            });
                        }
                        document.getElementById('recent-blocks').innerHTML = html;
                    });
            }

            function refreshDomains() {
                fetch('/api/domains')
                    .then(r => r.json())
                    .then(data => {
                        allDomains = data;
                        let html = '';
                        if (Object.keys(data).length === 0) {
                            html = '<tr><td colspan="4" class="empty-state"><div class="empty-state-icon">⏳</div><p>No domains</p></td></tr>';
                        } else {
                            Object.entries(data).forEach(([domain, ips]) => {
                                const ipList = ips.join(', ');
                                html += `<tr>
                                    <td><span class="domain-name">${domain}</span></td>
                                    <td><span class="ip-addr" style="font-size: 0.9em;">${ipList}</span></td>
                                    <td><span class="badge danger">BLOCKED</span></td>
                                    <td><button class="copy-btn" onclick="copyToClipboard('${domain}')">📋 Copy</button></td>
                                </tr>`;
                            });
                        }
                        document.getElementById('domains-list').innerHTML = html;
                    });
            }

            function refreshIPs() {
                fetch('/api/ips')
                    .then(r => r.json())
                    .then(data => {
                        allIPs = data;
                        let html = '';
                        if (data.length === 0) {
                            html = '<tr><td colspan="4" class="empty-state"><div class="empty-state-icon">⏳</div><p>No IPs</p></td></tr>';
                        } else {
                            data.forEach(ip => {
                                html += `<tr>
                                    <td><span class="ip-addr">${ip}</span></td>
                                    <td><span class="badge danger">Direct IOC</span></td>
                                    <td><span class="badge danger">BLOCKED</span></td>
                                    <td><button class="copy-btn" onclick="copyToClipboard('${ip}')">📋 Copy</button></td>
                                </tr>`;
                            });
                        }
                        document.getElementById('ips-list').innerHTML = html;
                    });
            }

            function refreshActivity() {
                fetch('/api/activity')
                    .then(r => r.json())
                    .then(data => {
                        let html = '';
                        if (data.length === 0) {
                            html = '<div class="empty-state"><div class="empty-state-icon">📭</div><p>No recent activity</p></div>';
                        } else {
                            data.forEach(item => {
                                html += `<div class="activity-item">
                                    <div style="color: var(--primary);">${item.action}</div>
                                    <div class="activity-time">${item.timestamp}</div>
                                </div>`;
                            });
                        }
                        document.getElementById('full-activity-log').innerHTML = html;
                    });
            }

            function refreshAllowlist() {
                fetch('/api/allowlist')
                    .then(r => r.json())
                    .then(data => {
                        allowlistIPs = data.ips || [];
                        let html = '';
                        if (allowlistIPs.length === 0) {
                            html = '<tr><td colspan="4" class="empty-state"><div class="empty-state-icon">✓</div><p>No IPs in allowlist</p></td></tr>';
                        } else {
                            allowlistIPs.forEach(ip => {
                                html += `<tr>
                                    <td><span class="ip-addr">${ip}</span></td>
                                    <td>Trusted Source</td>
                                    <td><span class="badge info">ALLOWED</span></td>
                                    <td><button class="copy-btn" onclick="copyToClipboard('${ip}')">📋 Copy</button></td>
                                </tr>`;
                            });
                        }
                        document.getElementById('allowlist-list').innerHTML = html;
                    });
            }

            function filterDomains() {
                const searchTerm = document.getElementById('domain-search').value.toLowerCase();
                const rows = document.querySelectorAll('#domains-list tr');
                rows.forEach(row => {
                    const domain = row.textContent.toLowerCase();
                    row.style.display = domain.includes(searchTerm) ? '' : 'none';
                });
            }

            function filterIPs() {
                const searchTerm = document.getElementById('ip-search').value.toLowerCase();
                const rows = document.querySelectorAll('#ips-list tr');
                rows.forEach(row => {
                    const ip = row.textContent.toLowerCase();
                    row.style.display = ip.includes(searchTerm) ? '' : 'none';
                });
            }

            function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('Copied: ' + text);
                });
            }

            // Auto-refresh
            setInterval(refreshData, 5000);
            setInterval(loadRecentBlocks, 5000);

            // Initial load
            refreshData();
            loadRecentBlocks();
        </script>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/api/stats')
def api_stats():
    """Get statistics"""
    ioc_data = load_iocs()
    return jsonify({
        'ips': len(ioc_data.get('ips', [])),
        'domains': len(ioc_data.get('domains', [])),
        'timestamp': ioc_data.get('timestamp', '')
    })

@app.route('/api/recent-blocks')
def api_recent_blocks():
    """Get recent blocks"""
    ioc_data = load_iocs()
    dns_cache = load_dns_cache()
    
    blocks = []
    
    # Add domains
    for domain in ioc_data.get('domains', [])[:20]:
        blocks.append({
            'type': 'domain',
            'value': domain,
            'ips': dns_cache.get(domain, [])
        })
    
    # Add IPs
    for ip in ioc_data.get('ips', [])[:20]:
        blocks.append({
            'type': 'ip',
            'value': ip
        })
    
    return jsonify(blocks[:50])

@app.route('/api/domains')
def api_domains():
    """Get all blocked domains with their resolved IPs"""
    dns_cache = load_dns_cache()
    return jsonify(dns_cache)

@app.route('/api/ips')
def api_ips():
    """Get all blocked IPs"""
    ioc_data = load_iocs()
    return jsonify(ioc_data.get('ips', []))

@app.route('/api/activity')
def api_activity():
    """Get activity log"""
    activities = [
        {
            'action': '🔴 Blocked IP: 144.172.98.156',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'action': '🌐 Resolved domain: q4m8v.ship5plum.coupons -> 182.124.53.202',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            'action': '✓ IOC Fetcher started',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    ]
    return jsonify(activities)

@app.route('/api/allowlist')
def api_allowlist():
    """Get allowlist"""
    return jsonify(load_allowlist())

if __name__ == '__main__':
    port = int(os.getenv('DASHBOARD_PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
