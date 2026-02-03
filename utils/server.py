"""
ICARUS-X Dashboard Server v3
============================
Professional real-time dashboard with:
- WebSocket for instant updates
- File watcher for state changes
- Command execution from browser
- Auto-refresh on state file changes
"""

import asyncio
import json
import os
import sys
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Set, Dict, Any, List
import threading
import webbrowser
import hashlib

try:
    from aiohttp import web, WSMsgType
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

from rich.console import Console

console = Console()

# State directory
STATE_DIR = Path.home() / ".icarus-x"
STATE_FILE = STATE_DIR / "dashboard_state.json"
PID_FILE = STATE_DIR / "dashboard.pid"

STATE_DIR.mkdir(exist_ok=True)


# ============================================================================
# STATE MANAGEMENT - Singleton with file watching
# ============================================================================

class DashboardState:
    """Shared state with automatic persistence."""
    
    _instance = None
    _state: Dict[str, Any] = {}
    _last_hash: str = ""
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._load()
        return cls._instance
    
    def _load(self) -> Dict:
        """Load from file."""
        try:
            if STATE_FILE.exists():
                content = STATE_FILE.read_text()
                self._state = json.loads(content)
                self._last_hash = hashlib.md5(content.encode()).hexdigest()
                return self._state
        except Exception as e:
            console.print(f"[dim]State load error: {e}[/dim]")
        return self._init_fresh()
    
    def _init_fresh(self) -> Dict:
        """Create fresh state."""
        self._state = {
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
            "commands": [],
            "active_scan": None,
            "progress": 0,
            "progress_message": "",
        }
        self._save()
        return self._state
    
    def _save(self):
        """Save to file."""
        try:
            content = json.dumps(self._state, indent=2, default=str)
            STATE_FILE.write_text(content)
            self._last_hash = hashlib.md5(content.encode()).hexdigest()
        except Exception as e:
            console.print(f"[dim]State save error: {e}[/dim]")
    
    def has_changed(self) -> bool:
        """Check if file changed externally."""
        try:
            if STATE_FILE.exists():
                content = STATE_FILE.read_text()
                current_hash = hashlib.md5(content.encode()).hexdigest()
                if current_hash != self._last_hash:
                    self._state = json.loads(content)
                    self._last_hash = current_hash
                    return True
        except Exception:
            pass
        return False
    
    def get(self) -> Dict:
        """Get current state, reload if changed."""
        self.has_changed()  # Auto-reload
        return self._state
    
    def add_log(self, level: str, message: str):
        self.has_changed()
        entry = {
            "time": datetime.now().isoformat(),
            "level": level,
            "message": message,
        }
        self._state.setdefault("logs", []).insert(0, entry)
        self._state["logs"] = self._state["logs"][:100]
        self._save()
        return entry
    
    def add_finding(self, target: str, title: str, severity: str,
                    category: str = "", details: str = ""):
        self.has_changed()
        finding = {
            "id": len(self._state.get("findings", [])) + 1,
            "time": datetime.now().isoformat(),
            "target": target,
            "title": title,
            "severity": severity,
            "category": category,
            "details": details,
            "status": "New",
        }
        self._state.setdefault("findings", []).insert(0, finding)
        
        sev = severity.lower()
        if sev in self._state.get("stats", {}):
            self._state["stats"][sev] += 1
        
        self._save()
        return finding


# Global state instance
def get_state() -> DashboardState:
    return DashboardState.get_instance()


# ============================================================================
# WEBSOCKET MANAGER
# ============================================================================

class WebSocketManager:
    """Manage WebSocket connections."""
    
    def __init__(self):
        self.clients: Set[web.WebSocketResponse] = set()
        self._lock = asyncio.Lock()
    
    async def register(self, ws: web.WebSocketResponse):
        async with self._lock:
            self.clients.add(ws)
            get_state().add_log("info", f"Client connected ({len(self.clients)} active)")
    
    async def unregister(self, ws: web.WebSocketResponse):
        async with self._lock:
            self.clients.discard(ws)
    
    async def broadcast(self, data: Dict):
        """Send to all clients."""
        if not self.clients:
            return
        
        msg = json.dumps(data, default=str)
        dead = set()
        
        for ws in list(self.clients):
            try:
                await ws.send_str(msg)
            except Exception:
                dead.add(ws)
        
        async with self._lock:
            self.clients -= dead
    
    async def broadcast_state(self):
        """Broadcast current state to all clients."""
        await self.broadcast({
            "type": "state",
            "state": get_state().get()
        })


ws_manager = WebSocketManager()


# ============================================================================
# COMMAND RUNNER
# ============================================================================

ALLOWED_PREFIXES = ["scout", "spider", "vuln", "pentest", "dirbrute", 
                    "tech", "netmap", "payloads", "tools", "wordlists", "ai"]


class CommandRunner:
    """Execute commands with streaming output."""
    
    def __init__(self):
        self.processes: Dict[int, asyncio.subprocess.Process] = {}
    
    def is_allowed(self, cmd: str) -> bool:
        """Check whitelist."""
        parts = cmd.strip().split()
        for i, p in enumerate(parts):
            if "icarus" in p.lower() and i + 1 < len(parts):
                return parts[i + 1] in ALLOWED_PREFIXES
        return False
    
    async def execute(self, cmd: str, ws: web.WebSocketResponse):
        """Run command and stream output."""
        if not self.is_allowed(cmd):
            await ws.send_json({
                "type": "error",
                "message": "Only ICARUS-X commands allowed!"
            })
            return
        
        get_state().add_log("info", f"Running: {cmd}")
        
        try:
            # Get icarus directory
            icarus_dir = Path(__file__).parent.parent
            
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=str(icarus_dir),
            )
            
            self.processes[proc.pid] = proc
            
            await ws.send_json({
                "type": "command_start",
                "pid": proc.pid,
            })
            
            # Stream output
            while True:
                try:
                    line = await asyncio.wait_for(
                        proc.stdout.readline(),
                        timeout=0.5
                    )
                    if line:
                        text = line.decode('utf-8', errors='replace').rstrip()
                        await ws.send_json({
                            "type": "output",
                            "pid": proc.pid,
                            "text": text,
                        })
                except asyncio.TimeoutError:
                    # Check if process ended
                    if proc.returncode is not None:
                        break
                    continue
                
                if not line:
                    break
            
            await proc.wait()
            
            await ws.send_json({
                "type": "command_done", 
                "pid": proc.pid,
                "code": proc.returncode,
            })
            
            get_state().add_log("success" if proc.returncode == 0 else "error",
                               f"Command finished (code {proc.returncode})")
            
        except Exception as e:
            await ws.send_json({
                "type": "error",
                "message": str(e),
            })
        finally:
            self.processes.pop(proc.pid, None)
    
    async def kill(self, pid: int):
        proc = self.processes.get(pid)
        if proc:
            proc.terminate()
            get_state().add_log("warning", f"Killed process {pid}")


cmd_runner = CommandRunner()


# ============================================================================
# STATE WATCHER - Polls for changes and broadcasts
# ============================================================================

async def state_watcher():
    """Watch state file for changes and broadcast."""
    while True:
        try:
            if get_state().has_changed():
                await ws_manager.broadcast_state()
        except Exception:
            pass
        await asyncio.sleep(0.5)  # Check every 500ms


# ============================================================================
# HTTP HANDLERS
# ============================================================================

async def handle_index(request):
    """Serve dashboard HTML."""
    return web.Response(text=DASHBOARD_HTML, content_type='text/html')


async def handle_api_state(request):
    """Return state as JSON."""
    return web.json_response(get_state().get())


async def handle_websocket(request):
    """WebSocket handler."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    await ws_manager.register(ws)
    
    # Send initial state
    await ws.send_json({
        "type": "init",
        "state": get_state().get(),
    })
    
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    cmd_type = data.get("type")
                    
                    if cmd_type == "run":
                        cmd = data.get("command", "")
                        asyncio.create_task(cmd_runner.execute(cmd, ws))
                    
                    elif cmd_type == "kill":
                        await cmd_runner.kill(data.get("pid", 0))
                    
                    elif cmd_type == "refresh":
                        await ws.send_json({
                            "type": "state",
                            "state": get_state().get(),
                        })
                        
                except json.JSONDecodeError:
                    pass
            
            elif msg.type == WSMsgType.ERROR:
                break
    
    finally:
        await ws_manager.unregister(ws)
    
    return ws


# ============================================================================
# SERVER
# ============================================================================

def create_app() -> web.Application:
    """Create aiohttp app."""
    app = web.Application()
    app.router.add_get('/', handle_index)
    app.router.add_get('/ws', handle_websocket)
    app.router.add_get('/api/state', handle_api_state)
    
    # Start state watcher
    async def start_watcher(app):
        app['watcher'] = asyncio.create_task(state_watcher())
    
    async def stop_watcher(app):
        app['watcher'].cancel()
        try:
            await app['watcher']
        except asyncio.CancelledError:
            pass
    
    app.on_startup.append(start_watcher)
    app.on_cleanup.append(stop_watcher)
    
    return app


def is_server_running() -> bool:
    """Check if server running."""
    if not PID_FILE.exists():
        return False
    
    try:
        data = json.loads(PID_FILE.read_text())
        pid = data.get("pid")
        
        if sys.platform == "win32":
            result = subprocess.run(
                f'tasklist /FI "PID eq {pid}" 2>NUL',
                shell=True, capture_output=True, text=True
            )
            return str(pid) in result.stdout
        else:
            os.kill(pid, 0)
            return True
    except Exception:
        return False


def get_server_port() -> int:
    try:
        if PID_FILE.exists():
            return json.loads(PID_FILE.read_text()).get("port", 8080)
    except Exception:
        pass
    return 8080


def start_server(port: int = 8080, open_browser: bool = True, background: bool = False):
    """Start dashboard server."""
    
    if not HAS_AIOHTTP:
        console.print("[red]aiohttp required![/red]")
        console.print("[dim]pip install aiohttp[/dim]")
        return False
    
    if is_server_running():
        p = get_server_port()
        console.print(f"[yellow]Dashboard already running on port {p}[/yellow]")
        console.print(f"[cyan]Open: http://localhost:{p}[/cyan]")
        console.print("[dim]Use --stop first[/dim]")
        return False
    
    # Init state
    get_state()._init_fresh()
    get_state().add_log("info", "Dashboard started")
    
    if background:
        return start_background(port, open_browser)
    else:
        return run_foreground(port, open_browser)


def run_foreground(port: int, open_browser: bool):
    """Run in foreground."""
    
    PID_FILE.write_text(json.dumps({
        "pid": os.getpid(),
        "port": port,
    }))
    
    console.print()
    console.print("[bold cyan]ICARUS-X Dashboard[/bold cyan]")
    console.print(f"[green]✓ Running at http://localhost:{port}[/green]")
    console.print()
    console.print("[yellow]━━━━━ IMPORTANT ━━━━━[/yellow]")
    console.print("[yellow]Open a NEW terminal to run commands![/yellow]")
    console.print("[dim]All activity will appear on dashboard in real-time[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()
    
    if open_browser:
        webbrowser.open(f"http://localhost:{port}")
    
    try:
        app = create_app()
        web.run_app(app, host="0.0.0.0", port=port, print=None)
    except KeyboardInterrupt:
        pass
    finally:
        PID_FILE.unlink(missing_ok=True)
    
    return True


def start_background(port: int, open_browser: bool):
    """Start as background process."""
    
    script = f'''
import sys
sys.path.insert(0, r"{Path(__file__).parent.parent}")
from utils.server import run_foreground
run_foreground({port}, False)
'''
    
    script_file = STATE_DIR / "_server.py"
    script_file.write_text(script)
    
    if sys.platform == "win32":
        proc = subprocess.Popen(
            [sys.executable, str(script_file)],
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        proc = subprocess.Popen(
            [sys.executable, str(script_file)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    
    time.sleep(1)
    
    console.print()
    console.print("[bold cyan]ICARUS-X Dashboard[/bold cyan]")
    console.print(f"[green]✓ Started in background[/green]")
    console.print(f"[cyan]Open: http://localhost:{port}[/cyan]")
    console.print()
    console.print("[dim]dashboard --status  Check status[/dim]")
    console.print("[dim]dashboard --stop    Stop server[/dim]")
    console.print()
    
    if open_browser:
        webbrowser.open(f"http://localhost:{port}")
    
    return True


def stop_server():
    """Stop server."""
    if not PID_FILE.exists():
        console.print("[yellow]Dashboard not running[/yellow]")
        return False
    
    try:
        data = json.loads(PID_FILE.read_text())
        pid = data.get("pid")
        
        if sys.platform == "win32":
            subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
        
        PID_FILE.unlink(missing_ok=True)
        console.print("[green]✓ Dashboard stopped[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        PID_FILE.unlink(missing_ok=True)
        return False


def server_status():
    """Show status."""
    if is_server_running():
        p = get_server_port()
        console.print(f"[green]✓ Dashboard running[/green]")
        console.print(f"[cyan]URL: http://localhost:{p}[/cyan]")
        
        state = get_state().get()
        stats = state.get("stats", {})
        console.print(f"\n[dim]Targets: {stats.get('targets_scanned', 0)} | "
                     f"Findings: {stats.get('critical', 0)}C {stats.get('high', 0)}H "
                     f"{stats.get('medium', 0)}M {stats.get('low', 0)}L[/dim]")
    else:
        console.print("[yellow]Dashboard not running[/yellow]")
        console.print("[dim]Start: python icarus.py dashboard[/dim]")


# ============================================================================
# DASHBOARD HTML
# ============================================================================

DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ICARUS-X Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0a0a12;
            --card: rgba(255,255,255,0.03);
            --border: rgba(0,255,255,0.15);
            --cyan: #00ffff;
            --green: #00ff88;
            --red: #ff4466;
            --orange: #ff8844;
            --yellow: #ffcc00;
            --purple: #aa88ff;
            --text: #e8e8f0;
            --dim: #666680;
        }
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 20px;
            background: rgba(0,0,0,0.5);
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .logo { font-size: 20px; font-weight: 700; color: var(--cyan); }
        .status {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            padding: 4px 12px;
            border-radius: 20px;
        }
        .status.connected { background: rgba(0,255,136,0.15); color: var(--green); }
        .status.disconnected { background: rgba(255,68,102,0.15); color: var(--red); }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
        .connected .dot { animation: pulse 2s infinite; }
        @keyframes pulse { 50% { opacity: 0.5; } }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 15px; }
        
        .tabs {
            display: flex;
            gap: 4px;
            padding: 10px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 15px;
        }
        .tab {
            padding: 8px 16px;
            background: transparent;
            border: none;
            color: var(--dim);
            cursor: pointer;
            font-size: 13px;
            border-radius: 6px;
        }
        .tab:hover { color: var(--text); background: var(--card); }
        .tab.active { color: var(--cyan); background: rgba(0,255,255,0.1); }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }
        .stat {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px;
            text-align: center;
        }
        .stat-label { font-size: 10px; color: var(--dim); text-transform: uppercase; margin-bottom: 4px; }
        .stat-value { font-size: 24px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
        .stat.critical .stat-value { color: var(--red); }
        .stat.high .stat-value { color: var(--orange); }
        .stat.medium .stat-value { color: var(--yellow); }
        .stat.low .stat-value { color: var(--green); }
        .stat.info .stat-value { color: var(--cyan); }
        
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
        
        .panel {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 10px;
            overflow: hidden;
        }
        .panel-header {
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
            background: rgba(0,0,0,0.3);
            font-size: 12px;
            font-weight: 600;
        }
        .panel-body { padding: 10px 14px; max-height: 300px; overflow-y: auto; }
        
        .terminal {
            background: #0c0c14;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 15px;
        }
        .term-header {
            background: #1a1a28;
            padding: 8px 12px;
            display: flex;
            gap: 6px;
        }
        .term-dot { width: 10px; height: 10px; border-radius: 50%; }
        .term-dot.r { background: #ff5f57; }
        .term-dot.y { background: #febc2e; }
        .term-dot.g { background: #28c840; }
        .term-output {
            padding: 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            min-height: 250px;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.4;
        }
        .term-input-row {
            display: flex;
            padding: 8px 12px;
            background: #1a1a28;
            gap: 8px;
        }
        .term-input {
            flex: 1;
            background: transparent;
            border: none;
            color: var(--cyan);
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            outline: none;
        }
        .term-btn {
            background: var(--cyan);
            color: #000;
            border: none;
            padding: 4px 14px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            font-size: 11px;
        }
        
        .badge { display: inline-block; padding: 2px 8px; border-radius: 8px; font-size: 9px; font-weight: 600; text-transform: uppercase; }
        .badge.critical { background: rgba(255,68,102,0.2); color: var(--red); }
        .badge.high { background: rgba(255,136,68,0.2); color: var(--orange); }
        .badge.medium { background: rgba(255,204,0,0.2); color: var(--yellow); }
        .badge.low { background: rgba(0,255,136,0.2); color: var(--green); }
        .badge.info { background: rgba(0,255,255,0.2); color: var(--cyan); }
        
        .log { padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 11px; font-family: 'JetBrains Mono', monospace; display: flex; gap: 8px; }
        .log-time { color: var(--dim); }
        .log-lvl { padding: 1px 5px; border-radius: 3px; font-size: 9px; }
        .log-lvl.info { background: rgba(0,255,255,0.2); color: var(--cyan); }
        .log-lvl.success { background: rgba(0,255,136,0.2); color: var(--green); }
        .log-lvl.warning { background: rgba(255,204,0,0.2); color: var(--yellow); }
        .log-lvl.error { background: rgba(255,68,102,0.2); color: var(--red); }
        
        .finding { padding: 8px; border-bottom: 1px solid var(--border); }
        .finding-title { font-size: 12px; margin-bottom: 3px; }
        .finding-target { font-size: 10px; color: var(--dim); font-family: 'JetBrains Mono', monospace; }
        
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .hint {
            background: rgba(0,255,255,0.08);
            border: 1px solid var(--cyan);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 15px;
            font-size: 12px;
        }
        .hint code { background: rgba(0,0,0,0.3); padding: 1px 6px; border-radius: 3px; font-family: 'JetBrains Mono', monospace; }
        
        .empty { text-align: center; padding: 30px; color: var(--dim); font-size: 13px; }
        
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
    </style>
</head>
<body>
    <header>
        <div class="logo">⚡ ICARUS-X</div>
        <div class="status connected" id="status">
            <div class="dot"></div><span>Connected</span>
        </div>
    </header>
    
    <div class="container">
        <div class="tabs">
            <button class="tab active" data-tab="overview">📊 Overview</button>
            <button class="tab" data-tab="terminal">💻 Terminal</button>
            <button class="tab" data-tab="findings">🎯 Findings</button>
            <button class="tab" data-tab="logs">📜 Logs</button>
        </div>
        
        <div class="tab-content active" id="tab-overview">
            <div class="hint">
                💡 Open a <strong>new terminal</strong> and run <code>python icarus.py scout --target example.com</code> to see real-time updates!
            </div>
            
            <div class="stats">
                <div class="stat"><div class="stat-label">Scanned</div><div class="stat-value" id="s-targets">0</div></div>
                <div class="stat critical"><div class="stat-label">Critical</div><div class="stat-value" id="s-critical">0</div></div>
                <div class="stat high"><div class="stat-label">High</div><div class="stat-value" id="s-high">0</div></div>
                <div class="stat medium"><div class="stat-label">Medium</div><div class="stat-value" id="s-medium">0</div></div>
                <div class="stat low"><div class="stat-label">Low</div><div class="stat-value" id="s-low">0</div></div>
                <div class="stat info"><div class="stat-label">Info</div><div class="stat-value" id="s-info">0</div></div>
            </div>
            
            <div class="grid">
                <div class="panel">
                    <div class="panel-header">🎯 Recent Findings</div>
                    <div class="panel-body" id="recent-findings"><div class="empty">No findings yet</div></div>
                </div>
                <div class="panel">
                    <div class="panel-header">📜 Activity</div>
                    <div class="panel-body" id="recent-logs"><div class="empty">Waiting for activity...</div></div>
                </div>
            </div>
        </div>
        
        <div class="tab-content" id="tab-terminal">
            <div class="hint">
                🔒 Only ICARUS-X commands allowed: scout, spider, vuln, pentest, dirbrute, tech, netmap, payloads, tools, wordlists, ai
            </div>
            <div class="terminal">
                <div class="term-header">
                    <div class="term-dot r"></div>
                    <div class="term-dot y"></div>
                    <div class="term-dot g"></div>
                </div>
                <div class="term-output" id="term-out">ICARUS-X Terminal Ready
Type a command and press Enter.

Examples:
  python icarus.py scout --target scanme.nmap.org
  python icarus.py payloads --list shells

</div>
                <div class="term-input-row">
                    <span style="color:var(--green)">$</span>
                    <input type="text" class="term-input" id="term-in" placeholder="python icarus.py scout --target ..." autocomplete="off">
                    <button class="term-btn" onclick="runCmd()">Run</button>
                </div>
            </div>
        </div>
        
        <div class="tab-content" id="tab-findings">
            <div class="panel">
                <div class="panel-header">All Findings</div>
                <div class="panel-body" style="max-height:500px" id="all-findings"><div class="empty">No findings</div></div>
            </div>
        </div>
        
        <div class="tab-content" id="tab-logs">
            <div class="panel">
                <div class="panel-header">Full Activity Log</div>
                <div class="panel-body" style="max-height:500px" id="all-logs"><div class="empty">No logs</div></div>
            </div>
        </div>
    </div>
    
    <script>
        let ws = null;
        let state = {};
        let reconnect = null;
        
        // Tabs
        document.querySelectorAll('.tab').forEach(t => {
            t.onclick = () => {
                document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
                t.classList.add('active');
                document.getElementById('tab-' + t.dataset.tab).classList.add('active');
            };
        });
        
        // Terminal
        document.getElementById('term-in').onkeydown = e => { if (e.key === 'Enter') runCmd(); };
        
        function runCmd() {
            const input = document.getElementById('term-in');
            const cmd = input.value.trim();
            if (!cmd) return;
            
            termWrite('\\n$ ' + cmd + '\\n');
            input.value = '';
            
            if (ws && ws.readyState === 1) {
                ws.send(JSON.stringify({ type: 'run', command: cmd }));
            } else {
                termWrite('[ERROR] Not connected\\n');
            }
        }
        
        function termWrite(txt) {
            const out = document.getElementById('term-out');
            out.textContent += txt;
            out.scrollTop = out.scrollHeight;
        }
        
        // WebSocket
        function connect() {
            const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(proto + '//' + location.host + '/ws');
            
            ws.onopen = () => {
                document.getElementById('status').className = 'status connected';
                document.getElementById('status').innerHTML = '<div class="dot"></div><span>Connected</span>';
                clearTimeout(reconnect);
            };
            
            ws.onclose = () => {
                document.getElementById('status').className = 'status disconnected';
                document.getElementById('status').innerHTML = '<div class="dot"></div><span>Disconnected</span>';
                reconnect = setTimeout(connect, 2000);
            };
            
            ws.onmessage = e => {
                const msg = JSON.parse(e.data);
                handleMsg(msg);
            };
        }
        
        function handleMsg(msg) {
            switch(msg.type) {
                case 'init':
                case 'state':
                    state = msg.state;
                    render();
                    break;
                case 'output':
                    termWrite(msg.text + '\\n');
                    break;
                case 'command_start':
                    termWrite('[Running...]\\n');
                    break;
                case 'command_done':
                    termWrite('\\n[Done - exit ' + msg.code + ']\\n\\n');
                    break;
                case 'error':
                    termWrite('[ERROR] ' + msg.message + '\\n');
                    break;
            }
        }
        
        function render() {
            const s = state.stats || {};
            document.getElementById('s-targets').textContent = s.targets_scanned || 0;
            document.getElementById('s-critical').textContent = s.critical || 0;
            document.getElementById('s-high').textContent = s.high || 0;
            document.getElementById('s-medium').textContent = s.medium || 0;
            document.getElementById('s-low').textContent = s.low || 0;
            document.getElementById('s-info').textContent = s.info || 0;
            
            renderFindings();
            renderLogs();
        }
        
        function renderFindings() {
            const f = state.findings || [];
            const html = f.length === 0 ? '<div class="empty">No findings yet</div>' :
                f.map(x => `
                    <div class="finding">
                        <div style="display:flex;justify-content:space-between">
                            <span class="finding-title">${x.title}</span>
                            <span class="badge ${x.severity.toLowerCase()}">${x.severity}</span>
                        </div>
                        <div class="finding-target">${x.target}</div>
                    </div>
                `).join('');
            document.getElementById('recent-findings').innerHTML = f.slice(0,5).length ? html.slice(0, html.indexOf('</div>', html.length - 10) + 6) : html;
            document.getElementById('all-findings').innerHTML = html;
        }
        
        function renderLogs() {
            const l = state.logs || [];
            const html = l.length === 0 ? '<div class="empty">Waiting for activity...</div>' :
                l.map(x => `
                    <div class="log">
                        <span class="log-time">${formatTime(x.time)}</span>
                        <span class="log-lvl ${x.level}">${x.level}</span>
                        <span>${x.message}</span>
                    </div>
                `).join('');
            document.getElementById('recent-logs').innerHTML = l.slice(0,8).map(x => `
                <div class="log">
                    <span class="log-time">${formatTime(x.time)}</span>
                    <span class="log-lvl ${x.level}">${x.level}</span>
                    <span>${x.message}</span>
                </div>
            `).join('') || '<div class="empty">Waiting for activity...</div>';
            document.getElementById('all-logs').innerHTML = html;
        }
        
        function formatTime(iso) {
            try { return new Date(iso).toLocaleTimeString(); } catch { return '--:--'; }
        }
        
        // Auto-refresh state (backup)
        setInterval(() => {
            if (ws && ws.readyState === 1) {
                ws.send(JSON.stringify({ type: 'refresh' }));
            }
        }, 1500);
        
        connect();
    </script>
</body>
</html>'''
