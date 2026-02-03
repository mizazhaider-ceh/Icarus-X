"""
ICARUS-X Dashboard Integration
==============================
Helper functions to push updates to dashboard from CLI commands.
These functions write to the shared state file that the dashboard server watches.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional
import threading

# State file location (shared with server)
STATE_DIR = Path.home() / ".icarus-x"
STATE_FILE = STATE_DIR / "dashboard_state.json"

# Ensure directory exists
STATE_DIR.mkdir(exist_ok=True)

_lock = threading.Lock()


def _load_state() -> dict:
    """Load current state from file."""
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
    except Exception:
        pass
    return _init_state()


def _init_state() -> dict:
    """Create default state."""
    return {
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


def _save_state(state: dict):
    """Save state to file."""
    with _lock:
        try:
            STATE_FILE.write_text(json.dumps(state, indent=2, default=str))
        except Exception:
            pass


# ============================================================================
# PUBLIC API - Call these from CLI commands
# ============================================================================

def dashboard_log(level: str, message: str):
    """
    Add a log entry to the dashboard.
    
    Args:
        level: info, success, warning, error
        message: Log message
    """
    state = _load_state()
    entry = {
        "time": datetime.now().isoformat(),
        "level": level,
        "message": message,
    }
    state.setdefault("logs", []).insert(0, entry)
    state["logs"] = state["logs"][:100]  # Keep last 100
    _save_state(state)


def dashboard_finding(
    target: str,
    title: str,
    severity: str,
    category: str = "",
    details: str = ""
):
    """
    Add a finding to the dashboard.
    
    Args:
        target: Target URL/IP
        title: Finding title
        severity: critical, high, medium, low, info
        category: Category (XSS, SQLi, Port, etc.)
        details: Additional details
    """
    state = _load_state()
    
    finding = {
        "id": len(state.get("findings", [])) + 1,
        "time": datetime.now().isoformat(),
        "target": target,
        "title": title,
        "severity": severity,
        "category": category,
        "details": details,
        "status": "New",
    }
    
    state.setdefault("findings", []).insert(0, finding)
    
    # Update stats
    sev = severity.lower()
    if sev in state.get("stats", {}):
        state["stats"][sev] += 1
    
    _save_state(state)


def dashboard_scan_start(scan_type: str, target: str):
    """
    Record start of a scan.
    
    Args:
        scan_type: Scout, Spider, Vuln, etc.
        target: Target being scanned
    """
    state = _load_state()
    
    scan = {
        "id": len(state.get("scans", [])) + 1,
        "type": scan_type,
        "target": target,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "findings_count": 0,
    }
    
    state.setdefault("scans", []).insert(0, scan)
    state["active_scan"] = scan
    state["stats"]["targets_scanned"] = state["stats"].get("targets_scanned", 0) + 1
    state["progress"] = 0
    
    _save_state(state)
    dashboard_log("info", f"Started {scan_type} scan on {target}")


def dashboard_scan_complete(findings_count: int = 0):
    """
    Mark current scan as complete.
    
    Args:
        findings_count: Number of findings discovered
    """
    state = _load_state()
    
    if state.get("active_scan"):
        scan_id = state["active_scan"].get("id")
        
        # Update active scan
        state["active_scan"]["status"] = "completed"
        state["active_scan"]["findings_count"] = findings_count
        state["active_scan"]["completed_at"] = datetime.now().isoformat()
        
        # Update in scans list
        for scan in state.get("scans", []):
            if scan.get("id") == scan_id:
                scan.update(state["active_scan"])
                break
    
    state["active_scan"] = None
    state["progress"] = 100
    
    _save_state(state)
    dashboard_log("success", f"Scan completed with {findings_count} findings")


def dashboard_progress(percent: int, message: str = ""):
    """
    Update scan progress.
    
    Args:
        percent: Progress percentage (0-100)
        message: Optional status message
    """
    state = _load_state()
    state["progress"] = min(100, max(0, percent))
    if message:
        state["progress_message"] = message
    _save_state(state)


def dashboard_stats_increment(stat_name: str, amount: int = 1):
    """
    Increment a stat counter.
    
    Args:
        stat_name: targets_scanned, critical, high, medium, low, info
        amount: Amount to add
    """
    state = _load_state()
    if stat_name in state.get("stats", {}):
        state["stats"][stat_name] += amount
        _save_state(state)
