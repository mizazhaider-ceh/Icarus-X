"""
ICARUS-X Tool Checker
=====================
Checks for required external tools and provides install commands.
"""

import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel


console = Console()


@dataclass
class Tool:
    """External tool definition."""
    name: str
    command: str
    description: str
    install_apt: Optional[str] = None
    install_go: Optional[str] = None
    install_pip: Optional[str] = None
    url: Optional[str] = None
    required: bool = False


# Tool definitions with install commands
TOOLS = [
    Tool(
        name="nmap",
        command="nmap",
        description="Network scanner & port detection",
        install_apt="sudo apt install nmap",
        required=True,
    ),
    Tool(
        name="ffuf",
        command="ffuf",
        description="Fast web fuzzer (directory brute-force)",
        install_apt="sudo apt install ffuf",
        install_go="go install github.com/ffuf/ffuf/v2@latest",
        url="https://github.com/ffuf/ffuf",
    ),
    Tool(
        name="gobuster",
        command="gobuster",
        description="Directory/DNS/vhost brute-forcing",
        install_apt="sudo apt install gobuster",
        install_go="go install github.com/OJ/gobuster/v3@latest",
    ),
    Tool(
        name="nuclei",
        command="nuclei",
        description="Vulnerability scanner with templates",
        install_apt="sudo apt install nuclei",
        install_go="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        url="https://github.com/projectdiscovery/nuclei",
    ),
    Tool(
        name="httpx",
        command="httpx",
        description="Fast HTTP toolkit (probing)",
        install_go="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    ),
    Tool(
        name="subfinder",
        command="subfinder",
        description="Subdomain discovery tool",
        install_go="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    Tool(
        name="amass",
        command="amass",
        description="OWASP subdomain enumeration",
        install_apt="sudo apt install amass",
        install_go="go install -v github.com/owasp-amass/amass/v4/...@master",
    ),
    Tool(
        name="whatweb",
        command="whatweb",
        description="Web technology fingerprinting",
        install_apt="sudo apt install whatweb",
    ),
    Tool(
        name="wappalyzer",
        command="wappalyzer",
        description="Technology detection (npm)",
        install_pip="pip install python-Wappalyzer",
    ),
    Tool(
        name="nikto",
        command="nikto",
        description="Web vulnerability scanner",
        install_apt="sudo apt install nikto",
    ),
    Tool(
        name="sqlmap",
        command="sqlmap",
        description="SQL injection detection & exploitation",
        install_apt="sudo apt install sqlmap",
    ),
    Tool(
        name="hydra",
        command="hydra",
        description="Password brute-forcing",
        install_apt="sudo apt install hydra",
    ),
    Tool(
        name="feroxbuster",
        command="feroxbuster",
        description="Fast content discovery (Rust)",
        install_apt="sudo apt install feroxbuster",
        url="https://github.com/epi052/feroxbuster",
    ),
    Tool(
        name="dirsearch",
        command="dirsearch",
        description="Web path discovery",
        install_pip="pip install dirsearch",
        url="https://github.com/maurosoria/dirsearch",
    ),
]


def check_tool(tool: Tool) -> bool:
    """Check if a tool is installed."""
    return shutil.which(tool.command) is not None


def get_tool_version(tool: Tool) -> Optional[str]:
    """Try to get tool version."""
    try:
        result = subprocess.run(
            [tool.command, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Get first line of output
        output = result.stdout.strip() or result.stderr.strip()
        if output:
            return output.split("\n")[0][:50]
    except Exception:
        pass
    return None


def check_all_tools() -> dict[str, dict]:
    """Check all tools and return status."""
    results = {}
    for tool in TOOLS:
        installed = check_tool(tool)
        version = get_tool_version(tool) if installed else None
        results[tool.name] = {
            "installed": installed,
            "version": version,
            "tool": tool,
        }
    return results


def display_tool_status():
    """Display tool status in a rich table."""
    console.print("\n[bold cyan]ICARUS-X Tool Checker[/bold cyan]\n")
    
    results = check_all_tools()
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Tool", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Description", style="dim")
    table.add_column("Version", style="dim")
    
    installed_count = 0
    missing_tools = []
    
    for name, info in results.items():
        tool = info["tool"]
        if info["installed"]:
            status = "[bold green]OK[/bold green]"
            installed_count += 1
        else:
            status = "[bold red]MISSING[/bold red]"
            missing_tools.append(tool)
        
        version = info["version"] or "-"
        table.add_row(name, status, tool.description, version)
    
    console.print(table)
    console.print(f"\n[dim]Installed: {installed_count}/{len(TOOLS)}[/dim]")
    
    # Show install commands for missing tools
    if missing_tools:
        console.print("\n[bold yellow]Install Missing Tools:[/bold yellow]\n")
        
        # Group by install method
        apt_tools = [t for t in missing_tools if t.install_apt]
        go_tools = [t for t in missing_tools if t.install_go and not t.install_apt]
        pip_tools = [t for t in missing_tools if t.install_pip and not t.install_apt]
        
        if apt_tools:
            console.print("[bold]APT (Debian/Kali):[/bold]")
            # Combine apt installs
            packages = " ".join([t.command for t in apt_tools])
            console.print(f"  sudo apt install {packages}")
        
        if go_tools:
            console.print("\n[bold]Go Install:[/bold]")
            for tool in go_tools:
                console.print(f"  {tool.install_go}")
        
        if pip_tools:
            console.print("\n[bold]Pip Install:[/bold]")
            for tool in pip_tools:
                console.print(f"  {tool.install_pip}")
    
    return results


def require_tool(tool_name: str) -> bool:
    """Check if a tool is available, show error if not."""
    tool = next((t for t in TOOLS if t.name == tool_name), None)
    if not tool:
        console.print(f"[red]Unknown tool: {tool_name}[/red]")
        return False
    
    if not check_tool(tool):
        console.print(Panel(
            f"[bold red]Tool not found: {tool_name}[/bold red]\n\n"
            f"{tool.description}\n\n"
            f"[bold]Install with:[/bold]\n"
            f"  {tool.install_apt or tool.install_go or tool.install_pip}",
            title="Missing Dependency",
            border_style="red",
        ))
        return False
    
    return True


def get_tool_path(tool_name: str) -> Optional[str]:
    """Get full path to a tool."""
    return shutil.which(tool_name)
