"""
ICARUS-X Directory Brute-forcing Module
=======================================
Wrapper for ffuf, gobuster, and feroxbuster.
"""

import asyncio
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


# Common wordlists (paths may vary)
WORDLISTS = {
    "small": [
        "/usr/share/wordlists/dirb/small.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ],
    "medium": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    ],
    "large": [
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ],
    "api": [
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "/usr/share/wordlists/dirb/vulns/apache.txt",
    ],
}


@dataclass
class DirBruteResult:
    """Result from directory brute-force."""
    url: str
    status_code: int
    size: int
    content_type: Optional[str] = None
    redirect: Optional[str] = None


def find_wordlist(wordlist_type: str = "medium") -> Optional[str]:
    """Find an available wordlist."""
    # First check our local aliases
    if wordlist_type in WORDLISTS:
        for path in WORDLISTS[wordlist_type]:
            if Path(path).exists():
                return path
    
    # Check if it's a direct path
    if Path(wordlist_type).exists():
        return wordlist_type
    
    # Try the wordlist manager
    try:
        from utils.wordlists import get_wordlist_path
        manager_path = get_wordlist_path(wordlist_type)
        if manager_path:
            return manager_path
    except ImportError:
        pass
    
    # Fallback: check common locations
    common_paths = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]
    for path in common_paths:
        if Path(path).exists():
            return path
    
    return None


def get_available_tool() -> Optional[str]:
    """Get the best available directory brute-force tool."""
    tools = ["ffuf", "feroxbuster", "gobuster"]
    for tool in tools:
        if shutil.which(tool):
            return tool
    return None


async def run_ffuf(
    url: str,
    wordlist: str,
    extensions: list[str] = None,
    threads: int = 50,
    timeout: int = 300,
    filter_codes: list[int] = None,
) -> list[DirBruteResult]:
    """Run ffuf for directory brute-forcing."""
    results = []
    
    # Build command
    cmd = [
        "ffuf",
        "-u", f"{url.rstrip('/')}/FUZZ",
        "-w", wordlist,
        "-t", str(threads),
        "-timeout", "10",
        "-o", "/tmp/ffuf_output.json",
        "-of", "json",
        "-mc", "200,201,202,203,204,301,302,307,308,401,403,405,500",
    ]
    
    if extensions:
        cmd.extend(["-e", ",".join(f".{e}" for e in extensions)])
    
    if filter_codes:
        cmd.extend(["-fc", ",".join(str(c) for c in filter_codes)])
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
        
        # Parse JSON output
        output_file = Path("/tmp/ffuf_output.json")
        if output_file.exists():
            import json
            with open(output_file) as f:
                data = json.load(f)
            
            for result in data.get("results", []):
                results.append(DirBruteResult(
                    url=result.get("url", ""),
                    status_code=result.get("status", 0),
                    size=result.get("length", 0),
                    content_type=result.get("content-type"),
                    redirect=result.get("redirectlocation"),
                ))
            
            output_file.unlink()  # Cleanup
    
    except asyncio.TimeoutError:
        console.print("[yellow]ffuf timed out[/yellow]")
    except Exception as e:
        console.print(f"[red]ffuf error: {e}[/red]")
    
    return results


async def run_gobuster(
    url: str,
    wordlist: str,
    extensions: list[str] = None,
    threads: int = 50,
    timeout: int = 300,
) -> list[DirBruteResult]:
    """Run gobuster for directory brute-forcing."""
    results = []
    
    cmd = [
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist,
        "-t", str(threads),
        "-q",  # Quiet mode
        "--no-progress",
    ]
    
    if extensions:
        cmd.extend(["-x", ",".join(extensions)])
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
        
        # Parse output (format: /path (Status: 200) [Size: 1234])
        for line in stdout.decode().splitlines():
            if "(Status:" in line:
                try:
                    parts = line.split()
                    path = parts[0]
                    status = int(line.split("Status:")[1].split(")")[0].strip())
                    size = int(line.split("Size:")[1].split("]")[0].strip())
                    
                    results.append(DirBruteResult(
                        url=f"{url.rstrip('/')}{path}",
                        status_code=status,
                        size=size,
                    ))
                except Exception:
                    pass
    
    except asyncio.TimeoutError:
        console.print("[yellow]gobuster timed out[/yellow]")
    except Exception as e:
        console.print(f"[red]gobuster error: {e}[/red]")
    
    return results


async def run_dirbrute(
    url: str,
    wordlist: str = "medium",
    extensions: list[str] = None,
    threads: int = 50,
    timeout: int = 300,
    tool: str = None,
) -> list[DirBruteResult]:
    """
    Run directory brute-forcing with best available tool.
    
    Args:
        url: Target URL
        wordlist: Wordlist name (small, medium, large) or path
        extensions: File extensions to check (e.g., ["php", "html"])
        threads: Number of concurrent threads
        timeout: Maximum runtime in seconds
        tool: Force specific tool (ffuf, gobuster, feroxbuster)
    
    Returns:
        List of discovered paths
    """
    # Find wordlist
    wordlist_path = find_wordlist(wordlist)
    if not wordlist_path:
        console.print(f"[red]Wordlist not found: {wordlist}[/red]")
        console.print("[dim]Install SecLists: sudo apt install seclists[/dim]")
        return []
    
    # Get tool
    if tool:
        if not shutil.which(tool):
            console.print(f"[red]Tool not found: {tool}[/red]")
            return []
    else:
        tool = get_available_tool()
        if not tool:
            console.print("[red]No directory brute-force tool found![/red]")
            console.print("[dim]Install: sudo apt install ffuf gobuster[/dim]")
            return []
    
    console.print(f"[dim]Using {tool} with wordlist: {wordlist_path}[/dim]")
    
    # Run appropriate tool
    if tool == "ffuf":
        return await run_ffuf(url, wordlist_path, extensions, threads, timeout)
    elif tool == "gobuster":
        return await run_gobuster(url, wordlist_path, extensions, threads, timeout)
    else:
        console.print(f"[yellow]Tool {tool} not implemented, using ffuf[/yellow]")
        return await run_ffuf(url, wordlist_path, extensions, threads, timeout)


def display_dirbrute_results(results: list[DirBruteResult]):
    """Display directory brute-force results."""
    if not results:
        console.print("[dim]No results found[/dim]")
        return
    
    table = Table(title="Directory Brute-force Results", show_header=True, header_style="bold cyan")
    table.add_column("URL", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Size", justify="right")
    table.add_column("Redirect", style="dim")
    
    for result in sorted(results, key=lambda x: x.status_code):
        # Color code status
        if 200 <= result.status_code < 300:
            status = f"[green]{result.status_code}[/green]"
        elif 300 <= result.status_code < 400:
            status = f"[yellow]{result.status_code}[/yellow]"
        elif result.status_code in [401, 403]:
            status = f"[red]{result.status_code}[/red]"
        else:
            status = str(result.status_code)
        
        table.add_row(
            result.url,
            status,
            str(result.size),
            result.redirect or "-",
        )
    
    console.print(table)
