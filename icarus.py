#!/usr/bin/env python3
"""
ICARUS-X: Unified AI-Powered Pentesting Framework
==================================================
One CLI, multiple modes:
  - scout: High-speed async reconnaissance
  - pentest: Full workflow orchestration
  - ai: AI-powered command advisor & explainer
  - vuln: Nuclei CVE scanning
  - dirbrute: Directory brute-forcing
  - tech: Technology detection
  - tools: Check installed tools
  - wordlists: Manage and browse wordlists
  - spider: Web application crawler
  - payloads: Payload generator (XSS, SQLi, shells)
  - netmap: Network discovery & mapping
  - dashboard: Live web dashboard

Usage:
  python icarus.py scout --target example.com
  python icarus.py pentest --target example.com --workflow full
  python icarus.py ai --query "explain CVE-2024-1234"
  python icarus.py vuln --target https://example.com
  python icarus.py dirbrute --target https://example.com
  python icarus.py tech --target https://example.com
  python icarus.py spider --target https://example.com --depth 5
  python icarus.py payloads --list shells
  python icarus.py payloads --type bash --ip 10.10.14.5 --port 4444
  python icarus.py netmap --range 192.168.1.0/24
  python icarus.py dashboard --port 8080
  python icarus.py tools
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import Optional

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()  # Load .env file if it exists

# Fix Windows console encoding
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.text import Text
from rich import print as rprint

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import ReconEngine
from core.workflow import WorkflowManager
from core.ai_engine import AIEngine
from core.reporter import ReportGenerator
from utils.logger import setup_logger, get_logger
from utils.config import load_config

# Initialize Typer app with Rich
app = typer.Typer(
    name="icarus-x",
    help="""[bold cyan]ICARUS-X[/bold cyan]: Unified AI-Powered Pentesting Framework
    
[bold]Fast, Async, Comprehensive Security Testing[/bold]

[dim]One CLI to rule them all - 13+ security modules unified:[/dim]
  • High-speed reconnaissance (500+ concurrent scans)
  • Vulnerability detection with Nuclei
  • Directory brute-forcing (ffuf/gobuster)
  • Payload generation (XSS, SQLi, shells)
  • AI-powered assistance (Cerebras AI - world's fastest)
  • Professional HTML/JSON reports
  • Mass target scanning (CIDR/ranges)

[bold yellow]Quick Start Examples:[/bold yellow]
  [cyan]# Check which tools are installed[/cyan]
  python icarus.py tools
  
  [cyan]# Fast reconnaissance on a target[/cyan]
  python icarus.py scout -t example.com
  python icarus.py scout -t example.com --ports 80,443,8080 --tech
  
  [cyan]# Scan multiple targets from file[/cyan]
  python icarus.py scout --targets targets.txt
  
  [cyan]# Directory brute-forcing[/cyan]
  python icarus.py dirbrute -t https://example.com
  python icarus.py dirbrute -t https://example.com --ext php,html
  
  [cyan]# Vulnerability scanning with Nuclei[/cyan]
  python icarus.py vuln -t https://example.com
  python icarus.py vuln -t https://example.com --severity critical,high
  
  [cyan]# Generate attack payloads[/cyan]
  python icarus.py payloads --list shells
  python icarus.py payloads --type bash --ip 10.10.14.5 --port 4444
  python icarus.py payloads --list xss
  
  [cyan]# AI-powered assistance (requires CEREBRAS_API_KEY)[/cyan]
  python icarus.py ai --commands --goal "enumerate SMB shares"
  python icarus.py ai --explain CVE-2024-1234
  
  [cyan]# Full pentest workflow[/cyan]
  python icarus.py pentest -t example.com --workflow full
  python icarus.py runs list
  python icarus.py report --run-id abc123 --format html
  
  [cyan]# Browse wordlists[/cyan]
  python icarus.py wordlists --scan
  python icarus.py wordlists --path rockyou

[bold magenta]Advanced Usage:[/bold magenta]
  [cyan]# Network discovery with CIDR[/cyan]
  python icarus.py netmap --range 192.168.1.0/24
  
  [cyan]# Technology fingerprinting[/cyan]
  python icarus.py tech -t https://example.com
  
  [cyan]# Web crawling/spidering[/cyan]
  python icarus.py spider -t https://example.com --depth 3
  
  [cyan]# Save output to file[/cyan]
  python icarus.py scout -t example.com -o results.json --format json
  
[bold cyan]Documentation:[/bold cyan] 
  • SETUP.md   - Installation guide
  • README.md  - Full documentation
  • PORTFOLIO.md - Project showcase
  
[bold green]Legal:[/bold green] ⚠️  Always obtain authorization before testing!
    """,
    add_completion=False,
    rich_markup_mode="rich",
    epilog="[dim]ICARUS-X v2.0 - Ethical Hacking Only | GitHub: https://github.com/mizazhaider-ceh/Icarus-X[/dim]"
)
console = Console(force_terminal=True)

# ASCII Banner (Windows-safe)
BANNER = """
[bold cyan]
 ___ ____    _    ____  _   _ ____        __  __
|_ _/ ___|  / \\  |  _ \\| | | / ___|      \\ \\/ /
 | | |     / _ \\ | |_) | | | \\___ \\  _____\\  / 
 | | |___ / ___ \\|  _ <| |_| |___) ||_____/  \\ 
|___|\\____/_/   \\_\\_| \\_\\\\___/|____/      /_/\\_\\
[/bold cyan]
[dim]Unified AI-Powered Pentesting Framework v2.0[/dim]
"""


def show_banner():
    """Display the ICARUS-X banner."""
    console.print(Panel(BANNER, border_style="cyan", expand=False))


# ============================================================================
# TOOLS COMMAND - Check installed tools
# ============================================================================
@app.command()
def tools():
    """
    [bold yellow]Tool Checker[/bold yellow] - Verify installed pentesting tools
    
    Checks for required tools like nmap, ffuf, nuclei, etc.
    Shows install commands for missing tools.
    """
    show_banner()
    from utils.tools import display_tool_status
    from utils.dashboard_integration import dashboard_log
    
    dashboard_log("info", "Checking installed tools")
    display_tool_status()


# ============================================================================
# WORDLISTS COMMAND - Manage wordlists
# ============================================================================
@app.command()
def wordlists(
    category: str = typer.Option(None, "--category", "-c", help="Filter by category (dir, pass, fuzz, api, etc.)"),
    search: str = typer.Option(None, "--search", "-s", help="Search for wordlists"),
    path: str = typer.Option(None, "--path", "-p", help="Get path for a wordlist by name"),
    scan: bool = typer.Option(False, "--scan", help="Scan all wordlist folders and show files"),
    folder: str = typer.Option(None, "--folder", "-f", help="Browse a specific folder"),
    locations: bool = typer.Option(False, "--locations", "-l", help="Show all wordlist folder locations"),
    table_view: bool = typer.Option(False, "--table", "-t", help="Show in compact table format"),
    show_all: bool = typer.Option(False, "--all", "-a", help="Show all including missing wordlists"),
):
    """
    [bold green]Wordlist Manager[/bold green] - Browse and find wordlists
    
    Categories:
    - Directory Bruteforce: Web path discovery
    - Subdomain Enumeration: DNS enumeration
    - Password Attacks: Cracking & brute-force
    - Username Enumeration: User discovery
    - Fuzzing: LFI, SQLi, XSS payloads
    - API Testing: API endpoint discovery
    - Technology Specific: CMS-specific paths
    
    [dim]Example: python icarus.py wordlists --scan[/dim]
    [dim]Example: python icarus.py wordlists --folder /usr/share/wordlists[/dim]
    [dim]Example: python icarus.py wordlists --path rockyou[/dim]
    """
    show_banner()
    from utils.wordlists import (
        display_wordlists, display_wordlists_table, 
        display_search_results, get_wordlist_path,
        install_seclists_instructions, display_all_wordlists,
        display_folder_contents, list_wordlist_folders
    )
    
    # Scan all wordlist folders
    if scan:
        display_all_wordlists()
        return
    
    # Browse specific folder
    if folder:
        display_folder_contents(folder)
        return
    
    # Show wordlist locations
    if locations:
        list_wordlist_folders()
        return
    
    if path:
        # Get path for a specific wordlist
        wordlist_path = get_wordlist_path(path)
        if wordlist_path:
            console.print(f"\n[green]Wordlist:[/green] {path}")
            console.print(f"[cyan]Path:[/cyan] {wordlist_path}\n")
        else:
            console.print(f"\n[red]Wordlist not found: {path}[/red]")
            console.print("[dim]Use 'wordlists --search <term>' to find wordlists[/dim]\n")
        return
    
    if search:
        display_search_results(search)
        return
    
    if table_view:
        display_wordlists_table(category)
    else:
        display_wordlists(category, show_missing=show_all)
    
    # Quick reference
    console.print("\n[bold]Quick Reference:[/bold]")
    console.print("[dim]  --scan              - Scan ALL wordlist folders[/dim]")
    console.print("[dim]  --locations         - Show folder locations[/dim]")
    console.print("[dim]  --folder /path      - Browse specific folder[/dim]")
    console.print("[dim]  --path rockyou      - Get path for wordlist[/dim]")
    console.print("[dim]  --search sqli       - Search wordlists[/dim]")


# ============================================================================
# SCOUT MODE - High-Speed Reconnaissance
# ============================================================================
@app.command()
def scout(
    target: str = typer.Option(None, "--target", "-t", help="Target domain or IP address"),
    targets_file: str = typer.Option(None, "--targets", "-T", help="File with list of targets"),
    ports: str = typer.Option(
        "top-1000", "--ports", "-p", help="Ports to scan: top-1000, full, or comma-separated"
    ),
    subdomains: bool = typer.Option(True, "--subdomains/--no-subdomains", help="Run subdomain enumeration"),
    whois_lookup: bool = typer.Option(True, "--whois/--no-whois", help="Run WHOIS lookup"),
    http_probe: bool = typer.Option(True, "--http/--no-http", help="Probe HTTP services"),
    tech_detect: bool = typer.Option(False, "--tech", help="Detect technologies"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    [bold green]Scout Mode[/bold green] - High-speed async reconnaissance
    
    Performs fast, parallel reconnaissance including:
    - Async port scanning (500+ concurrent connections)
    - Subdomain enumeration (aiodns)
    - HTTP service probing (httpx)
    - WHOIS lookups
    - Technology detection (optional)
    
    [dim]Example: python icarus.py scout --target scanme.nmap.org --ports 22,80,443[/dim]
    """
    show_banner()
    
    # Handle target from file or command line
    if not target and not targets_file:
        console.print("[red]Please provide --target or --targets file[/red]")
        raise typer.Exit(1)
    
    # Load targets from file
    scan_targets = []
    if targets_file:
        from modules.targets import load_targets_from_file, display_targets_summary
        targets_list = load_targets_from_file(targets_file)
        scan_targets = [t.value for t in targets_list]
        display_targets_summary(targets_list)
    elif target:
        scan_targets = [target]
    
    console.print(f"\n[bold green]Scout Mode[/bold green] - Scanning {len(scan_targets)} target(s)\n")
    
    # Load config
    config = load_config()
    setup_logger(config, verbose)
    logger = get_logger()
    
    # Dashboard integration
    from utils.dashboard_integration import (
        dashboard_log, dashboard_finding, dashboard_scan_start,
        dashboard_scan_complete, dashboard_progress
    )
    
    # Initialize scanner
    engine = ReconEngine(config)
    
    # Run async scan for each target
    try:
        total = len(scan_targets)
        for idx, tgt in enumerate(scan_targets):
            console.print(f"\n[cyan]Scanning: {tgt}[/cyan]")
            
            # Push to dashboard
            dashboard_scan_start("Scout", tgt)
            dashboard_progress(int((idx / total) * 100), f"Scanning {tgt}")
            
            results = asyncio.run(engine.run_recon(
                target=tgt,
                ports=ports,
                run_subdomains=subdomains,
                run_whois=whois_lookup,
                run_http=http_probe,
            ))
            
            # Display results
            _display_recon_results(results, format, output)
            
            # Push findings to dashboard
            if results.open_ports:
                for port_info in results.open_ports[:10]:
                    dashboard_finding(
                        target=tgt,
                        title=f"Open port: {port_info.port}/{port_info.protocol}",
                        severity="info",
                        category="Port Scan",
                        details=port_info.service or ""
                    )
            
            if results.subdomains:
                dashboard_finding(
                    target=tgt,
                    title=f"Found {len(results.subdomains)} subdomains",
                    severity="info",
                    category="Subdomain",
                )
            
            # Mark scan complete
            findings_count = len(results.open_ports) + len(results.subdomains)
            dashboard_scan_complete(findings_count)
            
            # Tech detection if enabled
            if tech_detect and results.http_services:
                from modules.techdetect import detect_technologies, display_technologies
                for svc in results.http_services[:5]:
                    techs = asyncio.run(detect_technologies(svc.url))
                    if techs:
                        display_technologies(techs)
        
        dashboard_log("success", f"Scout completed for {total} target(s)")
        console.print("\n[bold green]Scout complete![/bold green]")
        
    except KeyboardInterrupt:
        dashboard_log("warning", "Scan interrupted by user")
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        dashboard_log("error", f"Scout failed: {str(e)}")
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        logger.exception("Scout failed")
        raise typer.Exit(1)


def _display_recon_results(results, format: str, output: Optional[str]):
    """Display reconnaissance results in the specified format."""
    if format == "json":
        import orjson
        json_output = orjson.dumps(results.model_dump(), option=orjson.OPT_INDENT_2).decode()
        if output:
            Path(output).write_text(json_output)
            console.print(f"[dim]Results saved to {output}[/dim]")
        else:
            console.print(json_output)
    else:
        # Rich table display
        # Port scan results
        if results.open_ports:
            table = Table(title="Open Ports", show_header=True, header_style="bold cyan")
            table.add_column("Port", style="green")
            table.add_column("State", style="yellow")
            table.add_column("Service", style="white")
            
            for port_info in results.open_ports:
                table.add_row(
                    str(port_info.port),
                    port_info.state,
                    port_info.service or "unknown"
                )
            console.print(table)
        
        # Subdomain results
        if results.subdomains:
            table = Table(title="Subdomains Found", show_header=True, header_style="bold cyan")
            table.add_column("Subdomain", style="green")
            table.add_column("IP Addresses", style="white")
            
            for sub in results.subdomains[:20]:  # Limit display
                table.add_row(sub.name, ", ".join(sub.resolved_ips))
            
            if len(results.subdomains) > 20:
                console.print(f"[dim]...and {len(results.subdomains) - 20} more[/dim]")
            console.print(table)
        
        # HTTP services
        if results.http_services:
            table = Table(title="HTTP Services", show_header=True, header_style="bold cyan")
            table.add_column("URL", style="cyan")
            table.add_column("Status", style="yellow")
            table.add_column("Title", style="white")
            
            for svc in results.http_services:
                status_color = "green" if 200 <= svc.status_code < 300 else "yellow"
                table.add_row(
                    svc.url,
                    f"[{status_color}]{svc.status_code}[/{status_color}]",
                    svc.title[:50] if svc.title else "-"
                )
            console.print(table)
        
        # WHOIS info
        if results.whois:
            console.print(Panel(
                f"[bold]Registrar:[/bold] {results.whois.registrar or 'N/A'}\n"
                f"[bold]Created:[/bold] {results.whois.creation_date or 'N/A'}\n"
                f"[bold]Expires:[/bold] {results.whois.expiration_date or 'N/A'}\n"
                f"[bold]Org:[/bold] {results.whois.org or 'N/A'}",
                title="WHOIS Info",
                border_style="dim"
            ))
        
        # Save to file if requested
        if output:
            import orjson
            Path(output).write_text(
                orjson.dumps(results.model_dump(), option=orjson.OPT_INDENT_2).decode()
            )
            console.print(f"[dim]Results saved to {output}[/dim]")


# ============================================================================
# DIRBRUTE COMMAND - Directory Brute-forcing
# ============================================================================
@app.command()
def dirbrute(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    wordlist: str = typer.Option("medium", "--wordlist", "-w", help="Wordlist: small, medium, large, or path"),
    extensions: str = typer.Option(None, "--ext", "-e", help="File extensions (comma-separated, e.g., php,html,txt)"),
    threads: int = typer.Option(50, "--threads", help="Number of threads"),
    tool: str = typer.Option(None, "--tool", help="Force tool: ffuf, gobuster, feroxbuster"),
    timeout: int = typer.Option(300, "--timeout", help="Timeout in seconds"),
):
    """
    [bold magenta]Directory Brute-force[/bold magenta] - Find hidden paths
    
    Uses ffuf, gobuster, or feroxbuster to discover:
    - Hidden directories
    - Backup files
    - Admin panels
    - API endpoints
    
    [dim]Example: python icarus.py dirbrute --target https://example.com --ext php,html[/dim]
    """
    show_banner()
    console.print(f"\n[bold magenta]Directory Brute-force[/bold magenta] - Target: [cyan]{target}[/cyan]\n")
    
    from modules.dirbrute import run_dirbrute, display_dirbrute_results, get_available_tool
    from utils.tools import require_tool
    from utils.dashboard_integration import dashboard_scan_start, dashboard_scan_complete, dashboard_finding, dashboard_log
    
    # Push to dashboard
    dashboard_scan_start("DirBrute", target)
    
    # Check for required tools
    if tool:
        if not require_tool(tool):
            raise typer.Exit(1)
    else:
        available = get_available_tool()
        if not available:
            console.print("[red]No directory brute-force tool found![/red]")
            console.print("[dim]Install: sudo apt install ffuf gobuster[/dim]")
            raise typer.Exit(1)
    
    ext_list = extensions.split(",") if extensions else None
    
    try:
        results = asyncio.run(run_dirbrute(
            url=target,
            wordlist=wordlist,
            extensions=ext_list,
            threads=threads,
            timeout=timeout,
            tool=tool,
        ))
        
        display_dirbrute_results(results)
        console.print(f"\n[bold green]Found {len(results)} paths![/bold green]")
        
        # Push findings to dashboard
        for r in results[:50]:
            dashboard_finding(target, f"Path: {r.get('path', r)}", "info", "Directory")
        dashboard_scan_complete(len(results))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")
        dashboard_log("warning", "DirBrute scan interrupted")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        dashboard_log("error", f"DirBrute error: {e}")
        raise typer.Exit(1)


# ============================================================================
# VULN COMMAND - Nuclei Vulnerability Scanning
# ============================================================================
@app.command()
def vuln(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    severity: str = typer.Option("critical,high,medium", "--severity", "-s", help="Severity levels"),
    tags: str = typer.Option(None, "--tags", help="Template tags (cve, rce, sqli, etc.)"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick scan (critical/high only)"),
    output: str = typer.Option(None, "--output", "-o", help="Output file for results"),
    timeout: int = typer.Option(600, "--timeout", help="Timeout in seconds"),
):
    """
    [bold red]Vulnerability Scan[/bold red] - Nuclei CVE detection
    
    Scans for known vulnerabilities using Nuclei templates:
    - CVE exploits
    - Misconfigurations
    - Default credentials
    - Exposed panels
    
    [dim]Example: python icarus.py vuln --target https://example.com --quick[/dim]
    """
    show_banner()
    console.print(f"\n[bold red]Vulnerability Scan[/bold red] - Target: [cyan]{target}[/cyan]\n")
    
    from modules.nuclei import run_nuclei, quick_vuln_scan, display_nuclei_results, is_nuclei_installed
    from utils.tools import require_tool
    from utils.dashboard_integration import dashboard_scan_start, dashboard_scan_complete, dashboard_finding, dashboard_log
    
    # Push to dashboard
    dashboard_scan_start("Vuln Scan", target)
    
    # Check nuclei is installed
    if not is_nuclei_installed():
        console.print("[red]Nuclei not installed![/red]")
        console.print("[dim]Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/dim]")
        console.print("[dim]Or: sudo apt install nuclei[/dim]")
        raise typer.Exit(1)
    
    try:
        if quick:
            results = asyncio.run(quick_vuln_scan(target, timeout))
        else:
            severity_list = severity.split(",")
            tags_list = tags.split(",") if tags else None
            
            results = asyncio.run(run_nuclei(
                target=target,
                severity=severity_list,
                tags=tags_list,
                timeout=timeout,
                output_file=output,
            ))
        
        display_nuclei_results(results)
        
        # Push findings to dashboard
        for r in results:
            sev = r.get('severity', 'info').lower()
            dashboard_finding(target, r.get('name', r.get('template', 'Unknown')), sev, "Vulnerability", r.get('description', ''))
        dashboard_scan_complete(len(results))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")
        dashboard_log("warning", "Vuln scan interrupted")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        dashboard_log("error", f"Vuln scan error: {e}")
        raise typer.Exit(1)


# ============================================================================
# TECH COMMAND - Technology Detection
# ============================================================================
@app.command()
def tech(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
):
    """
    [bold blue]Technology Detection[/bold blue] - Fingerprint web technologies
    
    Detects:
    - Web servers (nginx, Apache, IIS)
    - CMS (WordPress, Drupal, Joomla)
    - Frameworks (React, Vue, Angular, Django)
    - CDN & Security (Cloudflare, AWS)
    
    [dim]Example: python icarus.py tech --target https://example.com[/dim]
    """
    show_banner()
    console.print(f"\n[bold blue]Technology Detection[/bold blue] - Target: [cyan]{target}[/cyan]\n")
    
    from modules.techdetect import detect_technologies, display_technologies, fingerprint_target
    from utils.dashboard_integration import dashboard_scan_start, dashboard_scan_complete, dashboard_finding, dashboard_log
    
    # Push to dashboard
    dashboard_scan_start("Tech Detect", target)
    
    try:
        technologies = asyncio.run(detect_technologies(target))
        display_technologies(technologies)
        
        # Push findings
        for tech in technologies:
            if isinstance(tech, dict):
                dashboard_finding(target, f"Tech: {tech.get('name', tech)}", "info", tech.get('category', 'Technology'))
            else:
                dashboard_finding(target, f"Tech: {tech}", "info", "Technology")
        dashboard_scan_complete(len(technologies))
        
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        dashboard_log("error", f"Tech detect error: {e}")
        raise typer.Exit(1)


# ============================================================================
# SPIDER COMMAND - Web Application Crawler
# ============================================================================
@app.command()
def spider(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    depth: int = typer.Option(3, "--depth", "-d", help="Maximum crawl depth"),
    max_pages: int = typer.Option(100, "--max-pages", "-m", help="Maximum pages to crawl"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds"),
):
    """
    [bold magenta]Web Spider[/bold magenta] - Crawl web applications
    
    Discovers:
    - Endpoints and URLs
    - Forms and parameters
    - JavaScript files
    - API endpoints
    - Email addresses
    
    [dim]Example: python icarus.py spider --target https://example.com --depth 5[/dim]
    """
    show_banner()
    console.print(f"\n[bold magenta]Web Spider[/bold magenta] - Target: [cyan]{target}[/cyan]\n")
    
    from modules.spider import run_spider, display_spider_results
    from utils.dashboard_integration import (
        dashboard_log, dashboard_finding, dashboard_scan_start,
        dashboard_scan_complete
    )
    
    # Push to dashboard
    dashboard_scan_start("Spider", target)
    
    try:
        result = asyncio.run(run_spider(
            target=target,
            depth=depth,
            max_pages=max_pages,
            timeout=timeout,
        ))
        
        display_spider_results(result)
        
        # Push findings to dashboard
        if result.endpoints:
            dashboard_finding(
                target=target,
                title=f"Found {len(result.endpoints)} endpoints",
                severity="info",
                category="Spider",
            )
        
        if result.forms:
            dashboard_finding(
                target=target,
                title=f"Found {len(result.forms)} forms",
                severity="low",
                category="Spider",
            )
        
        if result.js_files:
            dashboard_finding(
                target=target,
                title=f"Found {len(result.js_files)} JavaScript files",
                severity="info",
                category="Spider",
            )
        
        if result.api_endpoints:
            dashboard_finding(
                target=target,
                title=f"Found {len(result.api_endpoints)} API endpoints",
                severity="medium",
                category="Spider",
            )
        
        findings_count = len(result.endpoints) + len(result.forms) + len(result.api_endpoints)
        dashboard_scan_complete(findings_count)
        dashboard_log("success", f"Spider completed on {target}")
        
    except KeyboardInterrupt:
        dashboard_log("warning", "Spider interrupted")
        console.print("\n[yellow]Spider interrupted[/yellow]")
        raise typer.Exit(1)

    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        raise typer.Exit(1)


# ============================================================================
# PAYLOADS COMMAND - Payload Generator
# ============================================================================
@app.command()
def payloads(
    list_type: str = typer.Option(None, "--list", "-l", help="List payloads: xss, sqli, cmdi, shells"),
    payload_type: str = typer.Option(None, "--type", "-t", help="Payload type for generation"),
    ip: str = typer.Option(None, "--ip", "-i", help="Your IP for reverse shells"),
    port: int = typer.Option(4444, "--port", "-p", help="Your port for reverse shells"),
    encoder: str = typer.Option(None, "--encoder", "-e", help="Encoder: base64, url, hex, unicode, html"),
    output: str = typer.Option(None, "--output", "-o", help="Output file for payloads"),
):
    """
    [bold red]Payload Generator[/bold red] - Generate attack payloads
    
    Categories:
    - XSS: Cross-site scripting payloads
    - SQLi: SQL injection payloads
    - CMDi: Command injection payloads
    - Shells: Reverse shell generators
    
    [dim]Example: python icarus.py payloads --list shells[/dim]
    [dim]Example: python icarus.py payloads --type bash --ip 10.10.14.5 --port 4444[/dim]
    """
    show_banner()
    
    from modules.payloads import (
        display_payloads, display_reverse_shells, display_generated_shell,
        display_encoders, get_payload_by_category, REVERSE_SHELLS
    )
    
    # List payloads
    if list_type:
        if list_type.lower() == "shells":
            display_reverse_shells()
        elif list_type.lower() == "encoders":
            display_encoders()
        else:
            display_payloads(list_type)
        return
    
    # Generate reverse shell
    if payload_type:
        if payload_type.lower() in REVERSE_SHELLS:
            if not ip:
                console.print("[red]Error: --ip is required for reverse shells[/red]")
                console.print("[dim]Example: --type bash --ip 10.10.14.5 --port 4444[/dim]")
                raise typer.Exit(1)
            
            display_generated_shell(payload_type.lower(), ip, port, encoder)
        else:
            # Try to get payloads by category
            result = get_payload_by_category(payload_type, encoder=encoder)
            if result:
                if output:
                    Path(output).write_text(result)
                    console.print(f"[green]Payloads saved to {output}[/green]")
                else:
                    console.print(result)
            else:
                console.print(f"[red]Unknown payload type: {payload_type}[/red]")
                console.print("[dim]Use --list xss/sqli/cmdi/shells to see available payloads[/dim]")
        return
    
    # Default: show all payload categories
    display_payloads()
    display_reverse_shells()


# ============================================================================
# NETMAP COMMAND - Network Discovery
# ============================================================================
@app.command()
def netmap(
    network: str = typer.Option(None, "--range", "-r", help="Network range (e.g., 192.168.1.0/24)"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick scan (limited hosts)"),
    tree: bool = typer.Option(False, "--tree", "-t", help="Display as tree"),
):
    """
    [bold yellow]Network Discovery[/bold yellow] - Map your network
    
    Features:
    - Host discovery (ping sweep)
    - Port scanning
    - Device fingerprinting
    - MAC vendor lookup
    
    [dim]Example: python icarus.py netmap --range 192.168.1.0/24[/dim]
    [dim]Example: python icarus.py netmap --range 10.0.0.0/24 --quick[/dim]
    """
    show_banner()
    
    from modules.netmap import run_discovery, get_default_gateway
    from utils.dashboard_integration import dashboard_scan_start, dashboard_scan_complete, dashboard_log
    
    if not network:
        # Try to auto-detect network
        gateway = get_default_gateway()
        if gateway:
            # Assume /24 network
            parts = gateway.split('.')
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            console.print(f"[dim]Auto-detected network: {network}[/dim]")
        else:
            console.print("[red]Error: Could not detect network. Specify with --range[/red]")
            console.print("[dim]Example: --range 192.168.1.0/24[/dim]")
            raise typer.Exit(1)
    
    # Push to dashboard
    dashboard_scan_start("NetMap", network)
    
    try:
        asyncio.run(run_discovery(
            network=network,
            quick=quick,
            tree_view=tree,
        ))
        
        dashboard_scan_complete(0)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")
        dashboard_log("warning", "NetMap scan interrupted")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        dashboard_log("error", f"NetMap error: {e}")
        raise typer.Exit(1)


# ============================================================================
# PENTEST MODE - Full Workflow Orchestration
# ============================================================================
@app.command()
def pentest(
    target: str = typer.Option(..., "--target", "-t", help="Target domain or IP address"),
    workflow: str = typer.Option("full", "--workflow", "-w", help="Workflow: full, quick, recon-only"),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Resume existing run"),
    skip: Optional[str] = typer.Option(None, "--skip", help="Phases to skip (comma-separated)"),
    only: Optional[str] = typer.Option(None, "--only", help="Run only these phases"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    [bold blue]Pentest Mode[/bold blue] - Full workflow orchestration
    
    Executes structured pentest phases:
    - Recon -> Vulnerability Scan -> Exploit -> Post-Exploit -> Report
    
    All results are persisted to database for resumption.
    
    [dim]Example: python icarus.py pentest --target example.com --workflow full[/dim]
    """
    show_banner()
    console.print(f"\n[bold blue]Pentest Mode[/bold blue] - Target: [cyan]{target}[/cyan]\n")
    console.print(f"Workflow: [yellow]{workflow}[/yellow]")
    
    from utils.dashboard_integration import dashboard_scan_start, dashboard_scan_complete, dashboard_log
    
    # Load config
    config = load_config()
    setup_logger(config, verbose)
    logger = get_logger()
    
    # Push to dashboard
    dashboard_scan_start("Pentest", target)
    dashboard_log("info", f"Starting {workflow} pentest workflow")
    
    # Initialize workflow manager
    manager = WorkflowManager(config)
    
    try:
        # Create or resume run
        if run_id:
            run = manager.resume_run(run_id)
            console.print(f"[dim]Resuming run: {run_id}[/dim]")
        else:
            run = asyncio.run(manager.create_run(target, workflow))
            console.print(f"[dim]Created run: {run.id}[/dim]")
        
        # Parse skip/only phases
        skip_phases = set(skip.split(",")) if skip else set()
        only_phases = set(only.split(",")) if only else None
        
        # Execute workflow
        asyncio.run(manager.execute_workflow(
            run,
            skip_phases=skip_phases,
            only_phases=only_phases,
        ))
        
        console.print("\n[bold green]Pentest workflow complete![/bold green]")
        console.print(f"[dim]Run ID: {run.id}[/dim]")
        console.print(f"[dim]View with: python icarus.py runs show {run.id}[/dim]")
        
        dashboard_scan_complete(0)
        dashboard_log("success", "Pentest workflow completed")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Workflow interrupted by user[/yellow]")
        dashboard_log("warning", "Pentest interrupted")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        logger.exception("Pentest failed")
        dashboard_log("error", f"Pentest error: {e}")
        raise typer.Exit(1)


# ============================================================================
# AI MODE - AI-Powered Assistant
# ============================================================================
@app.command()
def ai(
    query: Optional[str] = typer.Option(None, "--query", "-q", help="Query for the AI assistant"),
    commands: bool = typer.Option(False, "--commands", "-c", help="Get command suggestions"),
    explain: Optional[str] = typer.Option(None, "--explain", "-e", help="Explain a CVE or finding"),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Use context from a run"),
    goal: Optional[str] = typer.Option(None, "--goal", "-g", help="Goal for command suggestions"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="AI model to use (llama3.1-8b, llama-3.3-70b, gpt-oss-120b)"),
):
    """
    [bold magenta]AI Mode[/bold magenta] - AI-powered assistant (Cerebras - World's Fastest)
    
    Get intelligent help with:
    - Command suggestions for specific goals
    - CVE/vulnerability explanations
    - Finding analysis and remediation
    
    Available models:
    - llama3.1-8b (default) - Fast & efficient (~2200 tok/s)
    - llama-3.3-70b - Better reasoning (~450 tok/s)
    - gpt-oss-120b - Fastest production (~3000 tok/s)
    
    [dim]Example: python icarus.py ai --commands --goal "initial foothold on Linux" --model gpt-oss-120b[/dim]
    """
    show_banner()
    console.print("\n[bold magenta]AI Mode[/bold magenta] - Powered by Cerebras (World's Fastest AI)\n")
    
    from utils.dashboard_integration import dashboard_log
    
    # Load config
    config = load_config()
    
    # Override model if specified
    if model:
        if model in config.ai.available_models:
            config.ai.model = model
            model_info = config.ai.available_models[model]
            console.print(f"[dim]Using model: {model} ({model_info['params']}, {model_info['speed']})[/dim]\n")
        else:
            console.print(f"[red]Unknown model: {model}[/red]")
            console.print("[yellow]Available models:[/yellow]")
            for m, info in config.ai.available_models.items():
                console.print(f"  • {m} ({info['params']}, {info['speed']})")
            raise typer.Exit(1)
    
    # Initialize AI engine
    ai_engine = AIEngine(config)
    
    try:
        if commands:
            if not goal:
                console.print("[red]Please provide a goal with --goal[/red]")
                raise typer.Exit(1)
            
            console.print(f"[dim]Generating commands for: {goal}[/dim]\n")
            dashboard_log("info", f"AI generating commands for: {goal}")
            
            # Get context if run_id provided
            context = None
            if run_id:
                manager = WorkflowManager(config)
                context = manager.get_run_context(run_id)
            
            response = asyncio.run(ai_engine.suggest_commands(goal, context))
            
            # Render with clean formatting
            console.print("\n" + "="*80)
            console.print("[bold cyan]🎯 Suggested Commands[/bold cyan]")
            console.print("="*80 + "\n")
            console.print(Markdown(response))
            console.print("\n" + "="*80 + "\n")
            
        elif explain:
            console.print(f"[dim]Explaining: {explain}[/dim]\n")
            dashboard_log("info", f"AI explaining: {explain}")
            response = asyncio.run(ai_engine.explain(explain))
            
            # Render with clean formatting
            console.print("\n" + "="*80)
            console.print("[bold green]📖 Explanation[/bold green]")
            console.print("="*80 + "\n")
            console.print(Markdown(response))
            console.print("\n" + "="*80 + "\n")
            
        elif query:
            console.print(f"[dim]Query: {query}[/dim]\n")
            dashboard_log("info", f"AI query: {query}")
            response = asyncio.run(ai_engine.ask(query))
            
            # Render with clean formatting
            console.print("\n" + "="*80)
            console.print("[bold magenta]🤖 AI Response[/bold magenta]")
            console.print("="*80 + "\n")
            console.print(Markdown(response))
            console.print("\n" + "="*80 + "\n")
            
        else:
            console.print("[yellow]Please provide --query, --commands, or --explain[/yellow]")
            console.print("\n[dim]Examples:")
            console.print("  icarus ai --query 'how to enumerate SMB?'")
            console.print("  icarus ai --commands --goal 'privilege escalation on Linux'")
            console.print("  icarus ai --explain CVE-2024-1234[/dim]")
            
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        dashboard_log("error", f"AI error: {e}")
        raise typer.Exit(1)


# ============================================================================
# RUNS SUBCOMMAND - Manage workflow runs
# ============================================================================
runs_app = typer.Typer(help="Manage workflow runs")
app.add_typer(runs_app, name="runs")


@runs_app.command("list")
def runs_list(
    limit: int = typer.Option(10, "--limit", "-n", help="Number of runs to show"),
):
    """List recent workflow runs."""
    config = load_config()
    manager = WorkflowManager(config)
    
    runs = manager.list_runs(limit)
    
    if not runs:
        console.print("[dim]No runs found[/dim]")
        return
    
    table = Table(title="Recent Runs", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim")
    table.add_column("Target", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Started", style="white")
    table.add_column("Findings", style="red")
    
    for run in runs:
        status_color = "green" if run.status == "done" else "yellow"
        table.add_row(
            str(run.id)[:8],
            run.target,
            f"[{status_color}]{run.status}[/{status_color}]",
            run.started_at.strftime("%Y-%m-%d %H:%M") if run.started_at else "-",
            str(run.finding_count),
        )
    
    console.print(table)


@runs_app.command("show")
def runs_show(run_id: str):
    """Show details of a specific run."""
    config = load_config()
    manager = WorkflowManager(config)
    
    run = manager.get_run(run_id)
    if not run:
        console.print(f"[red]Run not found: {run_id}[/red]")
        raise typer.Exit(1)
    
    console.print(Panel(
        f"[bold]Target:[/bold] {run.target}\n"
        f"[bold]Status:[/bold] {run.status}\n"
        f"[bold]Workflow:[/bold] {run.workflow}\n"
        f"[bold]Started:[/bold] {run.started_at}\n"
        f"[bold]Finished:[/bold] {run.finished_at or 'In progress'}\n"
        f"[bold]Findings:[/bold] {run.finding_count}",
        title=f"Run: {run_id}",
        border_style="cyan"
    ))


# ============================================================================
# REPORT SUBCOMMAND - Generate reports
# ============================================================================
@app.command()
def report(
    run_id: str = typer.Option(..., "--run-id", "-r", help="Run ID to generate report from"),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, markdown, json"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """
    Generate a report from a workflow run.
    """
    show_banner()
    console.print(f"\n[bold]Generating {format.upper()} Report[/bold]\n")
    
    config = load_config()
    manager = WorkflowManager(config)
    reporter = ReportGenerator(config)
    
    run = manager.get_run(run_id)
    if not run:
        console.print(f"[red]Run not found: {run_id}[/red]")
        raise typer.Exit(1)
    
    # Generate report
    report_path = asyncio.run(reporter.generate(run, format, output))
    
    console.print(f"\n[bold green]Report generated: {report_path}[/bold green]")


# ============================================================================
# VERSION & MAIN
# ============================================================================
@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version"),
):
    """ICARUS-X: Unified AI-Powered Pentesting Framework"""
    if version:
        console.print("[bold cyan]ICARUS-X[/bold cyan] v2.0.0")
        console.print("[dim]Unified AI-Powered Pentesting Framework[/dim]")
        console.print("\n[yellow]GitHub:[/yellow] https://github.com/mizazhaider-ceh/Icarus-X")
        raise typer.Exit()
    
    if ctx.invoked_subcommand is None:
        show_banner()
        
        # Display comprehensive help
        console.print("\n[bold green]🚀 Quick Start Guide[/bold green]\n")
        
        # Essential Commands Table
        from rich.table import Table
        table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("Command", style="yellow", width=12)
        table.add_column("Example", style="white", width=50)
        table.add_column("Description", style="dim", width=30)
        
        table.add_row(
            "tools",
            "python icarus.py tools",
            "Check installed tools"
        )
        table.add_row(
            "scout",
            "python icarus.py scout -t example.com",
            "Fast reconnaissance"
        )
        table.add_row(
            "dirbrute",
            "python icarus.py dirbrute -t https://target",
            "Directory brute-force"
        )
        table.add_row(
            "vuln",
            "python icarus.py vuln -t https://target",
            "Vulnerability scan (Nuclei)"
        )
        table.add_row(
            "spider",
            "python icarus.py spider -t https://target",
            "Web crawler"
        )
        table.add_row(
            "payloads",
            "python icarus.py payloads --list shells",
            "Generate attack payloads"
        )
        table.add_row(
            "ai",
            "python icarus.py ai --query 'explain nmap'",
            "AI assistant (requires API key)"
        )
        table.add_row(
            "pentest",
            "python icarus.py pentest -t example.com",
            "Full workflow"
        )
        
        console.print(table)
        
        # Additional helpful info
        console.print("\n[bold cyan]📚 More Commands:[/bold cyan]")
        console.print("  • [yellow]wordlists[/yellow] - Browse wordlist collections")
        console.print("  • [yellow]tech[/yellow]      - Technology detection")
        console.print("  • [yellow]netmap[/yellow]    - Network discovery")
        console.print("  • [yellow]report[/yellow]    - Generate reports")
        console.print("  • [yellow]runs[/yellow]      - Manage workflow runs")
        
        # Common Usage Patterns
        console.print("\n[bold magenta]🎯 Common Usage Patterns:[/bold magenta]")
        console.print("\n[cyan]1. Basic Reconnaissance:[/cyan]")
        console.print("   python icarus.py scout -t example.com")
        console.print("   python icarus.py scout -t example.com --ports 80,443,8080")
        console.print("   python icarus.py scout -t example.com --tech")
        
        console.print("\n[cyan]2. Mass Target Scanning:[/cyan]")
        console.print("   python icarus.py scout --targets targets.txt")
        console.print("   [dim]# targets.txt format: one target per line, supports IPs, domains, CIDR[/dim]")
        
        console.print("\n[cyan]3. Directory Discovery:[/cyan]")
        console.print("   python icarus.py dirbrute -t https://example.com")
        console.print("   python icarus.py dirbrute -t https://example.com --ext php,html,js")
        console.print("   python icarus.py wordlists --path common  [dim]# Find wordlist path[/dim]")
        
        console.print("\n[cyan]4. Vulnerability Assessment:[/cyan]")
        console.print("   python icarus.py vuln -t https://example.com")
        console.print("   python icarus.py vuln -t https://example.com --severity critical,high")
        console.print("   python icarus.py tech -t https://example.com  [dim]# Detect tech stack first[/dim]")
        
        console.print("\n[cyan]5. Payload Generation:[/cyan]")
        console.print("   python icarus.py payloads --list shells")
        console.print("   python icarus.py payloads --type bash --ip 10.10.14.5 --port 4444")
        console.print("   python icarus.py payloads --list xss")
        console.print("   python icarus.py payloads --list sqli")
        
        console.print("\n[cyan]6. AI-Assisted Hacking (requires API key):[/cyan]")
        console.print("   python icarus.py ai --commands --goal 'enumerate SMB shares'")
        console.print("   python icarus.py ai --explain CVE-2024-1234")
        console.print("   python icarus.py ai --query 'how to bypass WAF?'")
        
        console.print("\n[cyan]7. Full Penetration Testing Workflow:[/cyan]")
        console.print("   python icarus.py pentest -t example.com --workflow quick")
        console.print("   python icarus.py pentest -t example.com --workflow full")
        console.print("   python icarus.py runs list  [dim]# View previous scans[/dim]")
        console.print("   python icarus.py report --run-id abc123 --format html")
        
        console.print("\n[bold yellow]💡 Pro Tips:[/bold yellow]")
        console.print("  • Run [cyan]<command> --help[/cyan] for all options (e.g., scout --help)")
        console.print("  • Use [cyan]--verbose[/cyan] or [cyan]-v[/cyan] flag for detailed output")
        console.print("  • Check [cyan]python icarus.py wordlists --scan[/cyan] to see all wordlists")
        console.print("  • Use [cyan]--output[/cyan] or [cyan]-o[/cyan] to save results to file")
        console.print("  • Mass scanning: supports CIDR (192.168.1.0/24) and ranges (192.168.1.1-50)")
        console.print("  • Install SecLists: [cyan]git clone https://github.com/danielmiessler/SecLists[/cyan]")
        
        console.print("\n[bold green]📖 Documentation:[/bold green]")
        console.print("  • [cyan]SETUP.md[/cyan]    - Complete installation guide")
        console.print("  • [cyan]README.md[/cyan]   - Full documentation with examples")
        console.print("  • [cyan]PORTFOLIO.md[/cyan] - Project showcase materials")
        console.print("  • [cyan].env.example[/cyan] - API key configuration template")
        
        console.print("\n[bold red]⚠️  Legal Warning:[/bold red]")
        console.print("  [dim]• Always obtain written authorization before testing any target[/dim]")
        console.print("  [dim]• Unauthorized access is illegal and punishable by law[/dim]")
        console.print("  [dim]• This tool is for authorized security testing ONLY[/dim]")
        console.print("  [dim]• See LICENSE file for terms and conditions[/dim]")
        
        console.print("\n[bold]Need Help? Run [cyan]python icarus.py --help[/cyan] to see all commands[/bold]")
        console.print("[bold]Or visit: [cyan]https://github.com/mizazhaider-ceh/Icarus-X[/cyan][/bold]\n")


if __name__ == "__main__":
    app()
