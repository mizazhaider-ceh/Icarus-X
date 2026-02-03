"""
ICARUS-X Nuclei Integration
===========================
CVE scanning with Project Discovery's Nuclei.
"""

import asyncio
import json
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class NucleiResult:
    """Result from Nuclei scan."""
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: Optional[str] = None
    reference: Optional[list[str]] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None


def is_nuclei_installed() -> bool:
    """Check if nuclei is installed."""
    return shutil.which("nuclei") is not None


def get_nuclei_templates_path() -> Optional[str]:
    """Get nuclei templates path."""
    home = Path.home()
    template_paths = [
        home / "nuclei-templates",
        home / ".local/nuclei-templates",
        Path("/usr/share/nuclei-templates"),
    ]
    for path in template_paths:
        if path.exists():
            return str(path)
    return None


async def update_nuclei_templates():
    """Update nuclei templates."""
    console.print("[dim]Updating nuclei templates...[/dim]")
    
    process = await asyncio.create_subprocess_exec(
        "nuclei", "-update-templates",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    
    await process.communicate()
    console.print("[green]Templates updated[/green]")


async def run_nuclei(
    target: str,
    severity: list[str] = None,
    templates: list[str] = None,
    tags: list[str] = None,
    exclude_tags: list[str] = None,
    rate_limit: int = 150,
    timeout: int = 600,
    output_file: str = None,
) -> list[NucleiResult]:
    """
    Run Nuclei vulnerability scanner.
    
    Args:
        target: Target URL or host
        severity: Severity levels to scan (critical, high, medium, low, info)
        templates: Specific template paths/IDs
        tags: Template tags to include (cve, rce, lfi, sqli, etc.)
        exclude_tags: Template tags to exclude
        rate_limit: Requests per second
        timeout: Maximum runtime in seconds
        output_file: Save JSON results to file
    
    Returns:
        List of vulnerabilities found
    """
    if not is_nuclei_installed():
        console.print("[red]Nuclei not installed![/red]")
        console.print("[dim]Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/dim]")
        return []
    
    results = []
    temp_output = Path("/tmp/nuclei_output.json")
    
    # Build command
    cmd = [
        "nuclei",
        "-u", target,
        "-jsonl",
        "-o", str(temp_output),
        "-rate-limit", str(rate_limit),
        "-silent",
        "-no-color",
    ]
    
    if severity:
        cmd.extend(["-severity", ",".join(severity)])
    else:
        # Default to critical, high, medium
        cmd.extend(["-severity", "critical,high,medium"])
    
    if templates:
        for template in templates:
            cmd.extend(["-t", template])
    
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    
    if exclude_tags:
        cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
    
    console.print(f"[dim]Running nuclei scan on {target}...[/dim]")
    
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
        
        # Parse JSON Lines output
        if temp_output.exists():
            with open(temp_output) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        
                        # Extract CVE info
                        cve_id = None
                        cvss_score = None
                        if "classification" in data.get("info", {}):
                            cve_id = data["info"]["classification"].get("cve-id")
                            if isinstance(cve_id, list):
                                cve_id = cve_id[0] if cve_id else None
                            cvss_score = data["info"]["classification"].get("cvss-score")
                        
                        results.append(NucleiResult(
                            template_id=data.get("template-id", ""),
                            name=data.get("info", {}).get("name", "Unknown"),
                            severity=data.get("info", {}).get("severity", "unknown"),
                            host=data.get("host", target),
                            matched_at=data.get("matched-at", ""),
                            description=data.get("info", {}).get("description"),
                            reference=data.get("info", {}).get("reference"),
                            cve_id=cve_id,
                            cvss_score=cvss_score,
                        ))
                    except json.JSONDecodeError:
                        continue
            
            # Copy to output file if specified
            if output_file:
                import shutil
                shutil.copy(temp_output, output_file)
            
            temp_output.unlink()  # Cleanup
    
    except asyncio.TimeoutError:
        console.print("[yellow]Nuclei scan timed out[/yellow]")
    except Exception as e:
        console.print(f"[red]Nuclei error: {e}[/red]")
    
    return results


async def quick_vuln_scan(
    target: str,
    timeout: int = 300,
) -> list[NucleiResult]:
    """
    Quick vulnerability scan with common CVE templates.
    
    Focuses on critical and high severity vulnerabilities.
    """
    return await run_nuclei(
        target=target,
        severity=["critical", "high"],
        tags=["cve", "rce", "sqli", "lfi", "ssrf", "auth-bypass"],
        exclude_tags=["dos", "fuzz"],
        rate_limit=100,
        timeout=timeout,
    )


async def full_vuln_scan(
    target: str,
    timeout: int = 900,
) -> list[NucleiResult]:
    """
    Full vulnerability scan with all templates.
    """
    return await run_nuclei(
        target=target,
        severity=["critical", "high", "medium"],
        exclude_tags=["dos", "fuzz"],
        rate_limit=150,
        timeout=timeout,
    )


def display_nuclei_results(results: list[NucleiResult]):
    """Display nuclei results in a table."""
    if not results:
        console.print("[green]No vulnerabilities found[/green]")
        return
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results = sorted(results, key=lambda x: severity_order.get(x.severity, 5))
    
    table = Table(title="Nuclei Vulnerability Scan Results", show_header=True, header_style="bold cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Name")
    table.add_column("CVE", style="yellow")
    table.add_column("Target", style="dim")
    
    for result in results:
        # Color severity
        if result.severity == "critical":
            sev = "[bold red]CRITICAL[/bold red]"
        elif result.severity == "high":
            sev = "[red]HIGH[/red]"
        elif result.severity == "medium":
            sev = "[yellow]MEDIUM[/yellow]"
        elif result.severity == "low":
            sev = "[blue]LOW[/blue]"
        else:
            sev = "[dim]INFO[/dim]"
        
        table.add_row(
            sev,
            result.name[:50],
            result.cve_id or "-",
            result.matched_at[:60] if result.matched_at else result.host,
        )
    
    console.print(table)
    
    # Summary
    critical = sum(1 for r in results if r.severity == "critical")
    high = sum(1 for r in results if r.severity == "high")
    medium = sum(1 for r in results if r.severity == "medium")
    
    console.print(f"\n[bold]Summary:[/bold] {critical} Critical, {high} High, {medium} Medium")
