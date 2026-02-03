"""
ICARUS-X Mass Target Module
============================
Handle multiple targets from files and ranges.
"""

import asyncio
import ipaddress
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, AsyncGenerator

from rich.console import Console
from rich.progress import Progress, TaskID

console = Console()


@dataclass
class TargetEntry:
    """A single target entry."""
    value: str
    target_type: str  # ip, domain, url, cidr
    metadata: Optional[dict] = None


def parse_cidr(cidr: str) -> list[str]:
    """Expand CIDR notation to list of IPs."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # Limit to /16 networks to prevent memory issues
        if network.num_addresses > 65536:
            console.print(f"[yellow]Warning: {cidr} has too many hosts, limiting to first /16[/yellow]")
            return [str(ip) for ip in list(network.hosts())[:65536]]
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        console.print(f"[red]Invalid CIDR: {cidr} - {e}[/red]")
        return []


def parse_range(range_str: str) -> list[str]:
    """
    Parse IP range notation (e.g., 192.168.1.1-50).
    
    Supports:
    - 192.168.1.1-50 (last octet range)
    - 192.168.1.1-192.168.1.50 (full IP range)
    """
    ips = []
    
    # Pattern: IP-IP or IP-lastoctet
    if "-" in range_str:
        parts = range_str.split("-")
        if len(parts) == 2:
            start = parts[0].strip()
            end = parts[1].strip()
            
            try:
                if "." in end:
                    # Full IP range: 192.168.1.1-192.168.1.50
                    start_ip = ipaddress.ip_address(start)
                    end_ip = ipaddress.ip_address(end)
                    
                    current = start_ip
                    while current <= end_ip:
                        ips.append(str(current))
                        current = ipaddress.ip_address(int(current) + 1)
                else:
                    # Last octet range: 192.168.1.1-50
                    base = ".".join(start.split(".")[:-1])
                    start_octet = int(start.split(".")[-1])
                    end_octet = int(end)
                    
                    for i in range(start_octet, end_octet + 1):
                        ips.append(f"{base}.{i}")
            
            except ValueError as e:
                console.print(f"[red]Invalid range: {range_str} - {e}[/red]")
    
    return ips


def detect_target_type(value: str) -> str:
    """Detect the type of target."""
    value = value.strip()
    
    # URL
    if value.startswith(("http://", "https://")):
        return "url"
    
    # CIDR
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return "cidr"
        except ValueError:
            pass
    
    # IP Range
    if "-" in value and re.match(r"^\d+\.\d+\.\d+\.\d+-", value):
        return "range"
    
    # IP Address
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    
    # Domain
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$", value):
        return "domain"
    
    return "unknown"


def load_targets_from_file(filepath: str) -> list[TargetEntry]:
    """
    Load targets from a file.
    
    Supports:
    - One target per line
    - # comments
    - IPs, domains, URLs, CIDR, ranges
    """
    targets = []
    path = Path(filepath)
    
    if not path.exists():
        console.print(f"[red]File not found: {filepath}[/red]")
        return targets
    
    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            
            # Handle inline comments
            if "#" in line:
                line = line.split("#")[0].strip()
            
            target_type = detect_target_type(line)
            
            if target_type == "cidr":
                # Expand CIDR
                for ip in parse_cidr(line):
                    targets.append(TargetEntry(value=ip, target_type="ip"))
            
            elif target_type == "range":
                # Expand range
                for ip in parse_range(line):
                    targets.append(TargetEntry(value=ip, target_type="ip"))
            
            elif target_type != "unknown":
                targets.append(TargetEntry(value=line, target_type=target_type))
            
            else:
                console.print(f"[yellow]Unknown target format on line {line_num}: {line}[/yellow]")
    
    console.print(f"[dim]Loaded {len(targets)} targets from {filepath}[/dim]")
    return targets


def parse_targets(
    targets: list[str] = None,
    target_file: str = None,
) -> list[TargetEntry]:
    """
    Parse targets from various sources.
    
    Args:
        targets: List of target strings
        target_file: Path to file with targets
    
    Returns:
        List of TargetEntry objects
    """
    all_targets = []
    
    # Load from file
    if target_file:
        all_targets.extend(load_targets_from_file(target_file))
    
    # Parse command-line targets
    if targets:
        for target in targets:
            target = target.strip()
            target_type = detect_target_type(target)
            
            if target_type == "cidr":
                for ip in parse_cidr(target):
                    all_targets.append(TargetEntry(value=ip, target_type="ip"))
            elif target_type == "range":
                for ip in parse_range(target):
                    all_targets.append(TargetEntry(value=ip, target_type="ip"))
            elif target_type != "unknown":
                all_targets.append(TargetEntry(value=target, target_type=target_type))
    
    # Deduplicate
    seen = set()
    unique = []
    for target in all_targets:
        if target.value not in seen:
            seen.add(target.value)
            unique.append(target)
    
    return unique


async def iter_targets_async(
    targets: list[TargetEntry],
    batch_size: int = 10,
) -> AsyncGenerator[list[TargetEntry], None]:
    """
    Async generator for batched target iteration.
    
    Args:
        targets: List of targets
        batch_size: Number of targets per batch
    
    Yields:
        Batches of targets
    """
    for i in range(0, len(targets), batch_size):
        yield targets[i:i + batch_size]
        await asyncio.sleep(0)  # Allow other tasks to run


def display_targets_summary(targets: list[TargetEntry]):
    """Display summary of loaded targets."""
    from collections import Counter
    
    type_counts = Counter(t.target_type for t in targets)
    
    console.print(f"\n[bold]Target Summary:[/bold]")
    console.print(f"  Total: {len(targets)}")
    
    for target_type, count in type_counts.items():
        console.print(f"  {target_type.capitalize()}: {count}")


def save_targets_to_file(targets: list[TargetEntry], filepath: str):
    """Save targets to a file."""
    with open(filepath, "w") as f:
        for target in targets:
            f.write(f"{target.value}\n")
    
    console.print(f"[dim]Saved {len(targets)} targets to {filepath}[/dim]")
