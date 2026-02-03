"""
ICARUS-X Network Discovery Module
===================================
LAN network mapping, device fingerprinting, and visualization.
"""

import asyncio
import subprocess
import shutil
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional
from ipaddress import ip_network, ip_address

from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel

console = Console()


@dataclass
class Host:
    """Discovered host."""
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os: str = ""
    open_ports: list[int] = field(default_factory=list)
    services: dict = field(default_factory=dict)
    is_gateway: bool = False


@dataclass
class NetworkMap:
    """Network mapping result."""
    network: str
    gateway: str = ""
    hosts: list[Host] = field(default_factory=list)
    scan_time: float = 0


# Common port -> service mapping
PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# MAC vendor prefixes (common ones)
MAC_VENDORS = {
    "00:00:0c": "Cisco",
    "00:1a:2b": "Cisco",
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:1e:06": "WIBRAIN",
    "00:0d:93": "Apple",
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0a:95": "Apple",
    "00:14:51": "Apple",
    "00:17:f2": "Apple",
    "00:1c:b3": "Apple",
    "00:1e:c2": "Apple",
    "00:21:e9": "Apple",
    "00:25:bc": "Apple",
    "3c:d9:2b": "HP",
    "00:1a:4b": "HP",
    "00:21:5a": "HP",
    "00:25:b3": "HP",
    "2c:41:38": "HP",
    "10:60:4b": "HP",
    "00:1b:21": "Intel",
    "00:1c:c0": "Intel",
    "00:1f:3b": "Intel",
    "00:22:fa": "Intel",
    "00:24:d7": "Intel",
    "00:26:c6": "Intel",
    "24:77:03": "Intel",
    "00:e0:4c": "Realtek",
    "00:0d:56": "Dell",
    "00:14:22": "Dell",
    "00:18:8b": "Dell",
    "00:1a:a0": "Dell",
    "00:1c:23": "Dell",
    "00:1e:4f": "Dell",
    "00:21:9b": "Dell",
    "00:24:e8": "Dell",
    "00:16:3e": "Xen",
}


def get_vendor_from_mac(mac: str) -> str:
    """Get vendor name from MAC address prefix."""
    if not mac:
        return ""
    
    mac_prefix = mac.lower()[:8]
    return MAC_VENDORS.get(mac_prefix, "Unknown")


async def ping_host(ip: str, timeout: float = 1) -> bool:
    """Ping a host to check if it's alive."""
    try:
        # Use platform-appropriate ping
        import platform
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        
        process = await asyncio.create_subprocess_exec(
            "ping", param, "1", timeout_param, str(int(timeout * 1000) if platform.system().lower() == "windows" else int(timeout)),
            ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout + 1)
            return process.returncode == 0
        except asyncio.TimeoutError:
            process.kill()
            return False
    except Exception:
        return False


async def scan_port(ip: str, port: int, timeout: float = 1) -> bool:
    """Check if a port is open."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def scan_common_ports(ip: str, timeout: float = 0.5) -> list[int]:
    """Scan common ports on a host."""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080]
    open_ports = []
    
    tasks = [scan_port(ip, port, timeout) for port in common_ports]
    results = await asyncio.gather(*tasks)
    
    for port, is_open in zip(common_ports, results):
        if is_open:
            open_ports.append(port)
    
    return open_ports


def get_arp_table() -> dict[str, str]:
    """Get ARP table to map IPs to MACs."""
    arp_table = {}
    
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        # Parse ARP output
        import re
        # Match patterns like: 192.168.1.1 at aa:bb:cc:dd:ee:ff or (192.168.1.1) at aa:bb:cc:dd:ee:ff
        pattern = re.compile(r'[\(\s]?((?:\d{1,3}\.){3}\d{1,3})[\)\s]+(?:at\s+)?([a-fA-F0-9:-]{17})', re.I)
        
        for match in pattern.finditer(result.stdout):
            ip = match.group(1)
            mac = match.group(2).lower().replace('-', ':')
            if mac != 'ff:ff:ff:ff:ff:ff' and mac != '00:00:00:00:00:00':
                arp_table[ip] = mac
                
    except Exception:
        pass
    
    return arp_table


def get_hostname(ip: str) -> str:
    """Get hostname for an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return ""


def get_default_gateway() -> Optional[str]:
    """Get the default gateway IP."""
    try:
        # Try to get default gateway
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        for line in result.stdout.splitlines():
            if line.startswith("default"):
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "via":
                        return parts[i + 1]
    except Exception:
        pass
    
    # Fallback: try netstat
    try:
        result = subprocess.run(
            ["netstat", "-rn"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        for line in result.stdout.splitlines():
            if "0.0.0.0" in line or "default" in line.lower():
                parts = line.split()
                for part in parts:
                    if part.count('.') == 3:
                        try:
                            ip_address(part)
                            if part != "0.0.0.0":
                                return part
                        except Exception:
                            continue
    except Exception:
        pass
    
    return None


async def discover_network(
    network_range: str,
    quick: bool = False,
    scan_ports: bool = True,
) -> NetworkMap:
    """Discover hosts on a network."""
    
    # Parse network range
    try:
        net = ip_network(network_range, strict=False)
    except ValueError as e:
        console.print(f"[red]Invalid network range: {e}[/red]")
        return NetworkMap(network=network_range)
    
    result = NetworkMap(network=str(net))
    result.gateway = get_default_gateway() or ""
    
    # Get ARP table for MAC addresses
    arp_table = get_arp_table()
    
    hosts_to_scan = list(net.hosts())
    if quick:
        hosts_to_scan = hosts_to_scan[:50]  # Limit for quick scan
    
    discovered_hosts = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        
        # Phase 1: Discovery (ping sweep)
        task1 = progress.add_task("Discovering hosts...", total=len(hosts_to_scan))
        
        batch_size = 50
        for i in range(0, len(hosts_to_scan), batch_size):
            batch = hosts_to_scan[i:i + batch_size]
            tasks = [ping_host(str(ip)) for ip in batch]
            results = await asyncio.gather(*tasks)
            
            for ip, alive in zip(batch, results):
                progress.update(task1, advance=1)
                if alive:
                    ip_str = str(ip)
                    host = Host(
                        ip=ip_str,
                        mac=arp_table.get(ip_str, ""),
                        is_gateway=(ip_str == result.gateway),
                    )
                    host.vendor = get_vendor_from_mac(host.mac)
                    host.hostname = get_hostname(ip_str)
                    discovered_hosts.append(host)
        
        # Phase 2: Port scanning
        if scan_ports and discovered_hosts:
            task2 = progress.add_task("Scanning ports...", total=len(discovered_hosts))
            
            for host in discovered_hosts:
                progress.update(task2, advance=1, description=f"Scanning {host.ip}...")
                host.open_ports = await scan_common_ports(host.ip)
                
                # Map ports to services
                for port in host.open_ports:
                    host.services[port] = PORT_SERVICES.get(port, f"port-{port}")
    
    result.hosts = discovered_hosts
    return result


def display_network_map(net_map: NetworkMap):
    """Display network discovery results."""
    console.print(f"\n[bold cyan]Network Discovery: {net_map.network}[/bold cyan]\n")
    
    if net_map.gateway:
        console.print(f"[yellow]Gateway:[/yellow] {net_map.gateway}")
    console.print(f"[green]Hosts discovered:[/green] {len(net_map.hosts)}\n")
    
    if not net_map.hosts:
        console.print("[dim]No hosts discovered[/dim]")
        return
    
    # Table view
    table = Table(title="Discovered Hosts", show_header=True, header_style="bold cyan")
    table.add_column("IP", style="cyan")
    table.add_column("Hostname", style="white")
    table.add_column("MAC", style="dim")
    table.add_column("Vendor", style="yellow")
    table.add_column("Open Ports", style="green")
    table.add_column("", style="dim", width=3)
    
    for host in sorted(net_map.hosts, key=lambda h: [int(x) for x in h.ip.split('.')]):
        ports_str = ", ".join(str(p) for p in sorted(host.open_ports)[:5])
        if len(host.open_ports) > 5:
            ports_str += f" (+{len(host.open_ports) - 5})"
        
        icon = "🌐" if host.is_gateway else ""
        
        table.add_row(
            host.ip,
            host.hostname or "-",
            host.mac or "-",
            host.vendor or "-",
            ports_str or "-",
            icon,
        )
    
    console.print(table)
    
    # Services summary
    if any(h.services for h in net_map.hosts):
        console.print("\n[bold yellow]Services Found:[/bold yellow]")
        services_summary = {}
        for host in net_map.hosts:
            for port, service in host.services.items():
                if service not in services_summary:
                    services_summary[service] = []
                services_summary[service].append(f"{host.ip}:{port}")
        
        for service, hosts in sorted(services_summary.items()):
            console.print(f"  [cyan]{service}:[/cyan] {', '.join(hosts[:5])}")
            if len(hosts) > 5:
                console.print(f"       [dim]... and {len(hosts) - 5} more[/dim]")


def display_network_tree(net_map: NetworkMap):
    """Display network as a tree structure."""
    tree = Tree(f"[bold cyan]Network: {net_map.network}[/bold cyan]")
    
    if net_map.gateway:
        gateway_branch = tree.add(f"[yellow]🌐 Gateway: {net_map.gateway}[/yellow]")
    
    hosts_branch = tree.add(f"[green]📡 Hosts ({len(net_map.hosts)})[/green]")
    
    for host in sorted(net_map.hosts, key=lambda h: [int(x) for x in h.ip.split('.')]):
        if host.is_gateway:
            continue
        
        host_label = f"[cyan]{host.ip}[/cyan]"
        if host.hostname:
            host_label += f" ({host.hostname})"
        
        host_branch = hosts_branch.add(host_label)
        
        if host.vendor:
            host_branch.add(f"[dim]Vendor: {host.vendor}[/dim]")
        
        if host.open_ports:
            ports_branch = host_branch.add("[yellow]Ports[/yellow]")
            for port in sorted(host.open_ports):
                service = host.services.get(port, "")
                ports_branch.add(f"[green]{port}[/green] {service}")
    
    console.print(tree)


async def run_discovery(
    network: str,
    quick: bool = False,
    tree_view: bool = False,
) -> NetworkMap:
    """Run network discovery."""
    console.print(f"\n[bold cyan]ICARUS-X Network Discovery[/bold cyan]")
    console.print(f"[dim]Scanning: {network}[/dim]\n")
    
    net_map = await discover_network(network, quick=quick)
    
    if tree_view:
        display_network_tree(net_map)
    else:
        display_network_map(net_map)
    
    return net_map
