"""
ICARUS-X Async Scanner Engine
=============================
High-performance async reconnaissance engine.

Features:
- Async port scanning (500+ concurrent connections)
- Subdomain enumeration with aiodns
- HTTP service probing with httpx
- WHOIS lookups with threading fallback
"""

import asyncio
import socket
import re
from datetime import datetime
from typing import Optional
from pathlib import Path

import httpx

from models.target import (
    Target, TargetType, PortInfo, DomainInfo, 
    HttpService, WhoisInfo, ReconResult
)
from utils.config import IcarusConfig
from utils.logger import get_logger, ScanProgress, console
from utils.async_helpers import run_in_thread, RateLimiter, gather_with_concurrency

# Common ports list
TOP_1000_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 
    # Extended list
    20, 26, 37, 49, 69, 79, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100,
    106, 109, 113, 119, 125, 144, 146, 161, 162, 163, 179, 199, 211, 212,
    222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406,
    407, 416, 417, 425, 427, 444, 458, 464, 465, 481, 497, 500, 512, 513,
    514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616,
    617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705,
    711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843,
    873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992,
    999, 1000, 1001, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025,
    1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037,
    1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049,
    1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061,
    1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073,
    1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085,
    1434, 1521, 1583, 1720, 1812, 1813, 2000, 2001, 2049, 2121, 2181, 2222,
    2375, 2376, 2379, 2380, 3000, 3001, 3128, 3268, 3269, 3333, 4000, 4001,
    4443, 4444, 4567, 5000, 5001, 5353, 5555, 5601, 5672, 6000, 6379, 6443,
    6666, 7000, 7001, 7070, 7777, 8000, 8001, 8008, 8009, 8010, 8081, 8082,
    8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8181, 8222, 8333,
    8444, 8800, 8880, 8881, 8899, 9000, 9001, 9002, 9003, 9009, 9043, 9060,
    9080, 9090, 9091, 9200, 9300, 9443, 9999, 10000, 10443, 11211, 27017,
    27018, 28017, 50000, 50070, 50075
]

# Common service signatures
SERVICE_SIGNATURES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}


class ReconEngine:
    """
    High-performance async reconnaissance engine.
    
    Usage:
        engine = ReconEngine(config)
        results = await engine.run_recon("example.com", ports="top-1000")
    """
    
    def __init__(self, config: IcarusConfig):
        self.config = config
        self.logger = get_logger()
    
    async def run_recon(
        self,
        target: str,
        ports: str = "top-1000",
        run_subdomains: bool = True,
        run_whois: bool = True,
        run_http: bool = True,
    ) -> ReconResult:
        """
        Run complete reconnaissance on target.
        
        Args:
            target: Domain or IP address
            ports: Port specification (top-1000, full, comma-separated)
            run_subdomains: Run subdomain enumeration
            run_whois: Run WHOIS lookup
            run_http: Probe HTTP services
            
        Returns:
            ReconResult with all findings
        """
        # Create target object
        target_obj = Target.from_string(target)
        result = ReconResult(target=target_obj)
        
        self.logger.info(f"Starting recon on {target}")
        console.print(f"[dim]Target type: {target_obj.type.value}[/dim]")
        
        # Build task list
        tasks = []
        
        # Port scan
        port_list = self._parse_ports(ports)
        console.print(f"[dim]Scanning {len(port_list)} ports...[/dim]")
        tasks.append(("ports", self._scan_ports(target_obj.identifier, port_list, result)))
        
        # Subdomain enumeration (only for domains)
        if run_subdomains and target_obj.type == TargetType.DOMAIN:
            console.print("[dim]Enumerating subdomains...[/dim]")
            tasks.append(("subdomains", self._enumerate_subdomains(target_obj.identifier, result)))
        
        # WHOIS lookup
        if run_whois:
            console.print("[dim]Running WHOIS lookup...[/dim]")
            tasks.append(("whois", self._whois_lookup(target_obj.identifier, result)))
        
        # Run all tasks in parallel
        task_coros = [coro for _, coro in tasks]
        await asyncio.gather(*task_coros, return_exceptions=True)
        
        # HTTP probing (after port scan to check discovered HTTP ports)
        if run_http and result.open_ports:
            console.print("[dim]Probing HTTP services...[/dim]")
            await self._probe_http(target_obj.identifier, result)
        
        # Complete the scan
        result.complete()
        self.logger.info(f"Recon complete in {result.duration_seconds:.1f}s")
        
        return result
    
    def _parse_ports(self, ports: str) -> list[int]:
        """Parse port specification into list of ports."""
        if ports == "top-1000":
            return TOP_1000_PORTS[:200]  # Limited for speed
        elif ports == "full":
            return list(range(1, 65536))
        elif ports.startswith("top-"):
            count = int(ports.split("-")[1])
            return TOP_1000_PORTS[:count]
        else:
            # Comma-separated list
            return [int(p.strip()) for p in ports.split(",")]
    
    async def _scan_ports(
        self, 
        host: str, 
        ports: list[int], 
        result: ReconResult
    ) -> None:
        """
        Async port scanner using direct socket connections.
        
        Uses semaphore to limit concurrent connections.
        """
        semaphore = asyncio.Semaphore(self.config.scanner.max_concurrent_ports)
        timeout = self.config.scanner.port_timeout
        
        async def scan_single_port(port: int) -> Optional[PortInfo]:
            async with semaphore:
                try:
                    # Try to connect
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    
                    # Port is open
                    service = SERVICE_SIGNATURES.get(port)
                    return PortInfo(port=port, state="open", service=service)
                    
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None
        
        # Scan all ports concurrently
        with ScanProgress("Port Scanning", len(ports)) as progress:
            tasks = []
            for port in ports:
                tasks.append(scan_single_port(port))
            
            # Gather results in chunks for progress updates
            chunk_size = 50
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i+chunk_size]
                results_chunk = await asyncio.gather(*chunk, return_exceptions=True)
                
                for r in results_chunk:
                    if isinstance(r, PortInfo):
                        result.open_ports.append(r)
                
                progress.advance(len(chunk))
        
        result.ports_scanned = len(ports)
        self.logger.info(f"Found {len(result.open_ports)} open ports")
    
    async def _enumerate_subdomains(
        self, 
        domain: str, 
        result: ReconResult
    ) -> None:
        """
        Async subdomain enumeration using DNS resolution.
        """
        # Load wordlist
        wordlist = self._load_subdomain_wordlist()
        
        semaphore = asyncio.Semaphore(self.config.scanner.max_concurrent_dns)
        
        async def check_subdomain(subdomain: str) -> Optional[DomainInfo]:
            async with semaphore:
                full_domain = f"{subdomain}.{domain}"
                try:
                    # Use socket.getaddrinfo in thread (more reliable than aiodns on Windows)
                    loop = asyncio.get_event_loop()
                    addrs = await loop.run_in_executor(
                        None,
                        lambda: socket.getaddrinfo(full_domain, None, socket.AF_INET)
                    )
                    
                    if addrs:
                        ips = list(set(addr[4][0] for addr in addrs))
                        return DomainInfo(name=full_domain, resolved_ips=ips)
                    
                except (socket.gaierror, socket.herror, OSError):
                    pass
                
                return None
        
        # Run subdomain checks
        with ScanProgress("Subdomain Enum", len(wordlist)) as progress:
            chunk_size = 100
            for i in range(0, len(wordlist), chunk_size):
                chunk = wordlist[i:i+chunk_size]
                tasks = [check_subdomain(sub) for sub in chunk]
                results_chunk = await asyncio.gather(*tasks, return_exceptions=True)
                
                for r in results_chunk:
                    if isinstance(r, DomainInfo):
                        result.subdomains.append(r)
                
                progress.advance(len(chunk))
        
        result.subdomains_checked = len(wordlist)
        self.logger.info(f"Found {len(result.subdomains)} subdomains")
    
    def _load_subdomain_wordlist(self) -> list[str]:
        """Load subdomain wordlist."""
        # Default common subdomains
        default_subs = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
            "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
            "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin",
            "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists",
            "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql",
            "secure", "demo", "cp", "calendar", "wiki", "web", "media", "email",
            "images", "img", "www1", "intranet", "portal", "video", "sip",
            "dns2", "api", "cdn", "stats", "cloud", "dns1", "ns4", "www3",
            "dns", "search", "staging", "server", "mx1", "chat", "wap", "labs",
            "crm", "help", "jobs", "bugs", "assets", "ec2", "git", "app",
            "svn", "ssh", "login", "data", "files", "backup", "monitoring",
        ]
        
        # Try to load from file
        wordlist_path = Path(self.config.scanner.default_wordlist)
        if wordlist_path.exists():
            try:
                with open(wordlist_path) as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception:
                pass
        
        return default_subs
    
    async def _whois_lookup(
        self, 
        target: str, 
        result: ReconResult
    ) -> None:
        """
        Run WHOIS lookup (in thread pool since whois library is blocking).
        """
        try:
            import whois
            
            # Run in thread pool
            whois_data = await run_in_thread(whois.whois, target)
            
            if whois_data:
                result.whois = WhoisInfo(
                    registrar=getattr(whois_data, 'registrar', None),
                    org=getattr(whois_data, 'org', None),
                    creation_date=str(whois_data.creation_date) if whois_data.creation_date else None,
                    expiration_date=str(whois_data.expiration_date) if whois_data.expiration_date else None,
                    updated_date=str(whois_data.updated_date) if whois_data.updated_date else None,
                    name_servers=list(whois_data.name_servers or []) if hasattr(whois_data, 'name_servers') else [],
                    status=list(whois_data.status or []) if hasattr(whois_data, 'status') else [],
                    emails=list(whois_data.emails or []) if hasattr(whois_data, 'emails') else [],
                    country=getattr(whois_data, 'country', None),
                )
                self.logger.info("WHOIS lookup complete")
                
        except Exception as e:
            result.warnings.append(f"WHOIS lookup failed: {str(e)}")
            self.logger.warning(f"WHOIS failed: {e}")
    
    async def _probe_http(
        self, 
        target: str, 
        result: ReconResult
    ) -> None:
        """
        Probe HTTP services on discovered ports.
        """
        # Find HTTP-likely ports
        http_ports = []
        for port_info in result.open_ports:
            if port_info.port in [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]:
                http_ports.append(port_info.port)
            elif port_info.service and "http" in port_info.service.lower():
                http_ports.append(port_info.port)
        
        # Also probe standard ports if open
        for port in [80, 443]:
            if port not in http_ports:
                for pi in result.open_ports:
                    if pi.port == port:
                        http_ports.append(port)
        
        if not http_ports:
            # Default to common HTTP ports
            http_ports = [80, 443]
        
        async with httpx.AsyncClient(
            timeout=self.config.scanner.http_timeout,
            follow_redirects=self.config.scanner.follow_redirects,
            verify=self.config.scanner.verify_ssl,
        ) as client:
            
            async def probe_url(port: int, scheme: str) -> Optional[HttpService]:
                url = f"{scheme}://{target}:{port}" if port not in [80, 443] else f"{scheme}://{target}"
                if port == 443 and scheme == "http":
                    return None
                if port == 80 and scheme == "https":
                    return None
                    
                try:
                    start_time = datetime.now()
                    response = await client.get(url)
                    elapsed = (datetime.now() - start_time).total_seconds() * 1000
                    
                    # Extract title
                    title = None
                    if "text/html" in response.headers.get("content-type", ""):
                        match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE)
                        if match:
                            title = match.group(1).strip()
                    
                    return HttpService(
                        url=str(response.url),
                        status_code=response.status_code,
                        title=title,
                        server=response.headers.get("server"),
                        content_length=int(response.headers.get("content-length", 0)),
                        redirect_url=str(response.url) if response.url != url else None,
                        response_time_ms=elapsed,
                        headers=dict(response.headers),
                    )
                    
                except Exception:
                    return None
            
            # Probe both HTTP and HTTPS for each port
            tasks = []
            for port in http_ports:
                tasks.append(probe_url(port, "http"))
                tasks.append(probe_url(port, "https"))
            
            results_http = await asyncio.gather(*tasks, return_exceptions=True)
            
            for r in results_http:
                if isinstance(r, HttpService):
                    result.http_services.append(r)
            
            result.http_probed = len(http_ports)
            self.logger.info(f"Found {len(result.http_services)} HTTP services")
