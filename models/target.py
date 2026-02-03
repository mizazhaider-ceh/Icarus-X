"""
ICARUS-X Target and Recon Models
================================
Pydantic models for reconnaissance data.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class TargetType(str, Enum):
    """Type of scan target."""
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"


class Target(BaseModel):
    """Represents a scan target."""
    identifier: str = Field(..., description="Domain, IP, or CIDR notation")
    type: TargetType = Field(default=TargetType.DOMAIN)
    notes: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    
    @classmethod
    def from_string(cls, target: str) -> "Target":
        """Create Target from string, auto-detecting type."""
        import re
        
        # CIDR pattern
        if "/" in target and re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", target):
            return cls(identifier=target, type=TargetType.CIDR)
        
        # IP pattern
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            return cls(identifier=target, type=TargetType.IP)
        
        # URL pattern
        if target.startswith(("http://", "https://")):
            return cls(identifier=target, type=TargetType.URL)
        
        # Default to domain
        return cls(identifier=target, type=TargetType.DOMAIN)


class PortInfo(BaseModel):
    """Information about a discovered port."""
    port: int
    state: str = "open"
    protocol: str = "tcp"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


class DomainInfo(BaseModel):
    """Information about a discovered subdomain."""
    name: str
    resolved_ips: list[str] = Field(default_factory=list)
    cname: Optional[str] = None
    is_wildcard: bool = False


class HttpService(BaseModel):
    """Information about an HTTP service."""
    url: str
    status_code: int
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: list[str] = Field(default_factory=list)
    content_length: Optional[int] = None
    redirect_url: Optional[str] = None
    response_time_ms: Optional[float] = None
    headers: dict[str, str] = Field(default_factory=dict)
    tls_info: Optional[dict] = None


class WhoisInfo(BaseModel):
    """WHOIS lookup results."""
    registrar: Optional[str] = None
    org: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list)
    dnssec: Optional[str] = None
    emails: list[str] = Field(default_factory=list)
    country: Optional[str] = None
    raw: Optional[str] = None


class ReconResult(BaseModel):
    """Complete reconnaissance results."""
    target: Target
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    
    open_ports: list[PortInfo] = Field(default_factory=list)
    subdomains: list[DomainInfo] = Field(default_factory=list)
    http_services: list[HttpService] = Field(default_factory=list)
    whois: Optional[WhoisInfo] = None
    
    # Statistics
    ports_scanned: int = 0
    subdomains_checked: int = 0
    http_probed: int = 0
    
    # Errors and warnings
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    
    def complete(self):
        """Mark reconnaissance as complete."""
        self.finished_at = datetime.now()
        self.duration_seconds = (self.finished_at - self.started_at).total_seconds()
    
    @property
    def summary(self) -> dict:
        """Get result summary."""
        return {
            "target": self.target.identifier,
            "duration": f"{self.duration_seconds:.1f}s" if self.duration_seconds else "in progress",
            "open_ports": len(self.open_ports),
            "subdomains": len(self.subdomains),
            "http_services": len(self.http_services),
            "errors": len(self.errors),
        }
