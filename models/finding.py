"""
ICARUS-X Finding Model
======================
Model for security findings and vulnerabilities.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Finding status in workflow."""
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"


class Finding(BaseModel):
    """Security finding or vulnerability."""
    id: Optional[str] = None
    run_id: Optional[str] = None
    
    # Core info
    title: str
    description: str
    severity: Severity = Severity.INFO
    status: FindingStatus = FindingStatus.NEW
    
    # Technical details
    affected_asset: str  # URL, IP:port, etc.
    category: str = "General"  # e.g., "Network", "Web", "Configuration"
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    
    # Risk assessment
    impact: Optional[str] = None
    likelihood: Optional[str] = None
    risk_rating: Optional[str] = None
    
    # Evidence
    evidence: list[str] = Field(default_factory=list)  # Paths to evidence files
    evidence_snippets: list[str] = Field(default_factory=list)  # Code/output snippets
    
    # Remediation
    remediation: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    
    # Metadata
    detected_at: datetime = Field(default_factory=datetime.now)
    detected_by: str = "icarus-x"
    confidence: float = 1.0  # 0.0 to 1.0
    
    @property
    def severity_color(self) -> str:
        """Get color for severity display."""
        colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }
        return colors.get(self.severity, "white")


class FindingSummary(BaseModel):
    """Summary of findings for a run."""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    
    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "FindingSummary":
        """Create summary from list of findings."""
        summary = cls(total=len(findings))
        for f in findings:
            if f.severity == Severity.CRITICAL:
                summary.critical += 1
            elif f.severity == Severity.HIGH:
                summary.high += 1
            elif f.severity == Severity.MEDIUM:
                summary.medium += 1
            elif f.severity == Severity.LOW:
                summary.low += 1
            else:
                summary.info += 1
        return summary
