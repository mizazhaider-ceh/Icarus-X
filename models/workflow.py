"""
ICARUS-X Workflow Models
========================
Database models for workflow runs and phases.
"""

from datetime import datetime
from enum import Enum
from typing import ClassVar, Optional
from uuid import uuid4

from pydantic import BaseModel, Field
from sqlmodel import Field as SQLField, SQLModel


class PhaseStatus(str, Enum):
    """Status of a workflow phase."""
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


class RunStatus(str, Enum):
    """Status of a workflow run."""
    CREATED = "created"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


# SQLModel classes for database persistence
class TargetDB(SQLModel, table=True):
    """Database model for targets."""
    __tablename__ = "targets"
    
    id: Optional[int] = SQLField(default=None, primary_key=True)
    identifier: str
    type: str
    notes: Optional[str] = None
    created_at: datetime = SQLField(default_factory=datetime.now)


class RunDB(SQLModel, table=True):
    """Database model for workflow runs."""
    __tablename__ = "runs"
    
    id: str = SQLField(default_factory=lambda: str(uuid4()), primary_key=True)
    target: str
    workflow: str = "full"
    status: str = RunStatus.CREATED.value
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    finding_count: int = 0


class PhaseDB(SQLModel, table=True):
    """Database model for workflow phases."""
    __tablename__ = "phases"
    
    id: Optional[int] = SQLField(default=None, primary_key=True)
    run_id: str
    name: str
    status: str = PhaseStatus.PENDING.value
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    result_json: Optional[str] = None


class FindingDB(SQLModel, table=True):
    """Database model for findings."""
    __tablename__ = "findings"
    
    id: str = SQLField(default_factory=lambda: str(uuid4()), primary_key=True)
    run_id: str
    title: str
    description: str
    severity: str
    status: str = "new"
    affected_asset: str
    category: str = "General"
    remediation: Optional[str] = None
    evidence_json: Optional[str] = None
    detected_at: datetime = SQLField(default_factory=datetime.now)


# Pydantic models for API/business logic
class WorkflowPhase(BaseModel):
    """Workflow phase for business logic."""
    name: str
    status: PhaseStatus = PhaseStatus.PENDING
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    
    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


class WorkflowRun(BaseModel):
    """Complete workflow run."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    workflow: str = "full"
    status: RunStatus = RunStatus.CREATED
    
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    
    phases: dict[str, WorkflowPhase] = Field(default_factory=dict)
    finding_count: int = 0
    
    # Phase order
    PHASE_ORDER: ClassVar[list[str]] = ["recon", "vuln_scan", "exploit", "post_exploit", "report"]
    
    def __init__(self, **data):
        super().__init__(**data)
        # Initialize phases
        if not self.phases:
            for phase_name in self.PHASE_ORDER:
                self.phases[phase_name] = WorkflowPhase(name=phase_name)
    
    def start_phase(self, phase_name: str):
        """Mark phase as started."""
        if phase_name in self.phases:
            self.phases[phase_name].status = PhaseStatus.RUNNING
            self.phases[phase_name].started_at = datetime.now()
    
    def complete_phase(self, phase_name: str, success: bool = True, error: str = None):
        """Mark phase as complete."""
        if phase_name in self.phases:
            self.phases[phase_name].finished_at = datetime.now()
            self.phases[phase_name].status = PhaseStatus.DONE if success else PhaseStatus.FAILED
            if error:
                self.phases[phase_name].error = error
    
    def skip_phase(self, phase_name: str):
        """Mark phase as skipped."""
        if phase_name in self.phases:
            self.phases[phase_name].status = PhaseStatus.SKIPPED
    
    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None
