"""
ICARUS-X Workflow Manager
=========================
Orchestrates pentest workflow phases.
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional
import orjson

from sqlmodel import Session, SQLModel, create_engine, select

from models.workflow import (
    WorkflowRun, WorkflowPhase, PhaseStatus, RunStatus,
    RunDB, PhaseDB, FindingDB
)
from models.target import ReconResult
from models.finding import Finding, Severity
from core.scanner import ReconEngine
from utils.config import IcarusConfig
from utils.logger import get_logger, console


class WorkflowManager:
    """
    Manages pentest workflow execution.
    
    Phases:
    1. Recon - Target reconnaissance
    2. Vuln Scan - Vulnerability detection
    3. Exploit - Exploitation (placeholder)
    4. Post-Exploit - Post-exploitation (placeholder)
    5. Report - Generate report
    """
    
    def __init__(self, config: IcarusConfig):
        self.config = config
        self.logger = get_logger()
        
        # Initialize database
        db_path = Path(config.database_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{db_path}")
        SQLModel.metadata.create_all(self.engine)
        
        # Initialize sub-engines
        self.recon_engine = ReconEngine(config)
    
    async def create_run(self, target: str, workflow: str = "full") -> WorkflowRun:
        """Create a new workflow run."""
        run = WorkflowRun(target=target, workflow=workflow)
        run.started_at = datetime.now()
        run.status = RunStatus.RUNNING
        
        # Persist to database
        with Session(self.engine) as session:
            run_db = RunDB(
                id=run.id,
                target=target,
                workflow=workflow,
                status=run.status.value,
                started_at=run.started_at,
            )
            session.add(run_db)
            session.commit()
        
        self.logger.info(f"Created run: {run.id}")
        return run
    
    def resume_run(self, run_id: str) -> Optional[WorkflowRun]:
        """Resume an existing run."""
        with Session(self.engine) as session:
            run_db = session.get(RunDB, run_id)
            if not run_db:
                return None
            
            run = WorkflowRun(
                id=run_db.id,
                target=run_db.target,
                workflow=run_db.workflow,
                status=RunStatus(run_db.status),
                started_at=run_db.started_at,
                finished_at=run_db.finished_at,
                finding_count=run_db.finding_count,
            )
            
            # Load phases
            phases = session.exec(
                select(PhaseDB).where(PhaseDB.run_id == run_id)
            ).all()
            for phase_db in phases:
                run.phases[phase_db.name] = WorkflowPhase(
                    name=phase_db.name,
                    status=PhaseStatus(phase_db.status),
                    started_at=phase_db.started_at,
                    finished_at=phase_db.finished_at,
                    error=phase_db.error_message,
                )
            
            return run
    
    def get_run(self, run_id: str) -> Optional[WorkflowRun]:
        """Get a run by ID."""
        return self.resume_run(run_id)
    
    def list_runs(self, limit: int = 10) -> list[RunDB]:
        """List recent runs."""
        with Session(self.engine) as session:
            runs = session.exec(
                select(RunDB).order_by(RunDB.started_at.desc()).limit(limit)
            ).all()
            return list(runs)
    
    def get_run_context(self, run_id: str) -> dict:
        """Get run context for AI."""
        run = self.get_run(run_id)
        if not run:
            return {}
        
        with Session(self.engine) as session:
            findings = session.exec(
                select(FindingDB).where(FindingDB.run_id == run_id)
            ).all()
        
        return {
            "target": run.target,
            "phases": {k: v.status.value for k, v in run.phases.items()},
            "findings": [f.title for f in findings],
        }
    
    async def execute_workflow(
        self,
        run: WorkflowRun,
        skip_phases: set[str] = None,
        only_phases: set[str] = None,
    ) -> WorkflowRun:
        """Execute the workflow phases."""
        skip_phases = skip_phases or set()
        
        console.print(f"\n[bold]Starting workflow: {run.workflow}[/bold]\n")
        
        for phase_name in WorkflowRun.PHASE_ORDER:
            # Check skip/only
            if phase_name in skip_phases:
                run.skip_phase(phase_name)
                console.print(f"[dim]⏭️  Skipped: {phase_name}[/dim]")
                continue
            
            if only_phases and phase_name not in only_phases:
                run.skip_phase(phase_name)
                continue
            
            # Check if already done
            if run.phases[phase_name].status == PhaseStatus.DONE:
                console.print(f"[dim]✅ Already done: {phase_name}[/dim]")
                continue
            
            # Execute phase
            console.print(f"\n[bold cyan]▶️  Phase: {phase_name}[/bold cyan]")
            run.start_phase(phase_name)
            self._update_phase_db(run.id, phase_name, run.phases[phase_name])
            
            try:
                if phase_name == "recon":
                    await self._run_recon_phase(run)
                elif phase_name == "vuln_scan":
                    await self._run_vuln_phase(run)
                elif phase_name == "exploit":
                    await self._run_exploit_phase(run)
                elif phase_name == "post_exploit":
                    await self._run_postex_phase(run)
                elif phase_name == "report":
                    await self._run_report_phase(run)
                
                run.complete_phase(phase_name, success=True)
                console.print(f"[green]✅ Completed: {phase_name}[/green]")
                
            except Exception as e:
                run.complete_phase(phase_name, success=False, error=str(e))
                console.print(f"[red]❌ Failed: {phase_name} - {e}[/red]")
                self.logger.exception(f"Phase failed: {phase_name}")
            
            self._update_phase_db(run.id, phase_name, run.phases[phase_name])
        
        # Complete run
        run.finished_at = datetime.now()
        run.status = RunStatus.DONE
        self._update_run_db(run)
        
        return run
    
    async def _run_recon_phase(self, run: WorkflowRun):
        """Execute reconnaissance phase."""
        results = await self.recon_engine.run_recon(
            run.target,
            ports="top-1000",
            run_subdomains=True,
            run_whois=True,
            run_http=True,
        )
        
        # Store results
        self._store_recon_results(run.id, results)
        
        # Generate basic findings from recon
        findings = self._recon_to_findings(results)
        for finding in findings:
            self._store_finding(run.id, finding)
        
        run.finding_count += len(findings)
    
    async def _run_vuln_phase(self, run: WorkflowRun):
        """Execute vulnerability scanning phase."""
        # For now, generate basic findings based on open ports/services
        console.print("[dim]Running basic vulnerability checks...[/dim]")
        
        # TODO: Integrate with Nuclei, Nmap scripts, etc.
        await asyncio.sleep(1)  # Placeholder
        
        console.print("[dim]Vulnerability scanning complete (basic checks only)[/dim]")
    
    async def _run_exploit_phase(self, run: WorkflowRun):
        """Execute exploitation phase (placeholder)."""
        console.print("[yellow]⚠️ Exploit phase is a placeholder - manual exploitation required[/yellow]")
        console.print("[dim]This phase would suggest exploits based on findings[/dim]")
    
    async def _run_postex_phase(self, run: WorkflowRun):
        """Execute post-exploitation phase (placeholder)."""
        console.print("[yellow]⚠️ Post-exploit phase is a placeholder[/yellow]")
    
    async def _run_report_phase(self, run: WorkflowRun):
        """Execute report generation phase."""
        from core.reporter import ReportGenerator
        
        reporter = ReportGenerator(self.config)
        report_path = await reporter.generate(run, "html")
        console.print(f"[green]📄 Report generated: {report_path}[/green]")
    
    def _recon_to_findings(self, results: ReconResult) -> list[Finding]:
        """Convert recon results to findings."""
        findings = []
        
        # Flag potentially dangerous open ports
        dangerous_ports = {
            21: ("FTP Open", "FTP service exposed. Check for anonymous access.", Severity.MEDIUM),
            22: ("SSH Open", "SSH service exposed. Ensure strong authentication.", Severity.INFO),
            23: ("Telnet Open", "Telnet exposes credentials in cleartext.", Severity.HIGH),
            25: ("SMTP Open", "SMTP service may allow relay.", Severity.LOW),
            445: ("SMB Open", "SMB service exposed. Check for vulnerabilities.", Severity.MEDIUM),
            3389: ("RDP Open", "Remote Desktop exposed. Check for BlueKeep.", Severity.MEDIUM),
            6379: ("Redis Open", "Redis may be exposed without auth.", Severity.HIGH),
            27017: ("MongoDB Open", "MongoDB may lack authentication.", Severity.HIGH),
        }
        
        for port_info in results.open_ports:
            if port_info.port in dangerous_ports:
                title, desc, severity = dangerous_ports[port_info.port]
                findings.append(Finding(
                    title=title,
                    description=desc,
                    severity=severity,
                    affected_asset=f"{results.target.identifier}:{port_info.port}",
                    category="Network",
                ))
        
        return findings
    
    def _store_recon_results(self, run_id: str, results: ReconResult):
        """Store recon results to database."""
        with Session(self.engine) as session:
            phase = session.exec(
                select(PhaseDB).where(
                    PhaseDB.run_id == run_id,
                    PhaseDB.name == "recon"
                )
            ).first()
            
            if phase:
                phase.result_json = orjson.dumps(results.model_dump()).decode()
                session.add(phase)
                session.commit()
    
    def _store_finding(self, run_id: str, finding: Finding):
        """Store finding to database."""
        with Session(self.engine) as session:
            finding_db = FindingDB(
                run_id=run_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity.value,
                status=finding.status.value,
                affected_asset=finding.affected_asset,
                category=finding.category,
                remediation=finding.remediation,
            )
            session.add(finding_db)
            session.commit()
    
    def _update_phase_db(self, run_id: str, phase_name: str, phase: WorkflowPhase):
        """Update phase in database."""
        with Session(self.engine) as session:
            phase_db = session.exec(
                select(PhaseDB).where(
                    PhaseDB.run_id == run_id,
                    PhaseDB.name == phase_name
                )
            ).first()
            
            if not phase_db:
                phase_db = PhaseDB(run_id=run_id, name=phase_name)
            
            phase_db.status = phase.status.value
            phase_db.started_at = phase.started_at
            phase_db.finished_at = phase.finished_at
            phase_db.error_message = phase.error
            
            session.add(phase_db)
            session.commit()
    
    def _update_run_db(self, run: WorkflowRun):
        """Update run in database."""
        with Session(self.engine) as session:
            run_db = session.get(RunDB, run.id)
            if run_db:
                run_db.status = run.status.value
                run_db.finished_at = run.finished_at
                run_db.finding_count = run.finding_count
                session.add(run_db)
                session.commit()
