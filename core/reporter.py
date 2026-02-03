"""
ICARUS-X Report Generator
=========================
Generates professional pentest reports.
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiofiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
import orjson
from sqlmodel import Session, create_engine, select

from models.workflow import WorkflowRun, RunDB, PhaseDB, FindingDB
from models.finding import Finding, Severity, FindingSummary
from utils.config import IcarusConfig
from utils.logger import get_logger


class ReportGenerator:
    """
    Generates professional pentest reports.
    
    Supports:
    - HTML reports with styled output
    - Markdown reports
    - JSON export
    """
    
    def __init__(self, config: IcarusConfig):
        self.config = config
        self.logger = get_logger()
        
        # Initialize Jinja2
        template_dir = Path(__file__).parent.parent / "templates"
        template_dir.mkdir(exist_ok=True)
        
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml']),
        )
        
        # Create default templates if they don't exist
        self._ensure_templates(template_dir)
        
        # Database connection
        db_path = Path(config.database_path)
        self.engine = create_engine(f"sqlite:///{db_path}")
    
    def _ensure_templates(self, template_dir: Path):
        """Create default templates if missing."""
        html_template = template_dir / "report.html.j2"
        if not html_template.exists():
            html_template.write_text(DEFAULT_HTML_TEMPLATE)
        
        md_template = template_dir / "report.md.j2"
        if not md_template.exists():
            md_template.write_text(DEFAULT_MD_TEMPLATE)
    
    async def generate(
        self,
        run: WorkflowRun,
        format: str = "html",
        output_path: Optional[str] = None,
    ) -> Path:
        """
        Generate a report for a workflow run.
        
        Args:
            run: WorkflowRun to report on
            format: Report format (html, markdown, json)
            output_path: Optional output path
            
        Returns:
            Path to generated report
        """
        # Load findings from database
        findings = self._load_findings(run.id)
        summary = FindingSummary.from_findings(findings)
        
        # Prepare context
        context = {
            "run": run,
            "findings": findings,
            "summary": summary,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "phases": run.phases,
        }
        
        # Determine output path
        if output_path:
            output_file = Path(output_path)
        else:
            artifacts_dir = Path(self.config.artifacts_dir)
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            ext = "html" if format == "html" else ("md" if format == "markdown" else "json")
            output_file = artifacts_dir / f"report_{run.id[:8]}.{ext}"
        
        # Generate report
        if format == "json":
            content = orjson.dumps({
                "run_id": run.id,
                "target": run.target,
                "workflow": run.workflow,
                "started_at": str(run.started_at),
                "finished_at": str(run.finished_at),
                "summary": summary.model_dump(),
                "findings": [f.model_dump() for f in findings],
            }, option=orjson.OPT_INDENT_2).decode()
        else:
            template_name = "report.html.j2" if format == "html" else "report.md.j2"
            template = self.env.get_template(template_name)
            content = template.render(**context)
        
        # Write to file
        async with aiofiles.open(output_file, 'w', encoding='utf-8') as f:
            await f.write(content)
        
        self.logger.info(f"Report generated: {output_file}")
        return output_file
    
    def _load_findings(self, run_id: str) -> list[Finding]:
        """Load findings from database."""
        with Session(self.engine) as session:
            findings_db = session.exec(
                select(FindingDB).where(FindingDB.run_id == run_id)
            ).all()
            
            return [
                Finding(
                    id=f.id,
                    run_id=f.run_id,
                    title=f.title,
                    description=f.description,
                    severity=Severity(f.severity),
                    affected_asset=f.affected_asset,
                    category=f.category,
                    remediation=f.remediation,
                )
                for f in findings_db
            ]


# Default HTML template
DEFAULT_HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ICARUS-X Security Report - {{ run.target }}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-cyan: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-orange: #d29922;
            --accent-yellow: #e3b341;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        
        header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid #30363d;
        }
        
        h1 { color: var(--accent-cyan); font-size: 2.5rem; margin-bottom: 0.5rem; }
        h2 { color: var(--text-primary); font-size: 1.5rem; margin: 1.5rem 0 1rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }
        
        .meta { color: var(--text-secondary); font-size: 0.9rem; }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }
        
        .summary-card {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid #30363d;
        }
        
        .summary-card .count { font-size: 2.5rem; font-weight: bold; }
        .summary-card .label { color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; }
        
        .severity-critical { color: var(--accent-red); border-left: 4px solid var(--accent-red); }
        .severity-high { color: var(--accent-orange); border-left: 4px solid var(--accent-orange); }
        .severity-medium { color: var(--accent-yellow); border-left: 4px solid var(--accent-yellow); }
        .severity-low { color: var(--accent-cyan); border-left: 4px solid var(--accent-cyan); }
        .severity-info { color: var(--text-secondary); border-left: 4px solid var(--text-secondary); }
        
        .finding {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border: 1px solid #30363d;
        }
        
        .finding h3 { font-size: 1.2rem; margin-bottom: 0.5rem; }
        .finding .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 0.5rem;
        }
        
        .badge-critical { background: var(--accent-red); color: white; }
        .badge-high { background: var(--accent-orange); color: black; }
        .badge-medium { background: var(--accent-yellow); color: black; }
        .badge-low { background: var(--accent-cyan); color: black; }
        .badge-info { background: var(--text-secondary); color: black; }
        
        .finding p { color: var(--text-secondary); margin-top: 0.5rem; }
        .finding .asset { font-family: monospace; color: var(--accent-cyan); }
        
        footer {
            text-align: center;
            color: var(--text-secondary);
            padding: 2rem;
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ ICARUS-X Security Report</h1>
            <p class="meta">
                <strong>Target:</strong> {{ run.target }}<br>
                <strong>Generated:</strong> {{ generated_at }}<br>
                <strong>Run ID:</strong> {{ run.id[:8] }}
            </p>
        </header>
        
        <section>
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card severity-critical">
                    <div class="count">{{ summary.critical }}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-card severity-high">
                    <div class="count">{{ summary.high }}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-card severity-medium">
                    <div class="count">{{ summary.medium }}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-card severity-low">
                    <div class="count">{{ summary.low }}</div>
                    <div class="label">Low</div>
                </div>
                <div class="summary-card severity-info">
                    <div class="count">{{ summary.info }}</div>
                    <div class="label">Info</div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>🔍 Findings</h2>
            {% for finding in findings %}
            <div class="finding severity-{{ finding.severity.value }}">
                <h3>
                    <span class="badge badge-{{ finding.severity.value }}">{{ finding.severity.value }}</span>
                    {{ finding.title }}
                </h3>
                <p class="asset">📍 {{ finding.affected_asset }}</p>
                <p>{{ finding.description }}</p>
                {% if finding.remediation %}
                <p><strong>Remediation:</strong> {{ finding.remediation }}</p>
                {% endif %}
            </div>
            {% else %}
            <p>No findings discovered.</p>
            {% endfor %}
        </section>
        
        <footer>
            <p>Generated by ICARUS-X Unified Pentesting Framework</p>
        </footer>
    </div>
</body>
</html>
'''

# Default Markdown template
DEFAULT_MD_TEMPLATE = '''# 🛡️ ICARUS-X Security Report

**Target:** {{ run.target }}  
**Generated:** {{ generated_at }}  
**Run ID:** {{ run.id[:8] }}

---

## 📊 Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {{ summary.critical }} |
| 🟠 High | {{ summary.high }} |
| 🟡 Medium | {{ summary.medium }} |
| 🔵 Low | {{ summary.low }} |
| ⚪ Info | {{ summary.info }} |

---

## 🔍 Findings

{% for finding in findings %}
### {{ finding.severity.value | upper }}: {{ finding.title }}

- **Affected Asset:** `{{ finding.affected_asset }}`
- **Category:** {{ finding.category }}
- **Description:** {{ finding.description }}
{% if finding.remediation %}
- **Remediation:** {{ finding.remediation }}
{% endif %}

{% else %}
No findings discovered.
{% endfor %}

---

*Generated by ICARUS-X Unified Pentesting Framework*
'''
