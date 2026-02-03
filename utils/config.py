"""
ICARUS-X Configuration Management
=================================
Loads and manages configuration from TOML file and environment variables.
"""

import os
from pathlib import Path
from typing import Any, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class ScannerConfig(BaseModel):
    """Scanner configuration."""
    default_ports: str = "top-1000"
    port_timeout: float = 2.0
    max_concurrent_ports: int = 500
    subdomain_timeout: float = 3.0
    max_concurrent_dns: int = 200
    default_wordlist: str = "subdomains-top1mil-5000.txt"
    http_timeout: float = 5.0
    max_concurrent_http: int = 100
    follow_redirects: bool = True
    verify_ssl: bool = False


class WorkflowConfig(BaseModel):
    """Workflow configuration."""
    default_workflow: str = "full"
    enabled_phases: list[str] = ["recon", "vuln_scan", "report"]


class AIConfig(BaseModel):
    """AI configuration."""
    provider: str = "gemini"
    model: str = "gemini-1.5-flash"
    max_tokens: int = 4096
    temperature: float = 0.7
    api_key_env: str = "ICARUS_AI_API_KEY"
    
    @property
    def api_key(self) -> Optional[str]:
        """Get API key from environment."""
        return os.environ.get(self.api_key_env) or os.environ.get("GEMINI_API_KEY")


class ReportingConfig(BaseModel):
    """Reporting configuration."""
    default_format: str = "html"
    template_dir: str = "./templates"
    include_evidence: bool = True


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = "INFO"
    log_dir: str = "./logs"
    format: str = "rich"


class IcarusConfig(BaseModel):
    """Main ICARUS-X configuration."""
    version: str = "1.0.0"
    debug: bool = False
    artifacts_dir: str = "./artifacts"
    database_path: str = "./icarus.db"
    
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    workflow: WorkflowConfig = Field(default_factory=WorkflowConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


def load_config(config_path: Optional[Path] = None) -> IcarusConfig:
    """
    Load configuration from TOML file.
    
    Args:
        config_path: Path to config file. Defaults to icarus.toml in current dir.
        
    Returns:
        IcarusConfig instance
    """
    if config_path is None:
        # Look for config in current dir or package dir
        candidates = [
            Path.cwd() / "icarus.toml",
            Path(__file__).parent.parent / "icarus.toml",
        ]
        for candidate in candidates:
            if candidate.exists():
                config_path = candidate
                break
    
    if config_path and config_path.exists():
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        
        # Flatten structure for pydantic
        config_data = {
            "version": data.get("general", {}).get("version", "1.0.0"),
            "debug": data.get("general", {}).get("debug", False),
            "artifacts_dir": data.get("general", {}).get("artifacts_dir", "./artifacts"),
            "database_path": data.get("general", {}).get("database_path", "./icarus.db"),
            "scanner": data.get("scanner", {}),
            "workflow": data.get("workflow", {}),
            "ai": data.get("ai", {}),
            "reporting": data.get("reporting", {}),
            "logging": data.get("logging", {}),
        }
        return IcarusConfig(**config_data)
    
    # Return defaults if no config file
    return IcarusConfig()


# Singleton config instance
_config: Optional[IcarusConfig] = None


def get_config() -> IcarusConfig:
    """Get the global config instance."""
    global _config
    if _config is None:
        _config = load_config()
    return _config
