"""
ICARUS-X Logging System
=======================
Beautiful Rich-based logging with structured output support.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

from utils.config import IcarusConfig

# Global logger and console
_logger: Optional[logging.Logger] = None
console = Console()


def setup_logger(config: IcarusConfig, verbose: bool = False) -> logging.Logger:
    """
    Set up the logging system.
    
    Args:
        config: ICARUS-X configuration
        verbose: Enable verbose (DEBUG) output
        
    Returns:
        Configured logger instance
    """
    global _logger
    
    # Determine log level
    level = logging.DEBUG if verbose else getattr(logging, config.logging.level.upper())
    
    # Create logger
    logger = logging.getLogger("icarus")
    logger.setLevel(level)
    logger.handlers.clear()
    
    # Rich console handler (pretty output)
    if config.logging.format == "rich":
        handler = RichHandler(
            console=console,
            show_time=True,
            show_path=verbose,
            rich_tracebacks=True,
            tracebacks_suppress=[],
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        # Plain handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
        )
    
    handler.setLevel(level)
    logger.addHandler(handler)
    
    # File handler (if log_dir specified)
    if config.logging.log_dir:
        log_dir = Path(config.logging.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_dir / "icarus.log")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)s - %(name)s - %(message)s")
        )
        logger.addHandler(file_handler)
    
    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    """Get the global logger instance."""
    global _logger
    if _logger is None:
        # Create default logger if not set up
        _logger = logging.getLogger("icarus")
        if not _logger.handlers:
            handler = RichHandler(console=console, show_time=True, show_path=False)
            _logger.addHandler(handler)
            _logger.setLevel(logging.INFO)
    return _logger


class ScanProgress:
    """Helper for displaying scan progress with Rich."""
    
    def __init__(self, description: str, total: int):
        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
        
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
        )
        self.task_id = None
        self.description = description
        self.total = total
    
    def __enter__(self):
        self.progress.start()
        self.task_id = self.progress.add_task(self.description, total=self.total)
        return self
    
    def __exit__(self, *args):
        self.progress.stop()
    
    def advance(self, n: int = 1):
        """Advance progress by n steps."""
        self.progress.advance(self.task_id, n)
    
    def update(self, completed: int):
        """Update to specific completed count."""
        self.progress.update(self.task_id, completed=completed)
