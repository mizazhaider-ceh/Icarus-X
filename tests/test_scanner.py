"""
ICARUS-X Scanner Tests
======================
Tests for the async scanner.
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock

from core.scanner import ReconEngine, TOP_1000_PORTS, SERVICE_SIGNATURES
from utils.config import IcarusConfig


class TestReconEngine:
    """Tests for ReconEngine."""
    
    @pytest.fixture
    def config(self):
        """Create test config."""
        return IcarusConfig()
    
    @pytest.fixture
    def engine(self, config):
        """Create test engine."""
        return ReconEngine(config)
    
    def test_parse_ports_top_1000(self, engine):
        """Test top-1000 port parsing returns the full bundled list."""
        ports = engine._parse_ports("top-1000")
        assert ports == TOP_1000_PORTS
        assert 80 in ports
        assert 443 in ports
    
    def test_parse_ports_custom(self, engine):
        """Test custom port list parsing."""
        ports = engine._parse_ports("22,80,443")
        assert ports == [22, 80, 443]
    
    def test_parse_ports_top_n(self, engine):
        """Test top-N port parsing."""
        ports = engine._parse_ports("top-10")
        assert ports == TOP_1000_PORTS[:10]

    def test_parse_ports_invalid(self, engine):
        """Test invalid port specs raise ValueError."""
        for bad in ["", "abc", "0", "99999", "80-abc", "top-0", "top-abc", "22,foo"]:
            with pytest.raises(ValueError):
                engine._parse_ports(bad)

    def test_parse_ports_dedup_sorted(self, engine):
        """Custom lists are deduplicated and sorted."""
        assert engine._parse_ports("443,22,22,80") == [22, 80, 443]
    
    def test_service_signatures(self):
        """Test service signature mapping."""
        assert SERVICE_SIGNATURES[22] == "ssh"
        assert SERVICE_SIGNATURES[80] == "http"
        assert SERVICE_SIGNATURES[443] == "https"


class TestSubdomainWordlist:
    """Tests for subdomain wordlist."""
    
    @pytest.fixture
    def engine(self):
        return ReconEngine(IcarusConfig())
    
    def test_default_wordlist(self, engine):
        """Test default wordlist loaded."""
        wordlist = engine._load_subdomain_wordlist()
        assert len(wordlist) > 0
        assert "www" in wordlist
        assert "mail" in wordlist
        assert "api" in wordlist


# Async tests
@pytest.mark.asyncio
class TestAsyncScanning:
    """Async scanning tests."""
    
    @pytest.fixture
    def engine(self):
        return ReconEngine(IcarusConfig())
    
    async def test_port_scan_timeout(self, engine):
        """Test port scan handles timeouts."""
        # This should complete without hanging
        from models.target import ReconResult, Target
        
        result = ReconResult(target=Target.from_string("127.0.0.1"))
        
        # Scan a port that will timeout
        await engine._scan_ports("127.0.0.1", [65432], result)
        
        # Should complete without error
        assert result.ports_scanned == 1
