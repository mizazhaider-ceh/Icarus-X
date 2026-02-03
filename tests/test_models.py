"""
ICARUS-X Model Tests
====================
Tests for data models.
"""

import pytest
from models.target import Target, TargetType, PortInfo, ReconResult
from models.finding import Finding, Severity, FindingSummary


class TestTarget:
    """Tests for Target model."""
    
    def test_from_string_domain(self):
        """Test domain detection."""
        target = Target.from_string("example.com")
        assert target.type == TargetType.DOMAIN
        assert target.identifier == "example.com"
    
    def test_from_string_ip(self):
        """Test IP detection."""
        target = Target.from_string("192.168.1.1")
        assert target.type == TargetType.IP
        assert target.identifier == "192.168.1.1"
    
    def test_from_string_cidr(self):
        """Test CIDR detection."""
        target = Target.from_string("192.168.1.0/24")
        assert target.type == TargetType.CIDR
    
    def test_from_string_url(self):
        """Test URL detection."""
        target = Target.from_string("https://example.com")
        assert target.type == TargetType.URL


class TestPortInfo:
    """Tests for PortInfo model."""
    
    def test_port_info_creation(self):
        """Test basic creation."""
        port = PortInfo(port=80, state="open", service="http")
        assert port.port == 80
        assert port.state == "open"
        assert port.service == "http"


class TestReconResult:
    """Tests for ReconResult model."""
    
    def test_recon_result_creation(self):
        """Test result creation."""
        target = Target.from_string("example.com")
        result = ReconResult(target=target)
        assert result.target.identifier == "example.com"
        assert len(result.open_ports) == 0
    
    def test_recon_result_complete(self):
        """Test completion."""
        target = Target.from_string("example.com")
        result = ReconResult(target=target)
        result.complete()
        assert result.finished_at is not None
        assert result.duration_seconds is not None


class TestFinding:
    """Tests for Finding model."""
    
    def test_finding_creation(self):
        """Test finding creation."""
        finding = Finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            affected_asset="example.com:22",
        )
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
    
    def test_severity_color(self):
        """Test severity colors."""
        finding = Finding(
            title="Critical",
            description="Test",
            severity=Severity.CRITICAL,
            affected_asset="test",
        )
        assert finding.severity_color == "red"


class TestFindingSummary:
    """Tests for FindingSummary model."""
    
    def test_from_findings(self):
        """Test summary generation."""
        findings = [
            Finding(title="F1", description="D1", severity=Severity.CRITICAL, affected_asset="a1"),
            Finding(title="F2", description="D2", severity=Severity.HIGH, affected_asset="a2"),
            Finding(title="F3", description="D3", severity=Severity.HIGH, affected_asset="a3"),
            Finding(title="F4", description="D4", severity=Severity.LOW, affected_asset="a4"),
        ]
        summary = FindingSummary.from_findings(findings)
        assert summary.total == 4
        assert summary.critical == 1
        assert summary.high == 2
        assert summary.low == 1
