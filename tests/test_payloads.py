"""Tests for the payload generator (modules/payloads.py)."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.payloads import REVERSE_SHELLS, generate_reverse_shell  # noqa: E402


class TestReverseShells:
    def test_all_shells_generate(self):
        """Every bundled reverse shell must render without exceptions."""
        assert len(REVERSE_SHELLS) > 0
        for name in REVERSE_SHELLS:
            payload = generate_reverse_shell(name, "10.10.14.5", 4444)
            assert isinstance(payload, str) and len(payload) > 0

    def test_placeholders_substituted(self):
        """{ip} and {port} placeholders must be replaced, even with literal braces present."""
        for name in ["perl", "powershell", "awk", "bash", "python"]:
            payload = generate_reverse_shell(name, "10.10.14.5", 4444)
            assert "{ip}" not in payload, name
            assert "{port}" not in payload, name
            assert "10.10.14.5" in payload, name
            assert "4444" in payload, name

    def test_unknown_shell_type(self):
        result = generate_reverse_shell("nonexistent", "1.2.3.4", 4444)
        assert "Unknown shell type" in result

    def test_encoder_applied(self):
        payload = generate_reverse_shell("bash", "10.10.14.5", 4444, encoder="base64")
        assert payload != generate_reverse_shell("bash", "10.10.14.5", 4444)
