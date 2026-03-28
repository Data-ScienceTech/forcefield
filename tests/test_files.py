"""Tests for the files module (filename scanning + ProtectedPathSet)."""

import pytest
from forcefield.files import scan_filename, FilenameScanResult, FilenameFinding, ProtectedPathSet


class TestScanFilename:
    def test_safe_filename(self):
        result = scan_filename("README.md")
        assert isinstance(result, FilenameScanResult)
        assert result.dangerous is False
        assert len(result.findings) == 0

    def test_env_file(self):
        result = scan_filename(".env")
        assert result.dangerous is True
        codes = [f.code for f in result.findings]
        assert "env_file" in codes

    def test_env_variant(self):
        result = scan_filename(".env.production")
        assert result.dangerous is True

    def test_private_key(self):
        result = scan_filename("id_rsa")
        assert result.dangerous is True
        assert result.severity == "critical"

    def test_pem_file(self):
        result = scan_filename("server.pem")
        assert result.dangerous is True
        codes = [f.code for f in result.findings]
        assert "pem_file" in codes

    def test_secrets_json(self):
        result = scan_filename("secrets.json")
        assert result.dangerous is True
        assert result.severity == "critical"

    def test_gitignore(self):
        result = scan_filename(".gitignore")
        assert result.dangerous is True
        assert result.severity == "info"

    def test_delete_escalation(self):
        result = scan_filename(".gitignore", operation="delete")
        assert result.dangerous is True
        assert result.severity == "warning"

    def test_delete_critical_escalation(self):
        result = scan_filename(".env", operation="delete")
        assert result.dangerous is True
        assert result.severity == "critical"

    def test_system_auth_file(self):
        result = scan_filename("shadow")
        assert result.dangerous is True
        assert result.severity == "critical"

    def test_full_path_basename(self):
        result = scan_filename("/home/user/.ssh/id_rsa")
        assert result.dangerous is True
        codes = [f.code for f in result.findings]
        assert "private_key" in codes

    def test_to_dict(self):
        result = scan_filename(".env")
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["dangerous"] is True
        assert isinstance(d["findings"], list)
        assert "code" in d["findings"][0]
        assert "operation" in d["findings"][0]


class TestProtectedPathSet:
    def test_empty(self):
        ps = ProtectedPathSet()
        assert ps.is_protected("anything.txt") is False
        assert len(ps) == 0
        assert not ps

    def test_exact_match(self):
        ps = ProtectedPathSet([".env"])
        assert ps.is_protected(".env") is True
        assert ps.is_protected("other.txt") is False

    def test_basename_match(self):
        ps = ProtectedPathSet([".gitignore"])
        assert ps.is_protected("src/.gitignore") is True
        assert ps.is_protected("/home/user/project/.gitignore") is True

    def test_folder_glob(self):
        ps = ProtectedPathSet(["src/config/**"])
        assert ps.is_protected("src/config/secrets.yaml") is True
        assert ps.is_protected("src/config/db/conn.json") is True
        assert ps.is_protected("src/other/file.txt") is False

    def test_extension_glob(self):
        ps = ProtectedPathSet(["*.pem"])
        assert ps.is_protected("server.pem") is True
        assert ps.is_protected("certs/ca.pem") is True
        assert ps.is_protected("server.key") is False

    def test_folder_prefix(self):
        ps = ProtectedPathSet(["certs/"])
        assert ps.is_protected("certs/server.pem") is True
        assert ps.is_protected("certs/ca/root.crt") is True
        assert ps.is_protected("src/certs.txt") is False

    def test_add_remove(self):
        ps = ProtectedPathSet()
        ps.add(".env")
        assert ps.is_protected(".env") is True
        ps.remove(".env")
        assert ps.is_protected(".env") is False

    def test_clear(self):
        ps = ProtectedPathSet([".env", "*.pem"])
        ps.clear()
        assert len(ps) == 0
        assert ps.is_protected(".env") is False

    def test_patterns_property(self):
        ps = ProtectedPathSet([".env", "*.pem"])
        assert ps.patterns == [".env", "*.pem"]

    def test_no_duplicates_on_add(self):
        ps = ProtectedPathSet([".env"])
        ps.add(".env")
        assert len(ps) == 1

    def test_backslash_normalization(self):
        ps = ProtectedPathSet(["src/config/**"])
        assert ps.is_protected("src\\config\\secrets.yaml") is True

    def test_bool(self):
        ps = ProtectedPathSet()
        assert not ps
        ps.add(".env")
        assert ps
