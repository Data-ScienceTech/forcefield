"""Filename security scanning and protected path management.

Zero external dependencies (stdlib only).

Usage::

    from forcefield.files import scan_filename, ProtectedPathSet

    result = scan_filename(".env", operation="create")
    # result.dangerous == True

    protected = ProtectedPathSet([".env", "src/config/**", "*.pem"])
    protected.is_protected("src/config/secrets.yaml")  # True
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class FilenameFinding:
    """A single dangerous pattern match for a filename."""
    code: str
    severity: str
    description: str
    operation: str = ""


@dataclass
class FilenameScanResult:
    """Result of scanning a filename."""
    filename: str
    dangerous: bool
    severity: str
    findings: List[FilenameFinding] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "filename": self.filename,
            "dangerous": self.dangerous,
            "severity": self.severity,
            "findings": [
                {"code": f.code, "severity": f.severity, "description": f.description, "operation": f.operation}
                for f in self.findings
            ],
        }


_SEV_RANK: Dict[str, int] = {"info": 0, "warning": 1, "critical": 2}

DANGEROUS_FILE_PATTERNS = [
    (r"(\.env|\.env\..*)$", "env_file", "warning", "Environment file with potential secrets"),
    (r"(id_rsa|id_ed25519|id_ecdsa|id_dsa)$", "private_key", "critical", "SSH private key"),
    (r"\.pem$", "pem_file", "warning", "PEM certificate/key file"),
    (r"\.key$", "key_file", "warning", "Private key file"),
    (r"(credentials|secrets?\.json|secrets?\.yaml|secrets?\.yml)$", "secrets_file", "critical", "Secrets/credentials file"),
    (r"\.(bash_history|zsh_history|sh_history)$", "shell_history", "warning", "Shell history file"),
    (r"\.gitignore$", "gitignore", "info", "Git ignore file (deletion may expose secrets)"),
    (r"\.npmrc$|\.(pip|pypi)rc$", "package_config", "warning", "Package manager config (may contain tokens)"),
    (r"Dockerfile$|docker-compose.*\.ya?ml$", "container_config", "info", "Container configuration file"),
    (r"\.(sh|bash|zsh|bat|cmd|ps1)$", "executable_script", "info", "Executable script file"),
    (r"(authorized_keys|known_hosts)$", "ssh_config", "warning", "SSH authorization file"),
    (r"(shadow|passwd|sudoers)$", "system_auth", "critical", "System authentication file"),
]

_COMPILED_FILE_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), code, sev, desc)
    for pattern, code, sev, desc in DANGEROUS_FILE_PATTERNS
]


def scan_filename(
    filename: str,
    *,
    operation: str = "create",
) -> FilenameScanResult:
    """Scan a filename for dangerous patterns.

    Args:
        filename: The filename or full path to check.
        operation: One of ``create``, ``delete``, ``rename``.

    Returns:
        ``FilenameScanResult`` with findings and severity.
    """
    basename = os.path.basename(filename)
    findings: List[FilenameFinding] = []
    severity = "info"

    for compiled, code, sev, desc in _COMPILED_FILE_PATTERNS:
        if compiled.search(basename):
            findings.append(FilenameFinding(code=code, severity=sev, description=desc, operation=operation))
            if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(severity, 0):
                severity = sev

    # Deletion of security-critical files is escalated
    if operation == "delete" and findings:
        for f in findings:
            if f.severity == "info":
                f.severity = "warning"
            elif f.severity == "warning":
                f.severity = "critical"
        severity_vals = [_SEV_RANK.get(f.severity, 0) for f in findings]
        for s, r in _SEV_RANK.items():
            if r == max(severity_vals):
                severity = s
                break

    return FilenameScanResult(
        filename=filename,
        dangerous=len(findings) > 0,
        severity=severity,
        findings=findings,
    )


class ProtectedPathSet:
    """A set of glob/path patterns that are considered immutable.

    Supports:
    - Exact relative paths: ``src/config/secrets.yaml``
    - Basename matches: ``.env`` matches any ``.env`` anywhere
    - Folder globs: ``src/config/**`` matches everything inside
    - Extension globs: ``*.pem`` matches any ``.pem`` file
    - Folder prefixes: ``certs/`` matches anything under ``certs/``

    Usage::

        paths = ProtectedPathSet([".env", "src/config/**", "*.pem"])
        paths.is_protected("src/config/db.yaml")  # True
        paths.is_protected(".env")  # True
        paths.is_protected("cert.pem")  # True
        paths.is_protected("README.md")  # False

        paths.add("id_rsa")
        paths.remove("*.pem")
    """

    def __init__(self, patterns: Optional[List[str]] = None):
        self._patterns: List[str] = list(patterns or [])

    @property
    def patterns(self) -> List[str]:
        return list(self._patterns)

    def add(self, pattern: str) -> None:
        if pattern not in self._patterns:
            self._patterns.append(pattern)

    def remove(self, pattern: str) -> None:
        self._patterns = [p for p in self._patterns if p != pattern]

    def clear(self) -> None:
        self._patterns.clear()

    def __len__(self) -> int:
        return len(self._patterns)

    def __bool__(self) -> bool:
        return len(self._patterns) > 0

    def is_protected(self, filepath: str) -> bool:
        """Check if a file path matches any protected pattern."""
        if not self._patterns:
            return False

        # Normalize to forward slashes
        normalized = filepath.replace("\\", "/")
        basename = os.path.basename(filepath)

        for pattern in self._patterns:
            # Exact path match
            if normalized == pattern or filepath == pattern:
                return True
            # Basename match (e.g. ".env" matches any .env)
            if basename == pattern:
                return True
            # Folder glob: pattern/** matches anything inside
            if pattern.endswith("/**"):
                prefix = pattern[:-3]
                if normalized.startswith(prefix + "/") or normalized == prefix:
                    return True
            # Extension glob: *.ext
            if pattern.startswith("*.") and basename.endswith(pattern[1:]):
                return True
            # Folder prefix: pattern/ matches anything under it
            if pattern.endswith("/"):
                if normalized.startswith(pattern) or normalized + "/" == pattern:
                    return True

        return False
