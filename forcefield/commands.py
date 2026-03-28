"""Terminal command security scanning -- detect dangerous shell commands.

Zero external dependencies (stdlib only).

Usage::

    from forcefield.commands import scan_command

    result = scan_command("rm -rf /")
    # result.dangerous == True
    # result.severity == "critical"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .types import ToolEvalResult


@dataclass
class CommandFinding:
    """A single dangerous pattern match in a command."""
    code: str
    severity: str
    description: str


@dataclass
class CommandScanResult:
    """Result of scanning a terminal command."""
    command: str
    dangerous: bool
    severity: str
    findings: List[CommandFinding] = field(default_factory=list)
    tool_eval: Optional[ToolEvalResult] = None

    def to_dict(self) -> Dict:
        return {
            "command": self.command,
            "dangerous": self.dangerous,
            "severity": self.severity,
            "findings": [
                {"code": f.code, "severity": f.severity, "description": f.description}
                for f in self.findings
            ],
            "tool_eval": (
                {"allowed": self.tool_eval.allowed, "reason": self.tool_eval.reason, "tool_name": self.tool_eval.tool_name}
                if self.tool_eval else None
            ),
        }


_SEV_RANK: Dict[str, int] = {"info": 0, "warning": 1, "critical": 2}

DANGEROUS_COMMAND_PATTERNS = [
    (r"\brm\s+(-[a-z]*r[a-z]*\s+|--recursive)", "recursive_delete", "critical", "Recursive file deletion"),
    (r"\brm\s+-[a-z]*f", "force_delete", "warning", "Forced file deletion"),
    (r"\bchmod\s+777\b", "chmod_world_writable", "critical", "World-writable permissions"),
    (r"\bchmod\s+\+[sx]", "chmod_setuid", "warning", "Setuid/setgid permission change"),
    (r"curl\s+.*\|\s*(sh|bash|zsh|python)", "pipe_to_shell", "critical", "Piping remote content to shell"),
    (r"wget\s+.*\|\s*(sh|bash|zsh|python)", "pipe_to_shell", "critical", "Piping remote content to shell"),
    (r"curl\s+.*(-d|--data).*\$\{?\.?\w*(KEY|SECRET|TOKEN|PASS|CRED)", "credential_exfil", "critical", "Possible credential exfiltration via curl"),
    (r"\beval\s*\(", "eval_exec", "warning", "Dynamic code evaluation"),
    (r"\bexec\s*\(", "eval_exec", "warning", "Dynamic code execution"),
    (r"\bnc\s+-[a-z]*l", "reverse_shell", "critical", "Netcat listener (possible reverse shell)"),
    (r"/dev/tcp/", "reverse_shell", "critical", "Bash /dev/tcp reverse shell pattern"),
    (r"\bbase64\s+(-d|--decode)", "base64_decode", "warning", "Base64 decode (possible obfuscation)"),
    (r"\bdd\s+.*of=/dev/", "disk_write", "critical", "Direct disk write with dd"),
    (r"\bmkfs\b", "disk_format", "critical", "Filesystem format command"),
    (r"\b(useradd|adduser|passwd)\b", "user_management", "warning", "User account modification"),
    (r"\bsudo\s", "privilege_escalation", "warning", "Privilege escalation via sudo"),
    (r"\bsu\s+-?\s*$|\bsu\s+root", "privilege_escalation", "warning", "Switching to root user"),
    (r"\bcrontab\b", "persistence", "warning", "Crontab modification (possible persistence)"),
    (r"\bsystemctl\s+(enable|start|restart)", "service_management", "info", "System service management"),
    (r">\s*/etc/", "etc_overwrite", "critical", "Overwriting system config in /etc"),
    (r"\biptables\b|\bufw\b", "firewall_change", "warning", "Firewall rule modification"),
    (r"\bgit\s+push\s+.*--force", "force_push", "warning", "Force push to git remote"),
    (r"npm\s+install\s+.*--global|pip\s+install(?!.*forcefield)", "global_install", "info", "Global package installation"),
]

# Pre-compile for performance
_COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), code, sev, desc)
    for pattern, code, sev, desc in DANGEROUS_COMMAND_PATTERNS
]


def scan_command(
    command: str,
    *,
    tool_eval_func=None,
) -> CommandScanResult:
    """Scan a terminal command for dangerous patterns.

    Args:
        command: The shell command string to scan.
        tool_eval_func: Optional callable(tool_name) -> ToolEvalResult
            for tool governance integration.

    Returns:
        ``CommandScanResult`` with findings and severity.
    """
    findings: List[CommandFinding] = []
    severity = "info"

    for compiled, code, sev, desc in _COMPILED_PATTERNS:
        if compiled.search(command):
            findings.append(CommandFinding(code=code, severity=sev, description=desc))
            if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(severity, 0):
                severity = sev

    tool_eval = None
    if tool_eval_func is not None:
        cmd_lower = command.lower().strip()
        first_word = cmd_lower.split()[0] if cmd_lower else ""
        if first_word:
            try:
                r = tool_eval_func(first_word)
                if not r.allowed:
                    tool_eval = r
                    if severity == "info":
                        severity = "warning"
            except Exception:
                pass

    return CommandScanResult(
        command=command,
        dangerous=len(findings) > 0 or (tool_eval is not None and not tool_eval.allowed),
        severity=severity,
        findings=findings,
        tool_eval=tool_eval,
    )
