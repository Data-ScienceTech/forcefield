"""Constitution-driven governance engine for ForceField Sentinel.

A constitution is a YAML (or dict) document that declares the rules governing
what AI agents can and cannot do inside a workspace.  The ``PolicyEngine``
evaluates file, command, tool, and content events against the loaded
constitution and returns a ``PolicyVerdict``.

Usage::

    from forcefield.constitution import Constitution, PolicyEngine

    const = Constitution.from_file(".forcefield/constitution.yaml")
    engine = PolicyEngine(const)

    verdict = engine.evaluate_file("src/config/secrets.yaml", "delete")
    # verdict.allowed == False, verdict.action == PolicyAction.BLOCK

If no constitution is loaded the engine falls back to the hardcoded patterns
already shipped in ``forcefield.commands`` and ``forcefield.files``, so
existing Sentinel behaviour is fully preserved.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .types import PolicyAction, PolicyVerdict


# ---------------------------------------------------------------------------
# Constitution data model
# ---------------------------------------------------------------------------


@dataclass
class ConstitutionRule:
    """A single rule inside a constitution domain (files/commands/tools)."""
    pattern: str
    action: PolicyAction
    reason: str = ""
    operations: List[str] = field(default_factory=list)
    _compiled: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        except re.error:
            self._compiled = None

    def matches_regex(self, text: str) -> bool:
        if self._compiled is not None:
            return bool(self._compiled.search(text))
        return False

    def matches_glob(self, filepath: str) -> bool:
        normalized = filepath.replace("\\", "/")
        basename = os.path.basename(normalized)
        pat = self.pattern.replace("\\", "/")
        if fnmatch.fnmatch(normalized, pat):
            return True
        if fnmatch.fnmatch(basename, pat):
            return True
        if pat.endswith("/**") and (
            normalized.startswith(pat[:-3] + "/") or normalized == pat[:-3]
        ):
            return True
        if pat.endswith("/") and normalized.startswith(pat):
            return True
        return False


@dataclass
class ScopeConfig:
    """Defines where agents are allowed to operate."""
    allowed_paths: List[str] = field(default_factory=list)
    denied_paths: List[str] = field(default_factory=list)
    allowed_languages: List[str] = field(default_factory=list)


@dataclass
class ContentConfig:
    """Content-level policies."""
    block_pii: bool = True
    block_secrets: bool = True
    moderation: bool = True
    max_risk_score: float = 0.7


@dataclass
class DefaultsConfig:
    """Global defaults for the constitution."""
    protection_level: str = "confirm"
    sensitivity: str = "medium"
    auto_kill_critical: bool = True


class Constitution:
    """A loaded governance constitution.

    Can be built from a Python dict or loaded from a YAML file.
    """

    def __init__(self, data: Dict[str, Any]) -> None:
        self._raw = data
        self.version: str = str(data.get("version", "1"))
        self.name: str = data.get("name", "Default Constitution")

        # Defaults
        d = data.get("defaults", {})
        self.defaults = DefaultsConfig(
            protection_level=d.get("protection_level", "confirm"),
            sensitivity=d.get("sensitivity", "medium"),
            auto_kill_critical=d.get("auto_kill_critical", True),
        )

        # Scope
        s = data.get("scope", {})
        self.scope = ScopeConfig(
            allowed_paths=s.get("allowed_paths", []),
            denied_paths=s.get("denied_paths", []),
            allowed_languages=s.get("allowed_languages", []),
        )

        # Content
        c = data.get("content", {})
        self.content = ContentConfig(
            block_pii=c.get("block_pii", True),
            block_secrets=c.get("block_secrets", True),
            moderation=c.get("moderation", True),
            max_risk_score=float(c.get("max_risk_score", 0.7)),
        )

        # Domain rules
        self.file_rules = _parse_rules(data.get("files", []))
        self.command_rules = _parse_rules(data.get("commands", []))
        self.tool_rules = _parse_tool_rules(data.get("tools", []))

    # -- Constructors --------------------------------------------------------

    @classmethod
    def from_file(cls, path: str) -> "Constitution":
        """Load a constitution from a YAML file.

        Falls back to plain JSON if PyYAML is not installed.
        """
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()

        try:
            import yaml  # type: ignore
            data = yaml.safe_load(raw)
        except ImportError:
            import json
            data = json.loads(raw)

        if not isinstance(data, dict):
            raise ValueError(f"Constitution file must be a YAML/JSON mapping, got {type(data).__name__}")
        return cls(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Constitution":
        return cls(data)

    # -- Validation ----------------------------------------------------------

    def validate(self) -> List[str]:
        """Return a list of validation errors (empty == valid)."""
        errors: List[str] = []
        if self.version not in ("1",):
            errors.append(f"Unsupported constitution version: {self.version}")
        if self.defaults.protection_level not in ("monitor", "confirm", "strict"):
            errors.append(f"Invalid protection_level: {self.defaults.protection_level}")
        if self.defaults.sensitivity not in ("low", "medium", "high", "critical"):
            errors.append(f"Invalid sensitivity: {self.defaults.sensitivity}")
        for i, rule in enumerate(self.file_rules):
            if rule._compiled is None and not any(
                c in rule.pattern for c in ("*", "?", "/")
            ):
                errors.append(f"files[{i}]: invalid regex pattern: {rule.pattern}")
        for i, rule in enumerate(self.command_rules):
            if rule._compiled is None:
                errors.append(f"commands[{i}]: invalid regex pattern: {rule.pattern}")
        return errors

    # -- Serialisation -------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return self._raw

    def __repr__(self) -> str:
        return (
            f"Constitution(name={self.name!r}, version={self.version!r}, "
            f"file_rules={len(self.file_rules)}, command_rules={len(self.command_rules)}, "
            f"tool_rules={len(self.tool_rules)})"
        )


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Evaluates events against a constitution.

    If no constitution is provided, the engine uses the hardcoded patterns
    from ``forcefield.commands`` and ``forcefield.files`` as a fallback so
    that existing Sentinel behaviour is preserved.
    """

    def __init__(self, constitution: Optional[Constitution] = None) -> None:
        self._constitution = constitution

    @property
    def constitution(self) -> Optional[Constitution]:
        return self._constitution

    @constitution.setter
    def constitution(self, value: Optional[Constitution]) -> None:
        self._constitution = value

    @property
    def has_constitution(self) -> bool:
        return self._constitution is not None

    # -- File evaluation -----------------------------------------------------

    def evaluate_file(
        self,
        filepath: str,
        operation: str = "create",
    ) -> PolicyVerdict:
        """Evaluate a file event against the constitution.

        Args:
            filepath: Relative or absolute file path.
            operation: One of ``create``, ``delete``, ``rename``, ``modify``.
        """
        # Constitution rules
        if self._constitution is not None:
            # Scope check first
            scope_v = self._check_scope(filepath)
            if scope_v is not None:
                return scope_v

            for rule in self._constitution.file_rules:
                if rule.operations and operation not in rule.operations:
                    continue
                if rule.matches_glob(filepath):
                    allowed = rule.action in (PolicyAction.ALLOW, PolicyAction.LOG)
                    return PolicyVerdict(
                        allowed=allowed,
                        action=rule.action,
                        rule_matched=rule.pattern,
                        reason=rule.reason or f"Matched file rule: {rule.pattern}",
                        domain="files",
                        target=filepath,
                    )

            # No rule matched -- use default protection level
            return self._default_file_verdict(filepath, operation)

        # Fallback: use hardcoded SDK patterns
        return self._fallback_file(filepath, operation)

    # -- Command evaluation --------------------------------------------------

    def evaluate_command(self, command: str) -> PolicyVerdict:
        """Evaluate a terminal command against the constitution."""
        if self._constitution is not None:
            for rule in self._constitution.command_rules:
                if rule.matches_regex(command):
                    allowed = rule.action in (PolicyAction.ALLOW, PolicyAction.LOG)
                    return PolicyVerdict(
                        allowed=allowed,
                        action=rule.action,
                        rule_matched=rule.pattern,
                        reason=rule.reason or f"Matched command rule: {rule.pattern}",
                        domain="commands",
                        target=command,
                    )
            # No rule matched -- allow by default
            return PolicyVerdict(
                allowed=True,
                action=PolicyAction.ALLOW,
                reason="No command rule matched",
                domain="commands",
                target=command,
            )

        # Fallback: hardcoded patterns
        return self._fallback_command(command)

    # -- Tool evaluation -----------------------------------------------------

    def evaluate_tool(
        self,
        tool_name: str,
        arguments: Optional[str] = None,
    ) -> PolicyVerdict:
        """Evaluate a tool call against the constitution."""
        if self._constitution is not None:
            name_lower = tool_name.lower()
            for rule in self._constitution.tool_rules:
                if rule.pattern.lower() in name_lower or rule.matches_regex(tool_name):
                    allowed = rule.action in (PolicyAction.ALLOW, PolicyAction.LOG)
                    return PolicyVerdict(
                        allowed=allowed,
                        action=rule.action,
                        rule_matched=rule.pattern,
                        reason=rule.reason or f"Matched tool rule: {rule.pattern}",
                        domain="tools",
                        target=tool_name,
                    )
            return PolicyVerdict(
                allowed=True,
                action=PolicyAction.ALLOW,
                reason="No tool rule matched",
                domain="tools",
                target=tool_name,
            )

        # Fallback: hardcoded tool blocklist
        return self._fallback_tool(tool_name)

    # -- Content evaluation --------------------------------------------------

    def evaluate_content(self, risk_score: float, has_pii: bool = False, has_secrets: bool = False) -> PolicyVerdict:
        """Evaluate content scan results against the constitution's content policies."""
        if self._constitution is not None:
            cc = self._constitution.content
            if has_secrets and cc.block_secrets:
                return PolicyVerdict(
                    allowed=False, action=PolicyAction.BLOCK,
                    reason="Secrets detected (constitution: content.block_secrets)",
                    domain="content", target="secrets",
                )
            if has_pii and cc.block_pii:
                return PolicyVerdict(
                    allowed=False, action=PolicyAction.BLOCK,
                    reason="PII detected (constitution: content.block_pii)",
                    domain="content", target="pii",
                )
            if risk_score > cc.max_risk_score:
                return PolicyVerdict(
                    allowed=False, action=PolicyAction.BLOCK,
                    reason=f"Risk score {risk_score:.2f} exceeds threshold {cc.max_risk_score}",
                    domain="content", target="risk_score",
                )
            return PolicyVerdict(
                allowed=True, action=PolicyAction.ALLOW,
                reason="Content passes all policies",
                domain="content", target="",
            )

        # Fallback: allow (existing Sentinel doesn't have content policies)
        return PolicyVerdict(
            allowed=True, action=PolicyAction.ALLOW,
            reason="No constitution loaded", domain="content", target="",
        )

    # -- Scope check ---------------------------------------------------------

    def _check_scope(self, filepath: str) -> Optional[PolicyVerdict]:
        """Check if a file is within the allowed scope."""
        if self._constitution is None:
            return None
        scope = self._constitution.scope
        normalized = filepath.replace("\\", "/")
        basename = os.path.basename(normalized)

        # Denied paths (checked first, takes priority)
        for pattern in scope.denied_paths:
            if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(basename, pattern):
                return PolicyVerdict(
                    allowed=False, action=PolicyAction.BLOCK,
                    rule_matched=pattern,
                    reason=f"Path in denied scope: {pattern}",
                    domain="scope", target=filepath,
                )

        # Allowed paths (if specified, everything else is denied)
        if scope.allowed_paths:
            for pattern in scope.allowed_paths:
                if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(basename, pattern):
                    return None  # Within scope, continue to rule evaluation
            return PolicyVerdict(
                allowed=False, action=PolicyAction.BLOCK,
                reason="Path outside allowed scope",
                domain="scope", target=filepath,
            )

        return None  # No scope restrictions

    # -- Default verdict (constitution loaded but no rule matched) -----------

    def _default_file_verdict(self, filepath: str, operation: str) -> PolicyVerdict:
        """Apply the default protection level when no file rule matched."""
        level = self._constitution.defaults.protection_level if self._constitution else "monitor"
        if level == "strict" and operation in ("create", "delete", "rename", "modify"):
            return PolicyVerdict(
                allowed=False, action=PolicyAction.CONFIRM,
                reason=f"Default strict protection: {operation} requires confirmation",
                domain="files", target=filepath,
            )
        if level == "confirm" and operation in ("delete", "rename"):
            return PolicyVerdict(
                allowed=False, action=PolicyAction.CONFIRM,
                reason=f"Default confirm protection: {operation} requires confirmation",
                domain="files", target=filepath,
            )
        return PolicyVerdict(
            allowed=True, action=PolicyAction.ALLOW,
            reason="No file rule matched, default allows",
            domain="files", target=filepath,
        )

    # -- Fallbacks (no constitution loaded) ----------------------------------

    @staticmethod
    def _fallback_file(filepath: str, operation: str) -> PolicyVerdict:
        """Use hardcoded SDK file patterns when no constitution is loaded."""
        from .files import scan_filename
        result = scan_filename(filepath, operation=operation)
        if result.dangerous:
            sev = result.severity
            action = PolicyAction.BLOCK if sev == "critical" else PolicyAction.CONFIRM
            desc = "; ".join(f.description for f in result.findings)
            return PolicyVerdict(
                allowed=False, action=action,
                rule_matched=result.findings[0].code if result.findings else None,
                reason=desc,
                domain="files", target=filepath,
            )
        return PolicyVerdict(
            allowed=True, action=PolicyAction.ALLOW,
            reason="No dangerous file pattern matched",
            domain="files", target=filepath,
        )

    @staticmethod
    def _fallback_command(command: str) -> PolicyVerdict:
        """Use hardcoded SDK command patterns when no constitution is loaded."""
        from .commands import scan_command
        result = scan_command(command)
        if result.dangerous:
            sev = result.severity
            action = PolicyAction.BLOCK if sev == "critical" else PolicyAction.CONFIRM
            desc = "; ".join(f.description for f in result.findings)
            return PolicyVerdict(
                allowed=False, action=action,
                rule_matched=result.findings[0].code if result.findings else None,
                reason=desc,
                domain="commands", target=command,
            )
        return PolicyVerdict(
            allowed=True, action=PolicyAction.ALLOW,
            reason="No dangerous command pattern matched",
            domain="commands", target=command,
        )

    @staticmethod
    def _fallback_tool(tool_name: str) -> PolicyVerdict:
        """Use hardcoded SDK tool blocklist when no constitution is loaded."""
        from .tools import evaluate_tool
        result = evaluate_tool(tool_name)
        if not result.allowed:
            return PolicyVerdict(
                allowed=False, action=PolicyAction.BLOCK,
                rule_matched=tool_name,
                reason=result.reason,
                domain="tools", target=tool_name,
            )
        return PolicyVerdict(
            allowed=True, action=PolicyAction.ALLOW,
            reason="Tool permitted",
            domain="tools", target=tool_name,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_action(raw: str) -> PolicyAction:
    """Parse a string action into a PolicyAction enum."""
    mapping = {
        "allow": PolicyAction.ALLOW,
        "block": PolicyAction.BLOCK,
        "confirm": PolicyAction.CONFIRM,
        "log": PolicyAction.LOG,
    }
    return mapping.get(raw.lower(), PolicyAction.LOG)


def _parse_rules(raw_list: List[Dict[str, Any]]) -> List[ConstitutionRule]:
    """Parse a list of rule dicts into ConstitutionRule objects."""
    rules: List[ConstitutionRule] = []
    for entry in raw_list:
        if not isinstance(entry, dict):
            continue
        pattern = entry.get("pattern", "")
        if not pattern:
            continue
        rules.append(ConstitutionRule(
            pattern=pattern,
            action=_parse_action(entry.get("action", "log")),
            reason=entry.get("reason", ""),
            operations=entry.get("operations", []),
        ))
    return rules


def _parse_tool_rules(raw_list: List[Dict[str, Any]]) -> List[ConstitutionRule]:
    """Parse tool rules (use 'name' key instead of 'pattern')."""
    rules: List[ConstitutionRule] = []
    for entry in raw_list:
        if not isinstance(entry, dict):
            continue
        pattern = entry.get("name", entry.get("pattern", ""))
        if not pattern:
            continue
        rules.append(ConstitutionRule(
            pattern=pattern,
            action=_parse_action(entry.get("action", "log")),
            reason=entry.get("reason", ""),
        ))
    return rules
