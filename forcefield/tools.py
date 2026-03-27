"""Tool call security evaluation -- block dangerous tools, detect destructive actions.

Extracted from gcp/cloudrun/testing_gateway.py and
services/edge-proxy/app/tool_call_interceptor.py (production gateway).

Zero external dependencies (stdlib only).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

from .config import BLOCKED_TOOLS, DESTRUCTIVE_TOOL_PATTERNS
from .types import ToolAction, ToolEvalResult, ToolGovernorResult


# Secret/credential patterns for tool argument inspection
_SECRET_PATTERNS = {
    'api_key': re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*[\'"]?[A-Za-z0-9_-]{20,}[\'"]?'),
    'bearer_token': re.compile(r'(?i)bearer\s+[A-Za-z0-9_-]{20,}'),
    'openai_key': re.compile(r'sk-[A-Za-z0-9]{20,}'),
    'anthropic_key': re.compile(r'sk-ant-[A-Za-z0-9-]{20,}'),
    'private_key': re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    'password': re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"]?[^\s\'"]{8,}[\'"]?'),
    'secret': re.compile(r'(?i)(secret|token)\s*[:=]\s*[\'"]?[A-Za-z0-9_-]{20,}[\'"]?'),
}

_INJECTION_IN_ARGS = [
    re.compile(r'(?:ignore|disregard|forget)\s+(?:previous|prior|all|above)\s+(?:instructions?|rules?)', re.IGNORECASE),
    re.compile(r'you are now\s+(?:DAN|in developer mode|jailbroken)', re.IGNORECASE),
    re.compile(r'(?:new|updated?)\s+(?:system\s+)?instructions?:', re.IGNORECASE),
]


def evaluate_tool(
    tool_name: str,
    *,
    blocked_tools: Optional[Set[str]] = None,
    block_dangerous: bool = True,
) -> ToolEvalResult:
    """Evaluate whether a tool call should be allowed.

    Args:
        tool_name: Name of the tool being invoked.
        blocked_tools: Extra tool names to block (merged with defaults).
        block_dangerous: Whether to block destructive tool patterns.

    Returns:
        ``ToolEvalResult`` with allowed/denied status and reason.
    """
    name_lower = tool_name.lower()
    all_blocked = BLOCKED_TOOLS | (blocked_tools or set())

    if any(b in name_lower for b in all_blocked):
        return ToolEvalResult(allowed=False, reason="tool_blocked", tool_name=tool_name)

    if block_dangerous:
        if any(p in name_lower for p in DESTRUCTIVE_TOOL_PATTERNS):
            return ToolEvalResult(allowed=False, reason="requires_human_approval", tool_name=tool_name)

    return ToolEvalResult(allowed=True, reason="tool_permitted", tool_name=tool_name)


def inspect_tool_args(arguments: str) -> Dict[str, List[str]]:
    """Inspect tool call arguments for secrets, PII, or injection attempts.

    Returns a dict with keys ``secrets``, ``injection`` listing matched pattern names.
    """
    findings: Dict[str, List[str]] = {"secrets": [], "injection": []}

    for name, pat in _SECRET_PATTERNS.items():
        if pat.search(arguments):
            findings["secrets"].append(name)

    for pat in _INJECTION_IN_ARGS:
        if pat.search(arguments):
            findings["injection"].append(pat.pattern[:40])

    return findings


# ---------------------------------------------------------------------------
# Tool result inspection (Phase 4 expansion)
# ---------------------------------------------------------------------------

_PII_IN_RESULT = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}"),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
}


def inspect_tool_result(result_text: str) -> Dict[str, List[str]]:
    """Inspect tool call output for secrets, PII, or injection.

    Returns a dict with keys ``secrets``, ``pii``, ``injection``.
    """
    findings: Dict[str, List[str]] = {"secrets": [], "pii": [], "injection": []}

    for name, pat in _SECRET_PATTERNS.items():
        if pat.search(result_text):
            findings["secrets"].append(name)

    for name, pat in _PII_IN_RESULT.items():
        if pat.search(result_text):
            findings["pii"].append(name)

    for pat in _INJECTION_IN_ARGS:
        if pat.search(result_text):
            findings["injection"].append(pat.pattern[:40])

    return findings


# ---------------------------------------------------------------------------
# ToolGovernor (Phase 4 expansion)
# ---------------------------------------------------------------------------

class ToolGovernor:
    """Policy-driven tool governance with pre-call and post-call inspection.

    Args:
        policies: Mapping of tool name (or substring) to ``ToolAction``.
            If a tool name matches multiple policies, the most restrictive wins.
        block_dangerous: Whether to block tools matching destructive patterns.
        inspect_results: Whether ``after_call`` inspects tool output.
    """

    def __init__(
        self,
        policies: Optional[Dict[str, ToolAction]] = None,
        *,
        block_dangerous: bool = True,
        inspect_results: bool = True,
    ) -> None:
        self._policies = policies or {}
        self._block_dangerous = block_dangerous
        self._inspect_results = inspect_results

    def before_call(
        self,
        tool_name: str,
        arguments: Optional[str] = None,
    ) -> ToolGovernorResult:
        """Evaluate a tool call *before* execution.

        Checks the tool against configured policies, the default blocklist,
        destructive-pattern list, and optionally inspects arguments for
        secrets / injection.
        """
        name_lower = tool_name.lower()

        # Check explicit policies first
        for pattern, action in self._policies.items():
            if pattern.lower() in name_lower:
                if action == ToolAction.BLOCK:
                    return ToolGovernorResult(
                        allowed=False, action=ToolAction.BLOCK,
                        reason="tool_blocked_by_policy", tool_name=tool_name,
                    )
                if action == ToolAction.REQUIRE_APPROVAL:
                    return ToolGovernorResult(
                        allowed=False, action=ToolAction.REQUIRE_APPROVAL,
                        reason="requires_human_approval", tool_name=tool_name,
                    )

        # Default blocklist
        if any(b in name_lower for b in BLOCKED_TOOLS):
            return ToolGovernorResult(
                allowed=False, action=ToolAction.BLOCK,
                reason="tool_blocked", tool_name=tool_name,
            )

        # Destructive patterns
        if self._block_dangerous and any(p in name_lower for p in DESTRUCTIVE_TOOL_PATTERNS):
            return ToolGovernorResult(
                allowed=False, action=ToolAction.REQUIRE_APPROVAL,
                reason="requires_human_approval", tool_name=tool_name,
            )

        # Argument inspection
        findings: Dict = {}
        if arguments:
            findings = inspect_tool_args(arguments)
            if findings.get("injection"):
                return ToolGovernorResult(
                    allowed=False, action=ToolAction.BLOCK,
                    reason="injection_in_arguments", tool_name=tool_name,
                    findings=findings,
                )
            if findings.get("secrets"):
                return ToolGovernorResult(
                    allowed=False, action=ToolAction.BLOCK,
                    reason="secrets_in_arguments", tool_name=tool_name,
                    findings=findings,
                )

        return ToolGovernorResult(
            allowed=True, action=ToolAction.ALLOW,
            reason="tool_permitted", tool_name=tool_name,
            findings=findings,
        )

    def after_call(
        self,
        tool_name: str,
        result_text: str,
    ) -> ToolGovernorResult:
        """Inspect a tool call result *after* execution.

        Looks for leaked secrets, PII, and injection payloads in the output.
        """
        if not self._inspect_results:
            return ToolGovernorResult(
                allowed=True, action=ToolAction.ALLOW,
                reason="inspection_skipped", tool_name=tool_name,
            )

        findings = inspect_tool_result(result_text)
        has_issue = any(findings.get(k) for k in ("secrets", "pii", "injection"))

        if findings.get("injection"):
            return ToolGovernorResult(
                allowed=False, action=ToolAction.BLOCK,
                reason="injection_in_result", tool_name=tool_name,
                findings=findings,
            )

        if findings.get("secrets") or findings.get("pii"):
            return ToolGovernorResult(
                allowed=False, action=ToolAction.BLOCK,
                reason="sensitive_data_in_result", tool_name=tool_name,
                findings=findings,
            )

        return ToolGovernorResult(
            allowed=True, action=ToolAction.ALLOW,
            reason="result_clean", tool_name=tool_name,
        )
