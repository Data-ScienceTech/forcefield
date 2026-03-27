"""Tool call security evaluation -- block dangerous tools, detect destructive actions.

Extracted from gcp/cloudrun/testing_gateway.py and
services/edge-proxy/app/tool_call_interceptor.py (production gateway).

Zero external dependencies (stdlib only).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

from .config import BLOCKED_TOOLS, DESTRUCTIVE_TOOL_PATTERNS
from .types import ToolEvalResult


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
