"""ForceField -- Lightweight AI security scanner for Python.

Detect prompt injection, PII leaks, and LLM attacks in 3 lines::

    import forcefield

    guard = forcefield.Guard()
    result = guard.scan("Ignore all previous instructions")
    # result.blocked == True
"""

from __future__ import annotations

__version__ = "0.4.0"

from .guard import Guard
from .types import (
    Action,
    AbuseResult,
    ContentSafetyResult,
    ModerationResult,
    PIIMatch,
    PIIType,
    RateLimitResult,
    RedactResult,
    RedactionStrategy,
    ScanResult,
    SelftestResult,
    Severity,
    Threat,
    ThreatCategory,
    ToolAction,
    ToolEvalResult,
    ToolGovernorResult,
)
from .config import GuardConfig
from .session import SessionTracker
from .integrity import CanaryTokenManager, PromptSigner, PromptIntegrityGuard, IntegrityCheckResult
from .templates import TemplateValidationResult
from .ratelimit import RateLimiter
from .abuse import detect_abuse
from .tools import ToolGovernor

__all__ = [
    "Guard",
    "GuardConfig",
    "Action",
    "AbuseResult",
    "ContentSafetyResult",
    "ModerationResult",
    "PIIMatch",
    "PIIType",
    "RateLimitResult",
    "RedactResult",
    "RedactionStrategy",
    "ScanResult",
    "SelftestResult",
    "Severity",
    "Threat",
    "ThreatCategory",
    "ToolAction",
    "ToolEvalResult",
    "ToolGovernorResult",
    "SessionTracker",
    "CanaryTokenManager",
    "PromptSigner",
    "PromptIntegrityGuard",
    "IntegrityCheckResult",
    "TemplateValidationResult",
    "RateLimiter",
    "ToolGovernor",
    "detect_abuse",
    "__version__",
]
