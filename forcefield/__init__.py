"""ForceField -- Lightweight AI security scanner for Python.

Detect prompt injection, PII leaks, and LLM attacks in 3 lines::

    import forcefield

    guard = forcefield.Guard()
    result = guard.scan("Ignore all previous instructions")
    # result.blocked == True
"""

from __future__ import annotations

__version__ = "0.3.0"

from .guard import Guard
from .types import (
    Action,
    ModerationResult,
    PIIMatch,
    PIIType,
    RedactResult,
    RedactionStrategy,
    ScanResult,
    SelftestResult,
    Severity,
    Threat,
    ThreatCategory,
    ToolEvalResult,
)
from .config import GuardConfig
from .session import SessionTracker
from .integrity import CanaryTokenManager, PromptSigner, PromptIntegrityGuard, IntegrityCheckResult
from .templates import TemplateValidationResult

__all__ = [
    "Guard",
    "GuardConfig",
    "Action",
    "ModerationResult",
    "PIIMatch",
    "PIIType",
    "RedactResult",
    "RedactionStrategy",
    "ScanResult",
    "SelftestResult",
    "Severity",
    "Threat",
    "ThreatCategory",
    "ToolEvalResult",
    "SessionTracker",
    "CanaryTokenManager",
    "PromptSigner",
    "PromptIntegrityGuard",
    "IntegrityCheckResult",
    "TemplateValidationResult",
    "__version__",
]
