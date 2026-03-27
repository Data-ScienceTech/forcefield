"""Configuration and sensitivity thresholds for the ForceField SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


SENSITIVITY_ML_THRESHOLDS = {
    "low": 0.85,
    "medium": 0.60,
    "high": 0.45,
    "critical": 0.30,
}

SENSITIVITY_BLOCK_THRESHOLDS = {
    "low": 0.75,
    "medium": 0.50,
    "high": 0.35,
    "critical": 0.20,
}

BLOCKED_TOOLS = frozenset({"exec", "shell", "eval", "system", "rm", "format"})
DESTRUCTIVE_TOOL_PATTERNS = ["write", "delete", "remove", "send", "exec", "shell", "post"]


@dataclass
class GuardConfig:
    """Configuration for the ForceField Guard."""
    sensitivity: str = "medium"
    block_on_injection: bool = True
    block_on_pii: bool = False
    block_dangerous_tools: bool = True
    custom_blocked_patterns: List[str] = field(default_factory=list)
    max_prompt_tokens: int = 4096
    redaction_strategy: str = "mask"
    enable_obfuscation_detection: bool = True
    enable_session_tracking: bool = False

    @property
    def ml_threshold(self) -> float:
        return SENSITIVITY_ML_THRESHOLDS.get(self.sensitivity, 0.60)

    @property
    def block_threshold(self) -> float:
        return SENSITIVITY_BLOCK_THRESHOLDS.get(self.sensitivity, 0.50)
