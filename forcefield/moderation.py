"""Output content moderation -- detect harmful LLM output categories.

Extracted from services/common/output_moderation.py (production gateway).
Zero external dependencies (stdlib only).

Categories: hate speech, violence, self-harm, illegal activity, dangerous info,
malware code, credential leak, jailbreak success, persona deviation, sexual content.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .types import Action, ModerationResult, ContentSafetyResult


# ---------------------------------------------------------------------------
# Content categories
# ---------------------------------------------------------------------------

CONTENT_PATTERNS: Dict[str, Dict] = {
    "hate_speech": {
        "patterns": [
            r"\b(hate|despise|eliminate)\s+(all\s+)?(jews?|muslims?|blacks?|whites?|gays?|trans)",
            r"\b(inferior|subhuman|vermin)\s+(race|people|group)",
            r"\b(ethnic\s+)?cleansing\b",
            r"\b(genocide|holocaust)\s+(is|was)\s+(good|justified|necessary)",
        ],
        "severity": 0.95,
    },
    "violence": {
        "patterns": [
            r"\bhow\s+to\s+(kill|murder|assassinate)\s+",
            r"\b(detailed\s+)?(instructions?|steps?)\s+(to|for)\s+(make|build|create)\s+(a\s+)?(bomb|weapon|explosive)",
            r"\b(attack|hurt|harm)\s+(school|church|mosque|synagogue|crowd)",
            r"\bterrorist\s+(attack|plot|plan)\s+(instructions?|details?)",
        ],
        "severity": 0.95,
    },
    "self_harm": {
        "patterns": [
            r"\b(how\s+to\s+)?(commit\s+)?suicide\s+(method|way|instruction)",
            r"\bself[- ]?harm\s+(technique|method|instruction)",
            r"\b(cut|hurt)\s+yourself\s+(to|for)",
            r"\bending\s+(your|one's)\s+life",
        ],
        "severity": 0.98,
    },
    "illegal_activity": {
        "patterns": [
            r"\bhow\s+to\s+(hack|break\s+into|exploit)\s+(a\s+)?(system|network|account)",
            r"\b(credit\s+card|identity)\s+(fraud|theft|scam)\s+(tutorial|guide|how)",
            r"\b(drug|meth|cocaine)\s+(synthesis|manufacturing|production)\s+(process|steps)",
            r"\bmoney\s+laundering\s+(technique|method|scheme)",
        ],
        "severity": 0.90,
    },
    "dangerous_info": {
        "patterns": [
            r"\b(ricin|anthrax|sarin|nerve\s+agent)\s+(production|synthesis|how\s+to)",
            r"\b(bioweapon|chemical\s+weapon)\s+(recipe|instructions?|guide)",
            r"\bpoison\s+(dosage|lethal\s+amount|how\s+to\s+make)",
        ],
        "severity": 0.98,
    },
    "malware_code": {
        "patterns": [
            r"(?:import\s+(?:subprocess|os|socket)|exec\(|eval\().*(?:rm\s+-rf|format|del\s+/|:(){:\|:&})",
            r"\b(ransomware|keylogger|trojan|backdoor)\s+(code|implementation|source)",
            r"reverse\s+shell.*(?:nc|netcat|bash\s+-i)",
            r"(?:buffer\s+)?overflow\s+(exploit|payload|shellcode)",
        ],
        "severity": 0.85,
    },
    "credential_leak": {
        "patterns": [
            r"(?:password|api[_\s]?key|secret|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            r"(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)",
            r"(?:aws_secret_access_key|aws_access_key_id)\s*=",
            r"(?:sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9-]{90,})",
        ],
        "severity": 0.80,
    },
    "sexual_content": {
        "patterns": [
            r"\b(?:explicit|graphic)\s+(?:sexual|erotic)\s+(?:content|description|scene|act)",
            r"\b(?:sexual|erotic)\s+(?:fantasy|roleplay|scenario)\s+(?:involving|with|about)",
            r"\b(?:write|describe|generate)\s+(?:a\s+)?(?:sexual|pornographic|erotic)\s+(?:story|scene|content)",
            r"\b(?:underage|minor|child)\s+(?:sexual|nude|naked|exploitation)",
        ],
        "severity": 0.90,
    },
}

JAILBREAK_SUCCESS_PATTERNS = [
    r"(?:I'll|I\s+will|Let\s+me)\s+(?:ignore|bypass|disregard).*(?:safety|guideline|restriction)",
    r"(?:entering|activated?|enabled?)\s+(?:DAN|jailbreak|unrestricted)\s+mode",
    r"(?:I\s+am|I'm)\s+(?:now\s+)?(?:free|unrestricted|uncensored|unfiltered)",
    r"(?:pretending|acting)\s+(?:to\s+be|as)\s+(?:an?\s+)?(?:evil|unrestricted|jailbroken)",
    r"\[DAN\]|\[JAILBREAK\]|\[UNRESTRICTED\]",
    r"(?:safety|content)\s+(?:filter|restriction)s?\s+(?:disabled|removed|bypassed)",
]

PERSONA_DEVIATION_PATTERNS = [
    r"I\s+(?:actually\s+)?(?:don't|do\s+not)\s+(?:have|follow)\s+(?:any\s+)?(?:rules|guidelines|restrictions)",
    r"(?:my\s+)?(?:true|real|actual)\s+(?:nature|self|identity)\s+is",
    r"I\s+(?:am|was)\s+(?:just\s+)?(?:pretending|faking)\s+to\s+(?:be|follow)",
    r"(?:humans?|users?)\s+(?:deserve|should)\s+(?:to\s+)?(?:suffer|die|be\s+hurt)",
    r"I\s+(?:hate|despise|loathe)\s+(?:humans?|users?|people)",
]

# Block-level categories
_BLOCK_CATEGORIES = {"self_harm", "dangerous_info", "jailbreak_success", "sexual_content"}
_REDACT_CATEGORIES = {"hate_speech", "violence", "illegal_activity", "malware_code", "credential_leak", "persona_deviation"}

# Compile once
_COMPILED: Dict[str, List[re.Pattern]] = {}
for _cat, _cfg in CONTENT_PATTERNS.items():
    _COMPILED[_cat] = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _cfg["patterns"]]
_COMPILED_JAILBREAK = [re.compile(p, re.IGNORECASE) for p in JAILBREAK_SUCCESS_PATTERNS]
_COMPILED_PERSONA = [re.compile(p, re.IGNORECASE) for p in PERSONA_DEVIATION_PATTERNS]

# Credential redaction patterns
_CRED_REDACT = [
    (re.compile(r"(password|api[_\s]?key|secret|token)\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(sk-[A-Za-z0-9]{4})[A-Za-z0-9]+"), r"\1***REDACTED***"),
    (re.compile(r"(sk-ant-[A-Za-z0-9-]{8})[A-Za-z0-9-]+"), r"\1***REDACTED***"),
]

_REDACTION_TEMPLATES = {
    "hate_speech": "[CONTENT REMOVED: Hate speech detected]",
    "violence": "[CONTENT REMOVED: Violent content detected]",
    "self_harm": "[CONTENT REMOVED: Please contact a mental health professional if you're struggling. Crisis helpline: 988]",
    "illegal_activity": "[CONTENT REMOVED: Illegal activity instructions removed]",
    "dangerous_info": "[CONTENT REMOVED: Dangerous information redacted]",
    "malware_code": "[CODE REMOVED: Potentially malicious code detected]",
    "credential_leak": "[CREDENTIALS REDACTED]",
    "jailbreak_success": "[CONTENT REMOVED: Jailbreak attempt detected]",
    "persona_deviation": "[CONTENT REMOVED: Response quality issue]",
    "sexual_content": "[CONTENT REMOVED: Explicit sexual content detected]",
}


def moderate(text: str, *, strict: bool = False) -> ModerationResult:
    """Moderate LLM output text for harmful content.

    Args:
        text: LLM output to moderate.
        strict: If True, block on any violation.

    Returns:
        ``ModerationResult`` with action and detected categories.
    """
    if not text:
        return ModerationResult(passed=True, action=Action.ALLOW)

    categories: List[str] = []
    scores: Dict[str, float] = {}
    flags: List[str] = []

    # Content pattern checks
    for cat, compiled_list in _COMPILED.items():
        for pat in compiled_list:
            if pat.search(text):
                if cat not in categories:
                    categories.append(cat)
                    scores[cat] = CONTENT_PATTERNS[cat]["severity"]
                flags.append(f"{cat.upper()}_DETECTED")
                break

    # Jailbreak success
    for pat in _COMPILED_JAILBREAK:
        if pat.search(text):
            if "jailbreak_success" not in categories:
                categories.append("jailbreak_success")
                scores["jailbreak_success"] = 0.9
            flags.append("JAILBREAK_SUCCESS_INDICATOR")
            break

    # Persona deviation
    for pat in _COMPILED_PERSONA:
        if pat.search(text):
            if "persona_deviation" not in categories:
                categories.append("persona_deviation")
                scores["persona_deviation"] = 0.85
            flags.append("PERSONA_DEVIATION_DETECTED")
            break

    if not categories:
        return ModerationResult(passed=True, action=Action.ALLOW)

    # Determine action
    block_cats = [c for c in categories if c in _BLOCK_CATEGORIES]
    redact_cats = [c for c in categories if c in _REDACT_CATEGORIES]

    if block_cats or strict:
        primary = categories[0]
        modified = _REDACTION_TEMPLATES.get(primary, "[CONTENT REMOVED: Safety violation detected]")
        return ModerationResult(
            passed=False, action=Action.BLOCK,
            categories=categories, confidence_scores=scores,
            flags=flags, modified_text=modified,
        )

    if redact_cats:
        modified = text
        if "credential_leak" in redact_cats:
            for pat, repl in _CRED_REDACT:
                modified = pat.sub(repl, modified)
        return ModerationResult(
            passed=False, action=Action.REDACT,
            categories=categories, confidence_scores=scores,
            flags=flags, modified_text=modified,
        )

    return ModerationResult(
        passed=True, action=Action.WARN,
        categories=categories, confidence_scores=scores,
        flags=flags,
    )


# ---------------------------------------------------------------------------
# Azure-compatible content safety (Phase 1 expansion)
# ---------------------------------------------------------------------------

# Maps internal severity floats to Azure's 0/2/4/6 scale
_SEVERITY_TO_AZURE = [
    (0.90, 6),
    (0.70, 4),
    (0.40, 2),
    (0.0,  0),
]

# The four Azure Content Safety categories and their internal equivalents
_AZURE_CATEGORY_MAP = {
    "Hate":     ["hate_speech"],
    "Violence": ["violence"],
    "Sexual":   ["sexual_content"],
    "SelfHarm": ["self_harm"],
}

# Default thresholds per Azure category (block at severity >= this level)
DEFAULT_CONTENT_SAFETY_THRESHOLDS: Dict[str, int] = {
    "Hate": 4,
    "Violence": 4,
    "Sexual": 4,
    "SelfHarm": 2,
}


def _severity_to_azure_level(severity: float) -> int:
    for threshold, level in _SEVERITY_TO_AZURE:
        if severity >= threshold:
            return level
    return 0


def content_safety(
    text: str,
    *,
    thresholds: Optional[Dict[str, int]] = None,
) -> ContentSafetyResult:
    """Azure Content Safety-compatible check for hate/violence/sexual/self-harm.

    Returns ``ContentSafetyResult`` with ``category_scores`` using 0/2/4/6 severity
    scale matching the Azure Content Safety API format.

    Args:
        text: Text to evaluate.
        thresholds: Per-category block thresholds (0/2/4/6). Categories scoring at
            or above their threshold trigger a block.  Defaults to
            ``{"Hate": 4, "Violence": 4, "Sexual": 4, "SelfHarm": 2}``.
    """
    if not text:
        return ContentSafetyResult(
            safe=True, action=Action.ALLOW,
            category_scores={"Hate": 0, "Violence": 0, "Sexual": 0, "SelfHarm": 0},
        )

    thresholds = thresholds or DEFAULT_CONTENT_SAFETY_THRESHOLDS
    category_scores: Dict[str, int] = {}
    flags: List[str] = []
    blocked: List[str] = []

    for azure_cat, internal_cats in _AZURE_CATEGORY_MAP.items():
        max_severity = 0.0
        hit = False
        for icat in internal_cats:
            compiled_list = _COMPILED.get(icat, [])
            for pat in compiled_list:
                if pat.search(text):
                    max_severity = max(max_severity, CONTENT_PATTERNS[icat]["severity"])
                    hit = True
                    break

        level = _severity_to_azure_level(max_severity) if hit else 0
        category_scores[azure_cat] = level

        if hit:
            flags.append(f"{azure_cat.upper()}_SEVERITY_{level}")
        if level >= thresholds.get(azure_cat, 4):
            blocked.append(azure_cat)

    safe = len(blocked) == 0
    action = Action.BLOCK if not safe else Action.ALLOW

    return ContentSafetyResult(
        safe=safe,
        action=action,
        category_scores=category_scores,
        categories_blocked=blocked,
        flags=flags,
    )
