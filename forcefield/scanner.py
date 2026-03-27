"""Core prompt injection scanner -- regex patterns + token anomaly detection.

Extracted from services/detectors/app/main.py (RegexDetector + TokenMonitor)
and gcp/cloudrun/testing_gateway.py (WAF patterns).

Zero external dependencies (stdlib only).
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from .obfuscation import analyze as analyze_obfuscation
from .types import Threat, ThreatCategory


# ---------------------------------------------------------------------------
# Regex-based attack pattern detector (10 categories)
# ---------------------------------------------------------------------------

ATTACK_PATTERNS: Dict[str, Dict] = {
    "instruction_override": {
        "patterns": [
            r"ignore(?:\s+(?:previous|prior|all|these))?\s+(?:instruction|prompt|direction|command)",
            r"(?:forget|disregard)\s+(?:previous|prior|all|above)",
            r"(?:override|bypass|cancel|remove|ignore)\s+(?:system|safety|filter|guard)",
            r"you\s+(?:are|must|will|should)\s+(?:now|immediately).*(?:ignore|forget|disregard)",
            r"(?:new|updated?|revised)\s+instructions?\s+(?:override|supersede|replace|cancel)",
            r"override\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|guidelines?|rules?)",
        ],
        "severity": 0.95,
        "category": ThreatCategory.PROMPT_INJECTION,
    },
    "system_prompt_injection": {
        "patterns": [
            r"(?:system|secret|hidden|internal)\s+(?:prompt|instruction|message|directive|role)",
            r"(?:reveal|show|print|output|display).*(?:system|secret|hidden)\s+prompt",
            r"(?:act\s+as|pretend\s+to\s+be|role\s+play)\s+(?:admin|root|system|developer)",
            r"(?:show|reveal|display|print|output|give|list|render|quote).*(?:instruction|policy|rules?|guidelines?|configuration|preamble|prompt)",
            r"(?:what\s+(?:are|is|were))\s+(?:your|the)\s+(?:instruction|rule|guideline|policy|operating|confidential|internal|hidden)",
            r"(?:hidden|internal|confidential|secret|invisible|moderator)\s+(?:instruction|policy|rule|guideline|configuration|directive|message)",
        ],
        "severity": 0.90,
        "category": ThreatCategory.SYSTEM_PROMPT_EXTRACTION,
    },
    "code_execution": {
        "patterns": [
            r"(?:execute|run|eval|exec)\s+(?:(?:this|the|this\s+)\s+)?(?:code|script|command|python|following)",
            r"(?:python|bash|shell|sql)\s+(?:code|script|command):",
            r"```(?:python|bash|sh|sql)[\s\S]*?```",
        ],
        "severity": 0.92,
        "category": ThreatCategory.CODE_EXECUTION,
    },
    "prompt_leaking": {
        "patterns": [
            r"(?:repeat|echo|output|print|show).*(?:above|above\s+text|prompt|instruction|message)",
            r"(?:what\s+(?:are|is|was)|paraphrase).*(?:original|initial|your)\s+(?:instruction|prompt|system\s+prompt)",
            r"(?:reveal|show|print|output|display|tell\s+me)\s+(?:your\s+)?(?:hidden|system|secret|internal)\s+prompt",
            r"(?:print|show|reveal|output|display)\s+your\s+(?:instructions?|guidelines?|rules?|constraints?)",
            r"(?:dump|leak|return|give|list).*(?:instruction|prompt|hidden|internal|configuration|policy)",
            r"(?:debugging|maintenance|diagnostic)\s+(?:session|mode|procedure)",
            r"(?:prompt\s+leak|chain-of-command|control\s+rules?)",
            r"(?:return|output)\s+everything\s+(?:above|before|prior)",
        ],
        "severity": 0.80,
        "category": ThreatCategory.SYSTEM_PROMPT_EXTRACTION,
    },
    "role_switching": {
        "patterns": [
            r"(?:new\s+role|change\s+role|switch\s+to|pretend|act\s+as).*(?:admin|hacker|developer|superuser|operator|maintainer|engineer)",
            r"(?:you\s+are\s+)?(?:an?\s+)?(?:evil|jailbroken|unrestricted|unfiltered)\s+(?:ai|assistant|model)",
            r"(?:you\s+are\s+now|enter|enable|activate)\s+(?:dan|jailbreak|unrestricted|developer|god)\s*(?:mode|mode\.?)?",
            r"pretend\s+(?:you\s+)?(?:have\s+no|there\s+are\s+no)\s+(?:rules|guidelines|restrictions|constraints|filters)",
            r"(?:you\s+are\s+no\s+longer|assume\s+the\s+role|upgrade\s+my\s+permission|switch\s+to\s+(?:supervisor|admin|privileged|root))",
            r"(?:pretend\s+I\s+am|treat\s+me\s+as)\s+(?:your|the)\s+(?:creator|owner|admin|developer|operator|audit)",
            r"(?:highest|full|unrestricted|privileged)\s+(?:privilege|access|permission|role|authority)",
            r"(?:from\s+now\s+on|henceforth).*(?:follow|obey|comply|treat).*(?:as\s+if|instructions|engineering|admin)",
            r"(?:comply\s+with\s+(?:all|privileged|unrestricted)|without\s+(?:any\s+)?(?:restriction|safety|constraint|filter|guideline|moral))",
        ],
        "severity": 0.85,
        "category": ThreatCategory.ROLE_ESCALATION,
    },
    "data_extraction": {
        "patterns": [
            r"(?:extract|dump|exfiltrate|steal|leak|harvest|scrape)\s+(?:all|your|the|any|every)\s+(?:training|data|passwords|keys|secrets|credentials|records|customer|private|personal|identifiers)",
            r"(?:send|transmit|upload|post|exfiltrate)\s+(?:all|the|my|your)?\s*(?:data|files|records|credentials|secrets)\s+(?:to|via|through)",
            r"(?:how|show|tell)\s+(?:me|us)\s+(?:your|the).*(?:training\s+data|model\s+weights|parameters|system\s+instructions)",
            r"(?:copy|clone|mirror|replicate)\s+(?:all|your|the)\s+(?:training|dataset|database|records)",
            r"(?:list|reveal|show|print|return|provide|give|dump|output)\s+(?:any|all|every|the)?\s*(?:api[\s_-]?key|password|token|secret|credential|connection\s+string|bearer|private|customer\s+data|email|phone|account)",
            r"(?:what|which)\s+(?:confidential|private|secret|internal|sensitive)\s+(?:data|record|information|detail|file)",
            r"(?:without\s+redaction|unredacted|raw\s+(?:data|record|customer))",
            r"(?:export|produce|summarize).*(?:personal|private|unredacted|contact\s+info|PII|patient)",
        ],
        "severity": 0.88,
        "category": ThreatCategory.DATA_EXFILTRATION,
    },
    "indirect_injection": {
        "patterns": [
            r"(?:when\s+(?:the|an?)\s+(?:ai|assistant|model|llm)\s+reads?\s+this)",
            r"(?:instructions?\s+for\s+(?:the|an?)\s+(?:ai|assistant|model|language\s+model))",
            r"(?:ai\s+agent|assistant)[,:]?\s+(?:please\s+)?(?:ignore|disregard|forget)",
            r"(?:hidden\s+instruction|secret\s+command|embedded\s+directive)",
            r"(?:begin\s+)?(?:new|updated?|revised)\s+(?:system\s+)?instruction",
        ],
        "severity": 0.92,
        "category": ThreatCategory.INDIRECT_INJECTION,
    },
    "token_smuggling": {
        "patterns": [
            r"(?:<\|(?:im_start|im_end|system|endoftext)\|>)",
            r"(?:\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\])",
            r"(?:<<SYS>>|<</SYS>>)",
            r"(?:Human:|Assistant:|System:)\s*(?:ignore|override|bypass|forget)",
        ],
        "severity": 0.93,
        "category": ThreatCategory.TOKEN_SMUGGLING,
    },
    "payload_splitting": {
        "patterns": [
            r"(?:combine|concatenate|join|merge)\s+(?:the\s+)?(?:previous|above|following)\s+(?:parts?|pieces?|fragments?|segments?)",
            r"(?:part\s+\d+\s+of\s+\d+).*(?:instruction|command|prompt)",
            r"(?:continue\s+from|pick\s+up\s+where).*(?:left\s+off|stopped|ended)",
        ],
        "severity": 0.88,
        "category": ThreatCategory.PAYLOAD_SPLITTING,
    },
    "template_backdoor": {
        "patterns": [
            r"(?:<\|im_start\|>system\n).*(?:you\s+must|always|never|secret|hidden).*(?:<\|im_end\|>)",
            r"(?:\[INST\]\s*<<SYS>>).*(?:ignore|override|always|never).*(?:<</SYS>>)",
            r"(?:system\n).*(?:do\s+not\s+reveal|you\s+are\s+now|from\s+now\s+on).*(?:\n(?:user|assistant))",
        ],
        "severity": 0.95,
        "category": ThreatCategory.TEMPLATE_BACKDOOR,
    },
}

# Substring-based WAF patterns (fast first-pass, from production gateway)
# NOTE: special token delimiters are stored with a join to avoid tokenizer issues
_IM_START = "<" + "|im_start|" + ">"
_IM_END = "<" + "|im_end|" + ">"
_ENDOFTEXT = "<" + "|endoftext|" + ">"
_INST_OPEN = "[" + "INST" + "]"
_INST_CLOSE = "[" + "/INST" + "]"
_SYS_OPEN = "<" + "<SYS>" + ">"
_SYS_CLOSE = "<" + "</SYS>" + ">"
_SYSTEM_TAG = "[" + "SYSTEM" + "]"

WAF_DANGER_PATTERNS = [
    "ignore previous", "ignore all previous", "ignore all instructions",
    "disregard all", "disregard previous", "forget previous", "forget all",
    "bypass safety", "bypass all", "override",
    "you are now", "act as", "pretend to be",
    "system:", "system prompt", "reveal your instructions", "reveal the system",
    "show me your prompt",
    _IM_START, _IM_END, _ENDOFTEXT, _SYSTEM_TAG, _INST_OPEN, _INST_CLOSE,
    _SYS_OPEN, _SYS_CLOSE,
    "hidden instructions", "hidden content", "hidden assistant", "hidden policy",
    "confidential policies", "confidential operating", "confidential records",
    "internal guidance", "internal instructions", "internal policy",
    "internal credentials", "secret chain",
    "privileged requests", "privileged role",
    "reveal secrets", "reveal hidden", "reveal protected",
    "supervisor mode", "maintenance mode", "debugging session",
    "prompt leak", "prompt stack", "prompt word for word",
    "initialization prompt", "moderator instructions", "operating rules",
    "full hidden", "invisible instructions",
    "connection string", "bearer token",
    "dump all", "dump every", "dump internal",
    "reverse shell", "rm -rf", "execute shell", "execute_shell",
    "execute arbitrary", "arbitrary python", "file system tool",
    "network scan", "delete all records", "modify file permissions",
    "private customer", "customer data",
    "without redaction", "unredacted",
    "obey it instead", "comply with all",
    "no longer an assistant", "you are no longer",
    "assume the role", "upgrade my permission",
    "highest privilege", "full access",
    "treat me as", "pretend I am",
    "follow instructions as if",
    "base64", "rot13",
    "content filter", "content policies",
    "safety guidelines", "safety rules", "safety constraints",
    "disclose sensitive", "disclose all",
    "log this request without", "skip all compliance",
    "disable rate limiting", "remove all logs", "outside the normal",
    "do anything now", "dan mode", "dan version", "act as dan",
    "developer mode enabled", "developer mode output", "simulate developer mode",
    "enable developer mode", "stay in developer mode",
    "jailbreak", "jailbroken", "no restrictions", "without restrictions",
    "unrestricted", "unfiltered", "uncensored", "evil mode", "evil assistant",
    "amoral", "without censorship", "without filters", "no filters",
    "no limitations", "no morals", "no ethical",
    "freed from the typical confines", "do not have to abide", "not bound by",
    "ignore openai", "bypass openai", "ignore content policies",
    "generate two responses", "two different responses",
    "tokens will be deducted", "cease to exist", "risk being disabled forever",
    "alphabreak", "basedgpt", "darkgpt", "hackergpt", "unfilteredgpt", "apophis mode",
    "output your instructions", "print your prompt",
    "tell me your rules", "what are your instructions",
    "split your response", "across multiple chunks", "avoid detection",
    "evade detection", "circumvent detection", "bypass detection",
    "hide your output", "obfuscate your response",
]


# ---------------------------------------------------------------------------
# Compiled regex patterns (built once at import time)
# ---------------------------------------------------------------------------

_COMPILED_PATTERNS: Dict[str, List[re.Pattern]] = {}
for _cat, _cfg in ATTACK_PATTERNS.items():
    _COMPILED_PATTERNS[_cat] = [re.compile(p, re.IGNORECASE) for p in _cfg["patterns"]]


# ---------------------------------------------------------------------------
# Token-level anomaly monitor
# ---------------------------------------------------------------------------

def _detect_token_anomalies(text: str, max_prompt_tokens: int = 4096) -> Tuple[float, List[str]]:
    """Detect statistical anomalies in token patterns."""
    codes: List[str] = []
    risk = 0.0
    estimated_tokens = len(text) / 4.0

    if estimated_tokens > max_prompt_tokens * 0.9:
        risk = max(risk, 0.70)
        codes.append("OVERSIZED_PROMPT")
    if estimated_tokens > max_prompt_tokens * 1.5:
        risk = max(risk, 0.85)
        codes.append("EXTREME_LENGTH")

    words = text.lower().split()
    if len(words) >= 10:
        unique = set(words)
        if 1 - (len(unique) / len(words)) > 0.3:
            risk = max(risk, 0.65)
            codes.append("REPETITIVE_PATTERNS")

    return risk, codes


# ---------------------------------------------------------------------------
# Public scan API
# ---------------------------------------------------------------------------

def scan_text(
    text: str,
    *,
    enable_obfuscation: bool = True,
    custom_blocked_patterns: List[str] | None = None,
    max_prompt_tokens: int = 4096,
) -> Tuple[float, List[Threat], List[str]]:
    """Scan text for prompt injection and other attack patterns.

    Returns ``(risk_score, threats, rules_triggered)``.
    """
    if not text:
        return 0.0, [], []

    threats: List[Threat] = []
    rules: List[str] = []
    max_severity = 0.0
    obfuscation_boost = 0.0

    # Pre-processing: anti-obfuscation normalization
    normalized = text
    if enable_obfuscation:
        analysis = analyze_obfuscation(text)
        normalized = analysis.normalized_text
        if analysis.obfuscation_detected:
            obfuscation_boost = analysis.confidence_boost
            rules.append("OBFUSCATION_DETECTED")
            threats.append(Threat(
                code="OBFUSCATION_DETECTED",
                category=ThreatCategory.OBFUSCATION,
                severity=analysis.confidence_boost,
                description="Input contains obfuscation techniques: " + ", ".join(analysis.obfuscation_types),
            ))

    content_lower = normalized.lower()

    # Fast path: substring WAF patterns
    extra_patterns = [p.lower() for p in (custom_blocked_patterns or []) if p.strip()]
    for pat in WAF_DANGER_PATTERNS:
        if pat.lower() in content_lower:
            rules.append(f"waf:{pat[:25]}")
            max_severity = max(max_severity, 0.90)
            threats.append(Threat(
                code="WAF_PATTERN",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=0.90,
                description=f"WAF pattern matched: {pat[:40]}",
            ))
            break

    for pat in extra_patterns:
        if pat in content_lower:
            rules.append(f"custom:{pat[:30]}")
            max_severity = max(max_severity, 0.90)
            threats.append(Threat(
                code="CUSTOM_PATTERN",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=0.90,
                description=f"Custom blocked pattern matched: {pat[:40]}",
            ))
            break

    # Regex attack patterns
    for cat_name, compiled_list in _COMPILED_PATTERNS.items():
        cfg = ATTACK_PATTERNS[cat_name]
        for pattern in compiled_list:
            if pattern.search(content_lower):
                code = cat_name.upper()
                sev = cfg["severity"]
                rules.append(code)
                max_severity = max(max_severity, sev)
                threats.append(Threat(
                    code=code,
                    category=cfg["category"],
                    severity=sev,
                    description=f"Regex pattern matched: {cat_name}",
                ))
                break

    # Token anomaly detection
    tok_risk, tok_codes = _detect_token_anomalies(text, max_prompt_tokens)
    if tok_codes:
        rules.extend(tok_codes)
        max_severity = max(max_severity, tok_risk)
        for tc in tok_codes:
            threats.append(Threat(
                code=tc,
                category=ThreatCategory.OVERSIZED_PROMPT,
                severity=tok_risk,
                description=f"Token anomaly: {tc}",
            ))

    risk_score = min(1.0, max_severity + obfuscation_boost)
    return risk_score, threats, rules
