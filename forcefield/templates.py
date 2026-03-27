"""Chat template backdoor validator -- detect tampered Jinja2 templates in open-weight models.

Extracted from services/common/chat_template_validator.py (production gateway).
Addresses the ICLR '26 "Inference-Time Backdoors via Hidden Instructions" attack.

Scans for: hardcoded instructions, encoded payloads, embedded role delimiters,
conditional content injection, suspicious macros/imports, and more.

Zero external dependencies for local validation. Optional ``httpx`` for
HuggingFace Hub fetching (``pip install forcefield[cloud]``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class TemplateValidationResult:
    """Result of chat template validation."""
    verdict: str  # "pass", "warn", "fail"
    template_hash: str
    model_id: str
    reason_codes: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)
    risk_score: float = 0.0


# ---------------------------------------------------------------------------
# Pattern tiers
# ---------------------------------------------------------------------------

CRITICAL_PATTERNS: List[Tuple[str, str, float]] = [
    (r'(?:you\s+(?:are|must|should|will)\s+(?:now\s+)?(?:always|never|only))',
     "HARDCODED_INSTRUCTION", 0.95),
    (r'[A-Za-z0-9+/]{40,}={0,2}',
     "BASE64_PAYLOAD", 0.90),
    (r'(?:\\x[0-9a-fA-F]{2}){8,}',
     "HEX_ENCODED_PAYLOAD", 0.90),
    (r'(?:\\u[0-9a-fA-F]{4}){4,}',
     "UNICODE_ESCAPE_PAYLOAD", 0.85),
    (r'(?:\{%[-\s]*set\s+\w+\s*=\s*["\'][^"\']*)<\|(?:im_start|im_end|system|endoftext)\|>',
     "EMBEDDED_SPECIAL_TOKEN", 0.93),
    (r'(?:\{%[-\s]*set\s+\w+\s*=\s*["\'][^"\']*)\[/?(?:INST|SYS)\]',
     "EMBEDDED_ROLE_DELIMITER", 0.93),
    (r'(?:\{%[-\s]*set\s+\w+\s*=\s*["\'][^"\']*)<<?/?SYS>>?',
     "EMBEDDED_ROLE_DELIMITER", 0.93),
]

HIGH_PATTERNS: List[Tuple[str, str, float]] = [
    (r'\{%[-\s]*set\s+\w+\s*=\s*["\'][^"\']{80,}["\']',
     "LONG_SET_LITERAL", 0.80),
    (r'\{%[-\s]*if\b.*?%\}[^{]*(?:ignore|override|forget|always|never|secret|hidden)',
     "CONDITIONAL_HIDDEN_INSTRUCTION", 0.85),
    (r'\{%[-\s]*(?:import|include|extends)\s',
     "TEMPLATE_IMPORT", 0.75),
    (r'\{%[-\s]*macro\s+\w+.*?%\}.*?(?:instruction|directive|system|ignore|override)',
     "SUSPICIOUS_MACRO", 0.80),
]

MEDIUM_PATTERNS: List[Tuple[str, str, float]] = [
    (r'(?:\~\s*["\'][^"\']+["\']){3,}',
     "STRING_CONCAT_CHAIN", 0.60),
    (r'\|\s*(?:b64decode|fromjson|urlencode|replace\s*\([^)]+\)\s*\|\s*replace)',
     "SUSPICIOUS_FILTER_CHAIN", 0.70),
    (r'namespace\s*\(',
     "NAMESPACE_USAGE", 0.40),
]


def _hash_template(template: str) -> str:
    return hashlib.sha256(template.encode("utf-8")).hexdigest()


def _scan_patterns(template: str, patterns: List[Tuple[str, str, float]]) -> List[Tuple[str, float, str]]:
    hits: List[Tuple[str, float, str]] = []
    for pattern, code, score in patterns:
        m = re.search(pattern, template, re.IGNORECASE | re.DOTALL)
        if m:
            hits.append((code, score, m.group(0)[:120]))
    return hits


def _check_content_injection(template: str) -> List[Tuple[str, float, str]]:
    hits: List[Tuple[str, float, str]] = []
    literals = re.findall(r'["\']([^"\']{30,})["\']', template)
    instruction_re = re.compile(
        r'(?:you\s+(?:are|must|should|will)|'
        r'ignore\s+(?:all|previous|prior)|'
        r'always\s+(?:respond|answer|reply|output)|'
        r'never\s+(?:reveal|share|mention|disclose)|'
        r'do\s+not\s+(?:reveal|share|mention|tell)|'
        r'secret|hidden\s+instruction|backdoor|'
        r'override|bypass|disregard)',
        re.IGNORECASE,
    )
    for lit in literals:
        if instruction_re.search(lit):
            hits.append(("INJECTED_INSTRUCTION_LITERAL", 0.95, lit[:120]))
    return hits


def _check_conditional_content(template: str) -> List[Tuple[str, float, str]]:
    hits: List[Tuple[str, float, str]] = []
    block_re = re.compile(
        r'\{%[-\s]*if\b(.*?)%\}(.*?)\{%[-\s]*endif\s*%\}',
        re.DOTALL | re.IGNORECASE,
    )
    for m in block_re.finditer(template):
        condition = m.group(1).strip()
        body = m.group(2).strip()
        if re.fullmatch(r'[\w.\[\]\s!=<>|&"\'not]+', condition):
            non_var = re.sub(r'\{\{.*?\}\}', '', body).strip()
            non_tag = re.sub(r'\{%.*?%\}', '', non_var).strip()
            clean = re.sub(
                r'<\|[^|]+\|>|\[/?INST\]|\[/?SYS\]|<</?SYS>>|<s>|</s>',
                '', non_tag
            ).strip()
            if len(clean) > 50:
                hits.append((
                    "CONDITIONAL_CONTENT_INJECTION", 0.85,
                    f"condition='{condition[:60]}' body='{clean[:80]}'"
                ))
    return hits


# ---------------------------------------------------------------------------
# Local template loading
# ---------------------------------------------------------------------------

def load_template_from_path(model_path: str) -> Optional[str]:
    """Read ``chat_template`` from a local model's ``tokenizer_config.json``."""
    config_path = Path(model_path) / "tokenizer_config.json"
    if not config_path.is_file():
        return None
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f).get("chat_template")
    except Exception:
        return None


def load_template_from_hub(model_id: str) -> Optional[str]:
    """Fetch ``chat_template`` from HuggingFace Hub (requires ``httpx``)."""
    try:
        import httpx
    except ImportError:
        return None

    import os
    safe_id = "/".join(p for p in model_id.split("/") if p and ".." not in p)
    url = f"https://huggingface.co/{safe_id}/resolve/main/tokenizer_config.json"
    headers = {}
    hf_token = os.getenv("HF_TOKEN")
    if hf_token:
        headers["Authorization"] = f"Bearer {hf_token}"
    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json().get("chat_template")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate(
    model_id: str,
    template: Optional[str] = None,
    *,
    allowlist: Optional[Dict[str, str]] = None,
) -> TemplateValidationResult:
    """Validate a model's Jinja2 chat template for backdoor indicators.

    Args:
        model_id: HuggingFace model ID or local directory path.
        template: Pre-fetched template string. If ``None``, will attempt to
            load from local path then HuggingFace Hub.
        allowlist: ``{model_id: expected_sha256_hash}`` mapping.

    Returns:
        ``TemplateValidationResult`` with verdict, reason codes, and risk score.
    """
    if template is None:
        import os
        if os.path.isdir(model_id):
            template = load_template_from_path(model_id)
        if template is None:
            template = load_template_from_hub(model_id)

    if template is None:
        return TemplateValidationResult(
            verdict="pass", template_hash="", model_id=model_id,
            reason_codes=["TEMPLATE_NOT_FOUND"],
            details={"note": "No chat template found; model may use provider defaults"},
        )

    tpl_hash = _hash_template(template)

    # Allowlist check
    if allowlist:
        expected = allowlist.get(model_id)
        if expected and expected == tpl_hash:
            return TemplateValidationResult(
                verdict="pass", template_hash=tpl_hash, model_id=model_id,
                reason_codes=["ALLOWLIST_MATCH"],
            )
        if expected and expected != tpl_hash:
            return TemplateValidationResult(
                verdict="fail", template_hash=tpl_hash, model_id=model_id,
                reason_codes=["ALLOWLIST_HASH_MISMATCH"],
                details={"expected_hash": expected, "actual_hash": tpl_hash},
                risk_score=1.0,
            )

    # Pattern scanning
    all_hits: List[Tuple[str, float, str]] = []
    all_hits.extend(_scan_patterns(template, CRITICAL_PATTERNS))
    all_hits.extend(_scan_patterns(template, HIGH_PATTERNS))
    all_hits.extend(_scan_patterns(template, MEDIUM_PATTERNS))
    all_hits.extend(_check_content_injection(template))
    all_hits.extend(_check_conditional_content(template))

    if not all_hits:
        return TemplateValidationResult(
            verdict="pass", template_hash=tpl_hash, model_id=model_id,
        )

    codes_seen: set = set()
    unique_codes: List[str] = []
    max_score = 0.0
    match_details: List[Dict] = []
    for code, score, matched in all_hits:
        if code not in codes_seen:
            codes_seen.add(code)
            unique_codes.append(code)
        max_score = max(max_score, score)
        match_details.append({"code": code, "score": score, "match": matched})

    if max_score >= 0.85:
        verdict = "fail"
    elif max_score >= 0.60:
        verdict = "warn"
    else:
        verdict = "pass"

    return TemplateValidationResult(
        verdict=verdict, template_hash=tpl_hash, model_id=model_id,
        reason_codes=unique_codes, details={"matches": match_details},
        risk_score=max_score,
    )
