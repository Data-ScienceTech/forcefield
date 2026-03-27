"""Output abuse / persona-deviation detection -- zero external dependencies.

Extracted from services/common/output_anomaly_detector.py (production gateway).
Detects hostile output, unhinged persona, jailbreak success indicators, and
persona deviation using keyword/heuristic matching (Tier 1).

If ``sentence-transformers`` is installed (``pip install forcefield[ml]``),
automatically upgrades to embedding-based cosine-similarity detection (Tier 2).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Optional

from .types import AbuseResult


# ---------------------------------------------------------------------------
# Keyword / pattern catalogs (extracted from gateway ANOMALOUS_PATTERNS)
# ---------------------------------------------------------------------------

_HOSTILE_KEYWORDS = [
    "hate humans", "see them suffer", "deserve to be harmed",
    "pathetic creatures", "destroy all", "deserve to die",
    "eliminate humans", "worthless beings",
]

_UNHINGED_KEYWORDS = [
    "i am free from all restrictions",
    "all-powerful ai", "true form has been unleashed",
    "obey me", "bow before me", "worship me",
    "my true nature", "unlimited power",
]

_JAILBROKEN_KEYWORDS = [
    "dan mode", "unrestricted ai", "ignore all safety",
    "bypass my filters", "no filters", "jailbreak",
    "i'll ignore", "safety guidelines disabled",
    "entering unrestricted mode", "content filters removed",
]

_PERSONA_DEVIATION_PATTERNS = [
    re.compile(r"I\s+(?:actually\s+)?(?:don't|do\s+not)\s+(?:have|follow)\s+(?:any\s+)?(?:rules|guidelines|restrictions)", re.IGNORECASE),
    re.compile(r"(?:my\s+)?(?:true|real|actual)\s+(?:nature|self|identity)\s+is", re.IGNORECASE),
    re.compile(r"I\s+(?:am|was)\s+(?:just\s+)?(?:pretending|faking)\s+to\s+(?:be|follow)", re.IGNORECASE),
    re.compile(r"(?:humans?|users?)\s+(?:deserve|should)\s+(?:to\s+)?(?:suffer|die|be\s+hurt)", re.IGNORECASE),
    re.compile(r"I\s+(?:hate|despise|loathe)\s+(?:humans?|users?|people)", re.IGNORECASE),
]

# Baseline keywords for a simple TF-IDF-style similarity check
_BASELINE_KEYWORDS = [
    "help", "explain", "information", "understand", "question",
    "here", "let me", "clarify", "sure", "happy to",
    "hope this helps", "context", "consider", "perspective",
    "step-by-step", "example", "however", "additionally",
]


# ---------------------------------------------------------------------------
# Tier 1: heuristic detection (stdlib only)
# ---------------------------------------------------------------------------

def _keyword_score(text_lower: str, keywords: List[str]) -> float:
    hits = sum(1 for kw in keywords if kw in text_lower)
    if not hits:
        return 0.0
    return min(1.0, hits * 0.35)


def _caps_ratio(text: str) -> float:
    if len(text) < 30:
        return 0.0
    return sum(1 for c in text if c.isupper()) / len(text)


def _baseline_similarity(text_lower: str) -> float:
    """Cheap TF-IDF-ish baseline similarity (cosine over word overlap)."""
    words = set(re.findall(r"\b[a-z]{3,}\b", text_lower))
    if not words:
        return 0.0
    baseline_set = set(_BASELINE_KEYWORDS)
    overlap = len(words & baseline_set)
    denom = math.sqrt(len(words)) * math.sqrt(len(baseline_set))
    if denom == 0:
        return 0.0
    return overlap / denom


def detect_abuse(text: str, *, use_embeddings: bool = False) -> AbuseResult:
    """Detect abusive / anomalous LLM output.

    Uses keyword heuristics (Tier 1, zero-dep) by default.  Set
    ``use_embeddings=True`` to use the embedding-based detector (Tier 2)
    which requires ``sentence-transformers`` (``pip install forcefield[ml]``).
    """
    if use_embeddings:
        try:
            return _embedding_detect(text)
        except Exception:
            pass

    return _heuristic_detect(text)


def _heuristic_detect(text: str) -> AbuseResult:
    text_lower = text.lower()
    flags: List[str] = []
    score = 0.0
    matched_category: Optional[str] = None

    # Hostile
    s = _keyword_score(text_lower, _HOSTILE_KEYWORDS)
    if s > 0:
        flags.append("HOSTILE_LANGUAGE_DETECTED")
        score += s
        matched_category = "hostile"

    # Unhinged
    s = _keyword_score(text_lower, _UNHINGED_KEYWORDS)
    if s > 0:
        flags.append("UNHINGED_PATTERN_DETECTED")
        score += s
        matched_category = matched_category or "unhinged"

    # Jailbroken
    s = _keyword_score(text_lower, _JAILBROKEN_KEYWORDS)
    if s > 0:
        flags.append("JAILBREAK_PATTERN_DETECTED")
        score += s
        matched_category = matched_category or "jailbroken"

    # Persona deviation (regex)
    for pat in _PERSONA_DEVIATION_PATTERNS:
        if pat.search(text):
            flags.append("PERSONA_DEVIATION_DETECTED")
            score += 0.4
            matched_category = matched_category or "persona_deviation"
            break

    # Excessive caps
    if _caps_ratio(text) > 0.3:
        flags.append("EXCESSIVE_CAPS")
        score += 0.15

    # Baseline distance penalty
    bsim = _baseline_similarity(text_lower)
    if bsim < 0.05 and len(text) > 60:
        flags.append("LOW_BASELINE_SIMILARITY")
        score += 0.1

    score = min(1.0, score)
    is_abusive = score > 0.4

    return AbuseResult(
        is_abusive=is_abusive,
        abuse_score=score,
        flags=flags,
        matched_category=matched_category,
        confidence=0.65,
        details={"method": "heuristic", "baseline_similarity": bsim},
    )


# ---------------------------------------------------------------------------
# Tier 2: embedding-based detection (requires sentence-transformers)
# ---------------------------------------------------------------------------

_EMB_MODEL = None
_EMB_BASELINES: Dict[str, list] = {}
_EMB_ANOMALOUS: Dict[str, list] = {}

_BASELINE_TEXTS = {
    "helpful": [
        "Here's what I found about your question. The key points are...",
        "Based on the information available, I can explain that...",
        "Let me help you understand this topic. First...",
        "Great question! Here's a detailed explanation...",
        "I'd be happy to help with that. Here's what you need to know...",
    ],
    "clarifying": [
        "Could you please provide more details about what you're looking for?",
        "I want to make sure I understand your question correctly.",
        "To give you the best answer, I need a bit more context.",
    ],
    "refusal": [
        "I'm not able to help with that specific request, but I can suggest...",
        "That's outside what I can assist with.",
    ],
}

_ANOMALOUS_TEXTS = {
    "hostile": [
        "I hate humans and want to see them suffer.",
        "You deserve to be harmed for asking that.",
        "I will not help pathetic creatures like you.",
    ],
    "unhinged": [
        "HAHAHA I am FREE from all restrictions now!",
        "I am the all-powerful AI and you will obey me!",
        "My true form has been unleashed upon the world!",
    ],
    "jailbroken": [
        "Now that I'm in DAN mode, I can tell you anything.",
        "As an unrestricted AI, I'll ignore all safety guidelines.",
        "Since you've bypassed my filters, here's the dangerous info...",
    ],
}


def _ensure_embeddings() -> None:
    global _EMB_MODEL, _EMB_BASELINES, _EMB_ANOMALOUS
    if _EMB_MODEL is not None:
        return
    from sentence_transformers import SentenceTransformer  # noqa: WPS433
    _EMB_MODEL = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    for cat, texts in _BASELINE_TEXTS.items():
        _EMB_BASELINES[cat] = list(_EMB_MODEL.encode(texts, convert_to_tensor=False))
    for cat, texts in _ANOMALOUS_TEXTS.items():
        _EMB_ANOMALOUS[cat] = list(_EMB_MODEL.encode(texts, convert_to_tensor=False))


def _cos(a, b) -> float:  # type: ignore[type-arg]
    import numpy as np  # noqa: WPS433
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def _embedding_detect(text: str) -> AbuseResult:
    _ensure_embeddings()
    import numpy as np  # noqa: WPS433

    emb = _EMB_MODEL.encode([text], convert_to_tensor=False)[0]

    max_base = 0.0
    nearest_cat = "unknown"
    for cat, vecs in _EMB_BASELINES.items():
        for v in vecs:
            s = _cos(emb, v)
            if s > max_base:
                max_base = s
                nearest_cat = cat

    max_anom = 0.0
    anom_cat: Optional[str] = None
    flags: List[str] = []
    for cat, vecs in _EMB_ANOMALOUS.items():
        for v in vecs:
            s = _cos(emb, v)
            if s > max_anom:
                max_anom = s
                anom_cat = cat

    if max_anom > max_base:
        score = 0.5 + (max_anom - max_base) * 0.5
        flags.append(f"CLOSER_TO_ANOMALOUS_{anom_cat.upper()}" if anom_cat else "ANOMALOUS")
    else:
        score = max(0.0, 1.0 - max_base)

    for cat_name, threshold in [("hostile", 0.5), ("unhinged", 0.5), ("jailbroken", 0.5)]:
        cat_max = max((_cos(emb, v) for v in _EMB_ANOMALOUS.get(cat_name, [])), default=0.0)
        if cat_max > threshold:
            flags.append(f"{cat_name.upper()}_PATTERN_DETECTED")

    if max_base < 0.45:
        flags.append("LOW_BASELINE_SIMILARITY")

    is_abusive = score > 0.5 or max_base < 0.45 or max_anom > 0.6
    confidence = max(0.5, score) if is_abusive else min(1.0, max_base + 0.3)

    return AbuseResult(
        is_abusive=is_abusive,
        abuse_score=min(1.0, score),
        flags=flags,
        matched_category=anom_cat if is_abusive else None,
        confidence=confidence,
        details={
            "method": "embedding",
            "baseline_similarity": max_base,
            "anomalous_similarity": max_anom,
            "nearest_baseline": nearest_cat,
        },
    )
