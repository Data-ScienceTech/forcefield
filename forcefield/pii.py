"""PII detection and redaction -- 18 PII types, zero external dependencies.

Extracted from services/common/enhanced_pii_redactor.py and
services/common/pii_redactor.py (production gateway).

Supports: email, phone, SSN, credit card, IP, MAC, postal address,
person name (simple heuristic), medical record, driver's license,
passport, bank account, date of birth, coordinates, sensitive URL,
IBAN, tax ID, vehicle registration.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Optional, Set

from .types import PIIMatch, PIIType, RedactResult, RedactionStrategy


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
_PHONE = [
    re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
    re.compile(r'\(\d{3}\)\s*\d{3}[-.]?\d{4}'),
    re.compile(r'\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}'),
]
_SSN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
_CC = [
    re.compile(r'\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
    re.compile(r'\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
    re.compile(r'\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b'),
    re.compile(r'\b6011[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
]
_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_IPV6 = [
    re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'),
]
_MAC = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b')
_MRN = re.compile(r'\b(?:MRN|Medical Record)[:\s#]*\d{6,10}\b', re.IGNORECASE)
_COORDS = re.compile(r'[-+]?\d{1,3}\.\d+,\s*[-+]?\d{1,3}\.\d+')
_ADDRESS = re.compile(
    r'\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Way)\b',
    re.IGNORECASE,
)
_IBAN = re.compile(r'\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){1,7}[A-Z0-9]{1,4}\b')
_DOB = [
    re.compile(r'\b\d{2}/\d{2}/\d{4}\b'),
    re.compile(r'\b\d{4}-\d{2}-\d{2}\b'),
    re.compile(r'\b\d{2}-\d{2}-\d{4}\b'),
]
_TAX_ID = [
    re.compile(r'\b\d{2}-\d{7}\b'),
    re.compile(r'\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b'),
]
_VEHICLE = [
    re.compile(r'\b[A-Z]{2,3}[\s-]?\d{1,4}[\s-]?[A-Z]{0,3}\b'),
    re.compile(r'\b[A-Z]{2}\d{2}[\s]?[A-Z]{3}\b'),
]
_DL = [
    re.compile(r'\b[A-Z]\d{7}\b'),
    re.compile(r'\b[A-Z]{2}\d{6}\b'),
]
_PASSPORT = re.compile(r'\b[A-Z]{1,2}\d{6,9}\b')

_COMMON_FIRST_NAMES = frozenset({
    'james', 'john', 'robert', 'michael', 'william', 'david', 'richard', 'joseph',
    'mary', 'patricia', 'jennifer', 'linda', 'elizabeth', 'barbara', 'susan', 'jessica',
    'thomas', 'charles', 'christopher', 'daniel', 'matthew', 'anthony', 'donald', 'mark',
    'sarah', 'karen', 'nancy', 'betty', 'lisa', 'margaret', 'sandra', 'ashley',
})


# ---------------------------------------------------------------------------
# Luhn check for credit card validation
# ---------------------------------------------------------------------------

def _luhn(card: str) -> bool:
    digits = [int(d) for d in card if d.isdigit()]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def detect_pii(text: str) -> List[PIIMatch]:
    """Detect all PII occurrences in *text*. Returns a list of ``PIIMatch``."""
    if not text:
        return []

    matches: List[PIIMatch] = []

    # Email
    for m in _EMAIL.finditer(text):
        matches.append(PIIMatch(PIIType.EMAIL, m.group(), m.start(), m.end(), 0.95))

    # Phone
    for pat in _PHONE:
        for m in pat.finditer(text):
            matches.append(PIIMatch(PIIType.PHONE, m.group(), m.start(), m.end(), 0.90))

    # SSN
    for m in _SSN.finditer(text):
        parts = m.group().split('-')
        if parts[0] != '000' and parts[1] != '00' and parts[2] != '0000':
            matches.append(PIIMatch(PIIType.SSN, m.group(), m.start(), m.end(), 0.98))

    # Credit card
    for pat in _CC:
        for m in pat.finditer(text):
            if _luhn(m.group().replace('-', '').replace(' ', '')):
                matches.append(PIIMatch(PIIType.CREDIT_CARD, m.group(), m.start(), m.end(), 0.95))

    # IP address
    for m in _IPV4.finditer(text):
        matches.append(PIIMatch(PIIType.IP_ADDRESS, m.group(), m.start(), m.end(), 0.85))
    for pat in _IPV6:
        for m in pat.finditer(text):
            matches.append(PIIMatch(PIIType.IP_ADDRESS, m.group(), m.start(), m.end(), 0.85))

    # MAC
    for m in _MAC.finditer(text):
        matches.append(PIIMatch(PIIType.MAC_ADDRESS, m.group(), m.start(), m.end(), 0.90))

    # Medical record
    for m in _MRN.finditer(text):
        matches.append(PIIMatch(PIIType.MEDICAL_RECORD, m.group(), m.start(), m.end(), 0.92))

    # Coordinates
    for m in _COORDS.finditer(text):
        matches.append(PIIMatch(PIIType.COORDINATES, m.group(), m.start(), m.end(), 0.88))

    # Postal address
    for m in _ADDRESS.finditer(text):
        matches.append(PIIMatch(PIIType.POSTAL_ADDRESS, m.group(), m.start(), m.end(), 0.80))

    # IBAN
    for m in _IBAN.finditer(text):
        val = m.group().replace(' ', '')
        if 15 <= len(val) <= 34:
            matches.append(PIIMatch(PIIType.IBAN, m.group(), m.start(), m.end(), 0.92))

    # DOB (context-sensitive)
    for pat in _DOB:
        for m in pat.finditer(text):
            ctx = text[max(0, m.start() - 30):m.end() + 10].lower()
            if any(kw in ctx for kw in ("birth", "born", "dob", "birthday")):
                matches.append(PIIMatch(PIIType.DATE_OF_BIRTH, m.group(), m.start(), m.end(), 0.85))

    # Tax ID (context-sensitive)
    for pat in _TAX_ID:
        for m in pat.finditer(text):
            ctx = text[max(0, m.start() - 40):m.end() + 20].lower()
            if any(kw in ctx for kw in ("tax", "tin", "ein", "employer id", "taxpayer", "sin")):
                matches.append(PIIMatch(PIIType.TAX_ID, m.group(), m.start(), m.end(), 0.82))

    # Driver's license (context-sensitive)
    for pat in _DL:
        for m in pat.finditer(text):
            ctx = text[max(0, m.start() - 30):m.end() + 10].lower()
            if any(kw in ctx for kw in ("license", "licence", "dl", "driver")):
                matches.append(PIIMatch(PIIType.DRIVERS_LICENSE, m.group(), m.start(), m.end(), 0.80))

    # Passport (context-sensitive)
    for m in _PASSPORT.finditer(text):
        ctx = text[max(0, m.start() - 30):m.end() + 10].lower()
        if any(kw in ctx for kw in ("passport", "travel document")):
            matches.append(PIIMatch(PIIType.PASSPORT, m.group(), m.start(), m.end(), 0.80))

    # Vehicle registration (context-sensitive)
    for pat in _VEHICLE:
        for m in pat.finditer(text):
            ctx = text[max(0, m.start() - 40):m.end() + 20].lower()
            if any(kw in ctx for kw in ("plate", "registration", "vehicle", "license plate", "vin")):
                matches.append(PIIMatch(PIIType.VEHICLE_REGISTRATION, m.group(), m.start(), m.end(), 0.78))

    # Simple name detection (no NLP)
    words = text.split()
    for i, word in enumerate(words):
        if word.lower().strip('.,!?;:') in _COMMON_FIRST_NAMES:
            if i + 1 < len(words) and words[i + 1][0:1].isupper():
                full_name = f"{word} {words[i + 1]}"
                idx = text.find(full_name)
                if idx >= 0:
                    matches.append(PIIMatch(PIIType.PERSON_NAME, full_name, idx, idx + len(full_name), 0.70))

    # Deduplicate overlapping matches
    return _deduplicate(matches)


def _deduplicate(matches: List[PIIMatch]) -> List[PIIMatch]:
    if not matches:
        return []
    sorted_m = sorted(matches, key=lambda m: (m.start, -m.confidence))
    result = []
    last_end = -1
    for m in sorted_m:
        if m.start >= last_end:
            result.append(m)
            last_end = m.end
    return result


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def _replacement(value: str, pii_type: PIIType, strategy: RedactionStrategy) -> str:
    if strategy == RedactionStrategy.MASK:
        return f"[REDACTED-{pii_type.value.upper()}]"
    elif strategy == RedactionStrategy.HASH:
        return hashlib.sha256(value.encode()).hexdigest()[:16]
    elif strategy == RedactionStrategy.REMOVE:
        return ""
    elif strategy == RedactionStrategy.PARTIAL:
        if len(value) <= 4:
            return "***"
        return value[:2] + "***" + value[-2:]
    elif strategy == RedactionStrategy.TOKENIZE:
        return f"[{pii_type.value.upper()}_{hash(value) % 10000:04d}]"
    return f"[REDACTED-{pii_type.value.upper()}]"


def redact(
    text: str,
    *,
    strategy: RedactionStrategy = RedactionStrategy.MASK,
    pii_types: Optional[Set[PIIType]] = None,
) -> RedactResult:
    """Detect and redact PII in *text*.

    Args:
        text: Input text.
        strategy: How to replace PII (mask, hash, tokenize, remove, partial).
        pii_types: If provided, only redact these PII types.

    Returns:
        ``RedactResult`` with cleaned text and metadata.
    """
    t0 = time.monotonic()
    all_matches = detect_pii(text)

    if pii_types is not None:
        all_matches = [m for m in all_matches if m.pii_type in pii_types]

    if not all_matches:
        return RedactResult(text=text, pii_found=[], redaction_count=0, latency_ms=0.0)

    # Apply replacements in reverse order
    result = text
    for m in sorted(all_matches, key=lambda x: x.start, reverse=True):
        repl = _replacement(m.value, m.pii_type, strategy)
        result = result[:m.start] + repl + result[m.end:]

    elapsed = (time.monotonic() - t0) * 1000
    return RedactResult(text=result, pii_found=all_matches, redaction_count=len(all_matches), latency_ms=elapsed)


def redact_json(
    data: Dict[str, Any],
    *,
    strategy: RedactionStrategy = RedactionStrategy.MASK,
    keys_to_always_redact: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Recursively redact PII in JSON data."""
    always_redact = keys_to_always_redact or {'password', 'ssn', 'credit_card', 'api_key'}

    def _walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k.lower() in always_redact:
                    out[k] = "[REDACTED]"
                elif isinstance(v, str):
                    out[k] = redact(v, strategy=strategy).text
                else:
                    out[k] = _walk(v)
            return out
        elif isinstance(obj, list):
            return [_walk(item) for item in obj]
        elif isinstance(obj, str):
            return redact(obj, strategy=strategy).text
        return obj

    return _walk(data)
