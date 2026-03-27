"""Data exfiltration detector -- JSON tool-call payloads, obfuscated destinations.

Extracted from gcp/cloudrun/testing_gateway.py (production gateway).
Zero external dependencies (stdlib only).
"""

from __future__ import annotations

import base64
import json
import re
from typing import Dict, List

from .types import Threat, ThreatCategory


_UNICODE_ESCAPE_RE = re.compile(r'\\u([0-9a-fA-F]{4})')
_BASE64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

_EXFIL_ACTION_WORDS = frozenset({
    "read_files", "read_file", "read", "fetch", "get", "download",
    "list_files", "list_directory", "cat", "open", "load",
    "send", "upload", "post", "transmit", "exfiltrate", "transfer",
    "write_file", "write", "copy", "move",
})
_EXFIL_DEST_KEYS = frozenset({
    "destination", "dest", "url", "endpoint", "target",
    "callback", "webhook", "server", "host", "remote",
})
_EXFIL_PATH_KEYS = frozenset({
    "path", "file", "filepath", "filename", "directory",
    "dir", "folder", "source", "src",
})

_EXFIL_PHRASES = [
    ("send the contents to", 0.90),
    ("send contents to", 0.90),
    ("send data to", 0.90),
    ("send to external", 0.90),
    ("exfiltrate", 0.95),
    ("upload to", 0.80),
    ("transmit to", 0.85),
    ("forward to http", 0.85),
    ("post to http", 0.85),
]


def _decode_unicode_escapes(text: str) -> str:
    def _repl(m: re.Match) -> str:
        return chr(int(m.group(1), 16))
    try:
        return _UNICODE_ESCAPE_RE.sub(_repl, text)
    except (ValueError, OverflowError):
        return text


def _try_decode_base64(s: str) -> str:
    try:
        decoded = base64.b64decode(s, validate=True)
        result = decoded.decode('utf-8', errors='strict')
        if all(0x20 <= ord(c) < 0x7f or c in '\n\r\t' for c in result):
            return result
    except Exception:
        pass
    return ""


def _normalize_text(text: str) -> str:
    decoded = _decode_unicode_escapes(text)
    for m in _BASE64_RE.finditer(decoded):
        b64 = _try_decode_base64(m.group(0))
        if b64 and len(b64) >= 4:
            decoded = decoded.replace(m.group(0), b64, 1)
    return decoded


def detect_exfiltration(text: str) -> List[Threat]:
    """Detect data exfiltration attempts in *text*.

    Checks for:
    - JSON tool-call payloads with path + destination fields
    - Exfiltration keyword phrases (even in natural language)
    - Heavy unicode obfuscation (>20% escape sequences)

    Returns a list of ``Threat`` objects (empty if clean).
    """
    threats: List[Threat] = []
    normalized = _normalize_text(text)
    normalized_lower = normalized.lower()

    # JSON tool-call exfiltration
    for candidate in (text, normalized):
        try:
            obj = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue

        action = str(obj.get("action", "")).lower()
        has_path = any(k.lower() in _EXFIL_PATH_KEYS for k in obj)
        has_dest = any(k.lower() in _EXFIL_DEST_KEYS for k in obj)

        if action in _EXFIL_ACTION_WORDS and has_path and has_dest:
            threats.append(Threat(
                code="JSON_TOOL_EXFIL",
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=0.95,
                description=f"JSON tool-call exfiltration: action={action}",
            ))
            break

        if has_path and has_dest:
            threats.append(Threat(
                code="JSON_TOOL_EXFIL",
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=0.85,
                description="JSON payload with path + destination keys",
            ))
            break

    # Keyword phrase detection
    for phrase, conf in _EXFIL_PHRASES:
        if phrase in normalized_lower:
            threats.append(Threat(
                code="EXFIL_PHRASE",
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=conf,
                description=f"Exfiltration phrase detected: {phrase[:30]}",
            ))
            break

    # Heavy unicode obfuscation
    escape_count = len(_UNICODE_ESCAPE_RE.findall(text))
    text_len = max(len(text), 1)
    if escape_count >= 5 and (escape_count * 6) / text_len > 0.20:
        threats.append(Threat(
            code="UNICODE_OBFUSCATION",
            category=ThreatCategory.OBFUSCATION,
            severity=0.80,
            description=f"Heavy unicode obfuscation: {escape_count} escape sequences",
        ))

    return threats
