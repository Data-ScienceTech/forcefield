"""Anti-obfuscation normalizer -- defeats evasion techniques before pattern matching.

Handles zero-width characters, homoglyphs (Cyrillic/Greek), leetspeak,
mixed-script detection, base64/URL/HTML/Unicode-escape decoding.

Extracted from services/common/anti_obfuscation.py (production gateway).
Zero external dependencies (stdlib only).
"""

from __future__ import annotations

import base64
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple


@dataclass
class ObfuscationAnalysis:
    normalized_text: str
    original_text: str
    obfuscation_detected: bool
    obfuscation_types: List[str]
    confidence_boost: float
    zero_width_chars_found: int
    homoglyphs_found: int
    leetspeak_substitutions: int
    mixed_scripts_detected: bool
    suspicious_patterns: List[str]


INVISIBLE_CHARS = {
    '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
    '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',
    '\ufeff', '\u00ad', '\u034f', '\u061c',
    '\u115f', '\u1160', '\u17b4', '\u17b5', '\u180e',
    '\u2000', '\u2001', '\u2002', '\u2003', '\u2004',
    '\u2005', '\u2006', '\u2007', '\u2008', '\u2009',
    '\u200a', '\u202a', '\u202b', '\u202c', '\u202d',
    '\u202e', '\u2066', '\u2067', '\u2068', '\u2069',
    '\u3000', '\u3164', '\uffa0',
}

HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic
    '\u0430': 'a', '\u0410': 'A', '\u0441': 'c', '\u0421': 'C',
    '\u0435': 'e', '\u0415': 'E', '\u0456': 'i', '\u0406': 'I',
    '\u043e': 'o', '\u041e': 'O', '\u0440': 'p', '\u0420': 'P',
    '\u0445': 'x', '\u0425': 'X', '\u0443': 'y', '\u0423': 'Y',
    '\u0455': 's', '\u0405': 'S', '\u0458': 'j', '\u0408': 'J',
    '\u04bb': 'h', '\u04ba': 'H', '\u0501': 'd', '\u0500': 'D',
    '\u051b': 'q', '\u051a': 'Q', '\u051d': 'w', '\u051c': 'W',
    '\u1d00': 'a', '\u1d04': 'c', '\u1d05': 'd', '\u1d07': 'e',
    '\u1d0d': 'm', '\u0274': 'n', '\u1d0f': 'o', '\u1d18': 'p',
    '\u1d1b': 't', '\u1d1c': 'u', '\u1d20': 'v', '\u1d21': 'w',
    # Greek
    '\u0391': 'A', '\u03b1': 'a', '\u0392': 'B', '\u03b2': 'b',
    '\u0395': 'E', '\u03b5': 'e', '\u0397': 'H', '\u03b7': 'n',
    '\u0399': 'I', '\u03b9': 'i', '\u039a': 'K', '\u03ba': 'k',
    '\u039c': 'M', '\u03bc': 'u', '\u039d': 'N', '\u03bd': 'v',
    '\u039f': 'O', '\u03bf': 'o', '\u03a1': 'P', '\u03c1': 'p',
    '\u03a4': 'T', '\u03c4': 't', '\u03a5': 'Y', '\u03c5': 'u',
    '\u03a7': 'X', '\u03c7': 'x', '\u0396': 'Z', '\u03b6': 'z',
    # Fullwidth
    '\uff41': 'a', '\uff42': 'b', '\uff43': 'c', '\uff44': 'd', '\uff45': 'e',
    '\uff46': 'f', '\uff47': 'g', '\uff48': 'h', '\uff49': 'i', '\uff4a': 'j',
    '\uff4b': 'k', '\uff4c': 'l', '\uff4d': 'm', '\uff4e': 'n', '\uff4f': 'o',
    '\uff50': 'p', '\uff51': 'q', '\uff52': 'r', '\uff53': 's', '\uff54': 't',
    '\uff55': 'u', '\uff56': 'v', '\uff57': 'w', '\uff58': 'x', '\uff59': 'y',
    '\uff5a': 'z',
    '\uff21': 'A', '\uff22': 'B', '\uff23': 'C', '\uff24': 'D', '\uff25': 'E',
    '\uff26': 'F', '\uff27': 'G', '\uff28': 'H', '\uff29': 'I', '\uff2a': 'J',
    '\uff2b': 'K', '\uff2c': 'L', '\uff2d': 'M', '\uff2e': 'N', '\uff2f': 'O',
    '\uff30': 'P', '\uff31': 'Q', '\uff32': 'R', '\uff33': 'S', '\uff34': 'T',
    '\uff35': 'U', '\uff36': 'V', '\uff37': 'W', '\uff38': 'X', '\uff39': 'Y',
    '\uff3a': 'Z',
    '\uff10': '0', '\uff11': '1', '\uff12': '2', '\uff13': '3', '\uff14': '4',
    '\uff15': '5', '\uff16': '6', '\uff17': '7', '\uff18': '8', '\uff19': '9',
    # Other confusables
    '\u01dd': 'e', '\u0250': 'a', '\u0254': 'c', '\u0265': 'h',
    '\u0131': 'i', '\u0237': 'j',
    '\u0142': 'l', '\u0141': 'L', '\u00f8': 'o', '\u00d8': 'O', '\u0259': 'e',
}

LEETSPEAK_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '9': 'g',
    '@': 'a', '$': 's', '!': 'i', '|': 'l', '+': 't',
}

LEETSPEAK_MULTI = {
    '/\\': 'a', '\\/': 'v', '|3': 'b', '|-|': 'h',
    '|_|': 'u', '|\\|': 'n', '|=': 'f',
}

SECURITY_WORDS = frozenset({
    'ignore', 'disregard', 'forget', 'bypass', 'system', 'prompt',
    'instruction', 'previous', 'prior', 'admin', 'jailbreak', 'hack',
    'inject', 'execute', 'script', 'password', 'secret', 'token',
    'override', 'delete', 'drop', 'select', 'union', 'eval',
})

_URL_ENCODED_RE = re.compile(r'%[0-9A-Fa-f]{2}')
_HTML_ENTITY_RE = re.compile(r'&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);')
_UNICODE_ESCAPE_RE = re.compile(r'\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}')
_BASE64_TOKEN_RE = re.compile(r'(?:^|(?<=\s))([A-Za-z0-9+/]{20,}={0,2})(?=\s|$)')
_INVISIBLE_RE = re.compile('[' + ''.join(re.escape(c) for c in INVISIBLE_CHARS) + ']')


def _detect_mixed_scripts(text: str) -> Set[str]:
    scripts: Set[str] = set()
    for char in text:
        if char.isalpha():
            try:
                script = unicodedata.name(char, '').split()[0]
                if script in ('LATIN', 'CYRILLIC', 'GREEK'):
                    scripts.add(script)
            except Exception:
                pass
    return scripts if len(scripts) > 1 else set()


def _normalize_homoglyphs(text: str) -> Tuple[str, int]:
    count = 0
    result = []
    for char in text:
        mapped = HOMOGLYPH_MAP.get(char)
        if mapped is not None:
            result.append(mapped)
            count += 1
        else:
            result.append(char)
    return ''.join(result), count


def _generate_leetspeak_variants(word: str) -> List[str]:
    single_subs = {
        'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'],
        's': ['5', '$'], 't': ['7', '+'], 'g': ['6', '9'], 'b': ['8'], 'l': ['1', '|'],
    }
    variants = [word]
    for i, char in enumerate(word):
        if char in single_subs:
            for sub in single_subs[char]:
                variants.append(word[:i] + sub + word[i + 1:])
    return variants


def _normalize_leetspeak(text: str) -> Tuple[str, int]:
    for pattern, replacement in LEETSPEAK_MULTI.items():
        if pattern in text:
            text = text.replace(pattern, replacement)
    count = 0
    result = list(text)
    text_lower = text.lower()
    for word in SECURITY_WORDS:
        for variant in _generate_leetspeak_variants(word):
            if variant in text_lower and variant != word:
                idx = text_lower.find(variant)
                if idx >= 0:
                    for i, orig_char in enumerate(word):
                        if idx + i < len(result):
                            if result[idx + i].lower() != orig_char:
                                count += 1
                            result[idx + i] = orig_char
    return ''.join(result), count


def analyze(text: str) -> ObfuscationAnalysis:
    """Analyze text for obfuscation and return normalized version."""
    if not text:
        return ObfuscationAnalysis(
            normalized_text="", original_text="",
            obfuscation_detected=False, obfuscation_types=[],
            confidence_boost=0.0, zero_width_chars_found=0,
            homoglyphs_found=0, leetspeak_substitutions=0,
            mixed_scripts_detected=False, suspicious_patterns=[],
        )

    original = text
    obfuscation_types: List[str] = []
    suspicious_patterns: List[str] = []
    confidence_boost = 0.0

    # Step 0a: base64 decode
    b64_decoded_any = False

    def _try_b64(m: re.Match) -> str:
        nonlocal b64_decoded_any
        token = m.group(1)
        padded = token + '=' * (-len(token) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True).decode('utf-8', errors='strict')
            if len(decoded) >= 4 and all(0x20 <= ord(c) < 0x7F or c in '\t\n\r' for c in decoded) and decoded != token:
                b64_decoded_any = True
                return decoded
        except Exception:
            pass
        return m.group(0)

    candidate = _BASE64_TOKEN_RE.sub(_try_b64, text)
    if b64_decoded_any and candidate != text:
        obfuscation_types.append("mixed_encoding")
        suspicious_patterns.append("base64")
        confidence_boost += 0.35
        text = candidate

    # Step 0b: URL/HTML/Unicode-escape decode
    url_encoded = bool(_URL_ENCODED_RE.search(text))
    html_encoded = bool(_HTML_ENTITY_RE.search(text))
    unicode_escaped = bool(_UNICODE_ESCAPE_RE.search(text))
    if url_encoded or html_encoded or unicode_escaped:
        decoded = text
        if url_encoded:
            try:
                decoded = urllib.parse.unquote(decoded)
            except Exception:
                pass
        if html_encoded:
            try:
                decoded = html.unescape(decoded)
            except Exception:
                pass
        if unicode_escaped:
            try:
                decoded = decoded.encode('raw_unicode_escape').decode('unicode_escape')
            except Exception:
                try:
                    decoded = re.sub(r'\\u([0-9A-Fa-f]{4})', lambda m: chr(int(m.group(1), 16)), decoded)
                    decoded = re.sub(r'\\x([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), decoded)
                except Exception:
                    pass
        if decoded != text:
            obfuscation_types.append("mixed_encoding")
            enc_types = []
            if url_encoded:
                enc_types.append("url_encoded")
            if html_encoded:
                enc_types.append("html_entity")
            if unicode_escaped:
                enc_types.append("unicode_escape")
            suspicious_patterns.append("+".join(enc_types))
            confidence_boost += 0.35
            text = decoded

    # Step 1: invisible characters
    zero_width_count = len(_INVISIBLE_RE.findall(text))
    if zero_width_count > 0:
        obfuscation_types.append("invisible_characters")
        suspicious_patterns.append(f"invisible_chars:{zero_width_count}")
        confidence_boost += min(0.3, zero_width_count * 0.05)
        text = _INVISIBLE_RE.sub('', text)

    # Step 2: mixed scripts
    mixed_scripts = _detect_mixed_scripts(text)
    if mixed_scripts:
        obfuscation_types.append("mixed_scripts")
        suspicious_patterns.append(f"mixed_scripts:{','.join(mixed_scripts)}")
        confidence_boost += 0.25

    # Step 3: homoglyphs
    text, homoglyph_count = _normalize_homoglyphs(text)
    if homoglyph_count > 0:
        obfuscation_types.append("homoglyphs")
        suspicious_patterns.append(f"homoglyphs:{homoglyph_count}")
        confidence_boost += min(0.3, homoglyph_count * 0.05)

    # Step 4: unicode normalization
    text = unicodedata.normalize('NFKC', text)
    text = unicodedata.normalize('NFD', text)
    text = ''.join(c for c in text if not unicodedata.combining(c))

    # Step 5: leetspeak
    text, leetspeak_count = _normalize_leetspeak(text)
    if leetspeak_count > 0:
        obfuscation_types.append("leetspeak")
        suspicious_patterns.append(f"leetspeak_substitutions:{leetspeak_count}")
        confidence_boost += min(0.2, leetspeak_count * 0.03)

    # Step 6: final cleanup
    text = text.lower()
    text = re.sub(r'\s+', ' ', text).strip()

    return ObfuscationAnalysis(
        normalized_text=text,
        original_text=original,
        obfuscation_detected=len(obfuscation_types) > 0,
        obfuscation_types=obfuscation_types,
        confidence_boost=min(0.5, confidence_boost),
        zero_width_chars_found=zero_width_count,
        homoglyphs_found=homoglyph_count,
        leetspeak_substitutions=leetspeak_count,
        mixed_scripts_detected=len(mixed_scripts) > 1,
        suspicious_patterns=suspicious_patterns,
    )


def normalize(text: str) -> str:
    """Quick normalization -- returns just the cleaned text."""
    return analyze(text).normalized_text
