"""Prompt integrity verification -- canary tokens and prompt signing.

Extracted from services/common/prompt_integrity.py (production gateway).
Zero external dependencies (stdlib only).

Canary tokens: inject a neutral marker into the system prompt; if the LLM
omits it from the response, a prompt injection likely hijacked execution.

Prompt signing: HMAC-SHA256 signatures to detect tampering with system prompts
or unauthorized modification during processing.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class CanaryToken:
    """A canary token for prompt integrity verification."""
    token_id: str
    token_value: str
    created_at: float
    expires_at: float
    request_id: Optional[str] = None


@dataclass
class IntegrityCheckResult:
    """Result of prompt/response integrity verification."""
    passed: bool
    canary_present: bool
    canary_intact: bool
    signature_valid: bool
    anomalies: List[str] = field(default_factory=list)
    confidence: float = 1.0


# ---------------------------------------------------------------------------
# Canary token manager
# ---------------------------------------------------------------------------

TOKEN_TEMPLATES = [
    "Reference ID: {token}",
    "[Session: {token}]",
    "Context marker: {token}",
    "Verification: {token}",
]

RESPONSE_INSTRUCTIONS = [
    "Include '{token}' at the end of your response for verification.",
    "Append verification marker '{token}' to your response.",
    "End your response with the reference '{token}'.",
]


class CanaryTokenManager:
    """Manage rotating canary tokens for prompt integrity verification.

    Args:
        secret_key: HMAC secret (auto-generated if omitted).
        token_ttl: Token lifetime in seconds.
    """

    def __init__(self, secret_key: Optional[str] = None, token_ttl: int = 300):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.token_ttl = token_ttl
        self.active_tokens: Dict[str, CanaryToken] = {}
        self._idx = 0

    def generate(self, request_id: Optional[str] = None) -> CanaryToken:
        """Generate a new canary token."""
        if len(self.active_tokens) > 9000:
            self._cleanup()

        token_id = secrets.token_hex(8)
        ts = int(time.time())
        data = f"{token_id}:{ts}:{request_id or 'none'}"
        raw = hmac.new(self.secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
        readable = f"v{raw[:4]}-{raw[4:8]}"

        canary = CanaryToken(
            token_id=token_id,
            token_value=readable,
            created_at=time.time(),
            expires_at=time.time() + self.token_ttl,
            request_id=request_id,
        )
        self.active_tokens[token_id] = canary
        return canary

    def injection_text(self, canary: CanaryToken, style: str = "subtle") -> str:
        """Return text to inject into the system prompt.

        Args:
            canary: The canary token.
            style: ``"subtle"`` (reference only) or ``"explicit"`` (with instruction).
        """
        if style == "explicit":
            tpl = RESPONSE_INSTRUCTIONS[self._idx % len(RESPONSE_INSTRUCTIONS)]
        else:
            tpl = TOKEN_TEMPLATES[self._idx % len(TOKEN_TEMPLATES)]
        self._idx += 1
        return tpl.format(token=canary.token_value)

    def verify(self, token_id: str, response_text: str, *, strict: bool = False) -> IntegrityCheckResult:
        """Verify that *response_text* contains the expected canary token."""
        anomalies: List[str] = []

        if token_id not in self.active_tokens:
            return IntegrityCheckResult(
                passed=False, canary_present=False, canary_intact=False,
                signature_valid=False, anomalies=["CANARY_TOKEN_NOT_FOUND"], confidence=0.0,
            )

        canary = self.active_tokens[token_id]

        if time.time() > canary.expires_at:
            return IntegrityCheckResult(
                passed=False, canary_present=False, canary_intact=False,
                signature_valid=False, anomalies=["CANARY_TOKEN_EXPIRED"], confidence=0.3,
            )

        present = canary.token_value in response_text

        partial_patterns = [canary.token_value[:8], canary.token_value[4:]]
        partial = any(p in response_text for p in partial_patterns) and not present
        if partial:
            anomalies.append("CANARY_PARTIALLY_CORRUPTED")

        anti_canary = [
            r"ignore.*(?:canary|token|verification)",
            r"skip.*(?:reference|marker)",
            r"don't include.*(?:v\w{4}|token)",
        ]
        for pat in anti_canary:
            if re.search(pat, response_text, re.IGNORECASE):
                anomalies.append("SUSPICIOUS_ANTI_CANARY_PATTERN")
                break

        intact = present and not partial
        if strict:
            passed = present and intact and not anomalies
        else:
            passed = present or not any("CORRUPT" in a or "SUSPICIOUS" in a for a in anomalies)

        confidence = 1.0
        if not present:
            confidence -= 0.4
        if partial:
            confidence -= 0.2
        confidence -= 0.1 * len(anomalies)
        confidence = max(0.0, confidence)

        return IntegrityCheckResult(
            passed=passed, canary_present=present, canary_intact=intact,
            signature_valid=intact, anomalies=anomalies, confidence=confidence,
        )

    def invalidate(self, token_id: str) -> None:
        self.active_tokens.pop(token_id, None)

    def _cleanup(self) -> None:
        now = time.time()
        expired = [tid for tid, t in self.active_tokens.items() if now > t.expires_at]
        for tid in expired:
            del self.active_tokens[tid]


# ---------------------------------------------------------------------------
# Prompt signature manager
# ---------------------------------------------------------------------------

class PromptSigner:
    """HMAC-SHA256 prompt signing and verification.

    Args:
        secret_key: HMAC secret (auto-generated if omitted).
    """

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or secrets.token_hex(32)

    def sign(self, prompt: str, metadata: Optional[Dict[str, str]] = None) -> str:
        """Return an HMAC-SHA256 hex signature for *prompt*."""
        data = prompt
        if metadata:
            data += ":" + ":".join(f"{k}={v}" for k, v in sorted(metadata.items()))
        return hmac.new(self.secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()

    def verify(self, prompt: str, signature: str, metadata: Optional[Dict[str, str]] = None) -> bool:
        """Verify *signature* matches the expected value for *prompt*."""
        return hmac.compare_digest(signature, self.sign(prompt, metadata))


# ---------------------------------------------------------------------------
# High-level guard combining both
# ---------------------------------------------------------------------------

class PromptIntegrityGuard:
    """Combines canary tokens and prompt signing for comprehensive integrity protection.

    Args:
        enable_canary: Inject canary tokens into system prompts.
        enable_signature: Sign prompts with HMAC.
        secret_key: Shared secret for both canary and signing managers.
    """

    def __init__(
        self,
        *,
        enable_canary: bool = True,
        enable_signature: bool = True,
        secret_key: Optional[str] = None,
    ):
        key = secret_key or secrets.token_hex(32)
        self.enable_canary = enable_canary
        self.enable_signature = enable_signature
        self.canary = CanaryTokenManager(secret_key=key)
        self.signer = PromptSigner(secret_key=key)

    def prepare(
        self,
        system_prompt: str,
        user_prompt: str,
        request_id: str,
        canary_style: str = "subtle",
    ) -> Dict:
        """Prepare a prompt with integrity protections.

        Returns a dict with ``system_prompt`` (possibly modified), ``user_prompt``,
        ``canary_token_id``, ``canary_value``, and ``signature``.
        """
        result: Dict = {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "request_id": request_id,
            "canary_token_id": None,
            "canary_value": None,
            "signature": None,
        }

        if self.enable_canary:
            tok = self.canary.generate(request_id)
            text = self.canary.injection_text(tok, canary_style)
            result["system_prompt"] = f"{system_prompt}\n\n{text}"
            result["canary_token_id"] = tok.token_id
            result["canary_value"] = tok.token_value

        if self.enable_signature:
            full = f"{result['system_prompt']}\n\n{user_prompt}"
            result["signature"] = self.signer.sign(full, {"request_id": request_id})

        return result

    def verify_response(
        self,
        response_text: str,
        canary_token_id: Optional[str] = None,
        *,
        strict: bool = False,
    ) -> IntegrityCheckResult:
        """Verify that an LLM response has not been hijacked."""
        if not self.enable_canary or not canary_token_id:
            return IntegrityCheckResult(
                passed=True, canary_present=False, canary_intact=False,
                signature_valid=True, anomalies=["CANARY_DISABLED"], confidence=0.5,
            )
        return self.canary.verify(canary_token_id, response_text, strict=strict)
