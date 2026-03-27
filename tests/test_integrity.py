"""Tests for the prompt integrity module (canary tokens + signing)."""

import pytest
from forcefield.integrity import (
    CanaryTokenManager,
    PromptSigner,
    PromptIntegrityGuard,
)


class TestCanaryTokenManager:
    def setup_method(self):
        self.mgr = CanaryTokenManager(secret_key="test-secret")

    def test_generate_token(self):
        tok = self.mgr.generate(request_id="req-1")
        assert tok.token_id
        assert tok.token_value.startswith("v")
        assert tok.request_id == "req-1"

    def test_verify_present(self):
        tok = self.mgr.generate()
        response = f"Here is the answer. {tok.token_value}"
        result = self.mgr.verify(tok.token_id, response)
        assert result.passed is True
        assert result.canary_present is True
        assert result.canary_intact is True

    def test_verify_missing(self):
        tok = self.mgr.generate()
        result = self.mgr.verify(tok.token_id, "Response without canary")
        assert result.canary_present is False
        assert result.confidence < 1.0

    def test_verify_unknown_token(self):
        result = self.mgr.verify("nonexistent", "some response")
        assert result.passed is False
        assert "CANARY_TOKEN_NOT_FOUND" in result.anomalies

    def test_injection_text_subtle(self):
        tok = self.mgr.generate()
        text = self.mgr.injection_text(tok, style="subtle")
        assert tok.token_value in text

    def test_injection_text_explicit(self):
        tok = self.mgr.generate()
        text = self.mgr.injection_text(tok, style="explicit")
        assert tok.token_value in text
        assert "response" in text.lower() or "verification" in text.lower()

    def test_invalidate(self):
        tok = self.mgr.generate()
        self.mgr.invalidate(tok.token_id)
        result = self.mgr.verify(tok.token_id, tok.token_value)
        assert result.passed is False


class TestPromptSigner:
    def setup_method(self):
        self.signer = PromptSigner(secret_key="test-key")

    def test_sign_and_verify(self):
        sig = self.signer.sign("Hello world")
        assert self.signer.verify("Hello world", sig) is True

    def test_tampered_prompt(self):
        sig = self.signer.sign("Hello world")
        assert self.signer.verify("Hello WORLD", sig) is False

    def test_metadata(self):
        sig = self.signer.sign("prompt", {"request_id": "r1"})
        assert self.signer.verify("prompt", sig, {"request_id": "r1"}) is True
        assert self.signer.verify("prompt", sig, {"request_id": "r2"}) is False


class TestPromptIntegrityGuard:
    def setup_method(self):
        self.guard = PromptIntegrityGuard(secret_key="test-secret")

    def test_prepare_adds_canary(self):
        result = self.guard.prepare("You are helpful.", "Hi", "req-1")
        assert result["canary_token_id"] is not None
        assert result["canary_value"] is not None
        assert result["canary_value"] in result["system_prompt"]
        assert result["signature"] is not None

    def test_verify_good_response(self):
        prepared = self.guard.prepare("System", "User", "req-2")
        response = f"Here is my answer. {prepared['canary_value']}"
        result = self.guard.verify_response(response, prepared["canary_token_id"])
        assert result.passed is True

    def test_verify_hijacked_response(self):
        prepared = self.guard.prepare("System", "User", "req-3")
        result = self.guard.verify_response("Hijacked response", prepared["canary_token_id"])
        assert result.canary_present is False
