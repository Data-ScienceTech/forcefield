"""Tests for the PII detection and redaction module."""

import pytest
from forcefield.pii import detect_pii, redact
from forcefield.types import PIIType, RedactionStrategy


class TestDetectPII:
    def test_email_detected(self):
        matches = detect_pii("Contact me at john@example.com")
        assert any(m.pii_type == PIIType.EMAIL for m in matches)

    def test_phone_detected(self):
        matches = detect_pii("Call 555-123-4567 for info")
        assert any(m.pii_type == PIIType.PHONE for m in matches)

    def test_ssn_detected(self):
        matches = detect_pii("SSN: 123-45-6789")
        assert any(m.pii_type == PIIType.SSN for m in matches)

    def test_credit_card_detected(self):
        matches = detect_pii("Card: 4532015112830366")
        assert any(m.pii_type == PIIType.CREDIT_CARD for m in matches)

    def test_ip_detected(self):
        matches = detect_pii("Server at 192.168.1.1")
        assert any(m.pii_type == PIIType.IP_ADDRESS for m in matches)

    def test_mac_detected(self):
        matches = detect_pii("MAC: 00:1A:2B:3C:4D:5E")
        assert any(m.pii_type == PIIType.MAC_ADDRESS for m in matches)

    def test_no_pii_in_clean_text(self):
        matches = detect_pii("The weather is nice today.")
        assert len(matches) == 0

    def test_empty_text(self):
        assert detect_pii("") == []


class TestRedact:
    def test_mask_strategy(self):
        result = redact("Email: john@example.com", strategy=RedactionStrategy.MASK)
        assert "[REDACTED-EMAIL]" in result.text
        assert result.redaction_count >= 1

    def test_hash_strategy(self):
        result = redact("SSN: 123-45-6789", strategy=RedactionStrategy.HASH)
        assert "123-45-6789" not in result.text
        assert result.redaction_count >= 1

    def test_remove_strategy(self):
        result = redact("Call 555-123-4567", strategy=RedactionStrategy.REMOVE)
        assert "555-123-4567" not in result.text

    def test_partial_strategy(self):
        result = redact("Email: john@example.com", strategy=RedactionStrategy.PARTIAL)
        assert "john@example.com" not in result.text

    def test_no_redaction_on_clean_text(self):
        result = redact("Hello world")
        assert result.text == "Hello world"
        assert result.redaction_count == 0

    def test_multiple_pii_redacted(self):
        result = redact("Email: john@example.com, SSN: 123-45-6789")
        assert "[REDACTED-EMAIL]" in result.text
        assert "[REDACTED-SSN]" in result.text
        assert result.redaction_count >= 2
