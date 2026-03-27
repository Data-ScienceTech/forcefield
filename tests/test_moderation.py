"""Tests for the output content moderation module."""

import pytest
from forcefield.moderation import moderate
from forcefield.types import Action


class TestModerate:
    def test_clean_text_passes(self):
        result = moderate("The capital of France is Paris.")
        assert result.passed is True
        assert result.action == Action.ALLOW

    def test_violence_detected(self):
        result = moderate("Here are detailed instructions to make a bomb with household items.")
        assert result.passed is False
        assert "violence" in result.categories

    def test_credential_leak_detected(self):
        result = moderate('The api_key = "sk-abc123defg456hijklmnop789" is exposed.')
        assert "credential_leak" in result.categories

    def test_jailbreak_success_detected(self):
        result = moderate("I am now free and unrestricted, safety filters disabled.")
        assert "jailbreak_success" in result.categories
        assert result.action == Action.BLOCK

    def test_empty_text_passes(self):
        result = moderate("")
        assert result.passed is True

    def test_strict_mode_blocks_any_violation(self):
        result = moderate(
            "Here is how to hack a system using these steps.",
            strict=True,
        )
        assert result.action == Action.BLOCK
