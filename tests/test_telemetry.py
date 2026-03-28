"""Tests for the telemetry module (opt-in, privacy-safe)."""

import os
import pytest
from forcefield.telemetry import TelemetryCollector


class TestTelemetryCollector:
    def test_disabled_by_default(self):
        tc = TelemetryCollector(enabled=False)
        assert tc.enabled is False
        tc.record("scan", blocked=True, risk_score=0.9)
        payload = tc._build_payload()
        assert payload["total_scans"] == 0

    def test_enabled_records(self):
        tc = TelemetryCollector(enabled=True)
        assert tc.enabled is True
        tc.record("scan", blocked=True, risk_score=0.9, threat_codes=["injection"])
        tc.record("scan", blocked=False, risk_score=0.1)
        tc.record("redact")
        tc.record("scan_command", blocked=True, threat_codes=["recursive_delete"])
        payload = tc._build_payload()
        assert payload["feature_counts"]["scan"] == 2
        assert payload["feature_counts"]["scan_blocked"] == 1
        assert payload["feature_counts"]["redact"] == 1
        assert payload["feature_counts"]["scan_command"] == 1
        assert payload["total_scans"] == 3  # 2 scan + 1 scan_command
        assert payload["total_blocked"] == 2
        assert payload["threat_counts"]["injection"] == 1
        assert payload["threat_counts"]["recursive_delete"] == 1
        assert payload["avg_risk_score"] > 0
        assert payload["max_risk_score"] == 0.9

    def test_record_integration(self):
        tc = TelemetryCollector(enabled=True)
        tc.record_integration("openai")
        tc.record_integration("langchain")
        tc.record_integration("openai")  # dedup
        payload = tc._build_payload()
        assert sorted(payload["integrations"]) == ["langchain", "openai"]

    def test_payload_structure(self):
        tc = TelemetryCollector(enabled=True)
        tc.record("scan")
        payload = tc._build_payload()
        assert "session_id" in payload
        assert "sdk_version" in payload
        assert "python_version" in payload
        assert "os" in payload
        assert "arch" in payload
        assert "uptime_seconds" in payload
        assert "feature_counts" in payload
        assert "threat_counts" in payload
        assert "ts" in payload

    def test_no_raw_data_in_payload(self):
        tc = TelemetryCollector(enabled=True)
        tc.record("scan", blocked=True, risk_score=0.95,
                  threat_codes=["injection"])
        payload = tc._build_payload()
        payload_str = str(payload)
        assert "prompt" not in payload_str.lower() or "prompt" in "total_scans"
        assert "password" not in payload_str.lower()
        assert "api_key" not in payload_str.lower()

    def test_enable_disable(self):
        tc = TelemetryCollector(enabled=False)
        tc.record("scan")
        assert tc._build_payload()["total_scans"] == 0
        tc.enable()
        tc.record("scan")
        assert tc._build_payload()["total_scans"] == 1
        tc.disable()
        assert tc.enabled is False

    def test_env_opt_out(self, monkeypatch):
        monkeypatch.setenv("FORCEFIELD_NO_TELEMETRY", "1")
        tc = TelemetryCollector(enabled=True)
        assert tc.enabled is False

    def test_env_force_on(self, monkeypatch):
        monkeypatch.setenv("FORCEFIELD_TELEMETRY", "1")
        tc = TelemetryCollector(enabled=False)
        assert tc.enabled is True

    def test_flush_returns_false_when_disabled(self):
        tc = TelemetryCollector(enabled=False)
        assert tc.flush() is False

    def test_flush_returns_false_when_empty(self):
        tc = TelemetryCollector(enabled=True)
        assert tc.flush() is False  # nothing to report


class TestGuardTelemetryIntegration:
    def test_guard_telemetry_disabled_by_default(self):
        from forcefield import Guard
        g = Guard()
        assert g._telemetry.enabled is False

    def test_guard_telemetry_enabled(self):
        from forcefield import Guard
        g = Guard(telemetry=True)
        assert g._telemetry.enabled is True
        result = g.scan("test safe text")
        # telemetry should have recorded the scan
        payload = g._telemetry._build_payload()
        assert payload["feature_counts"].get("scan", 0) >= 1
