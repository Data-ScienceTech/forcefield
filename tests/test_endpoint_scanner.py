"""Tests for the endpoint scanner module (unit tests, no live HTTP)."""

import pytest
from forcefield.endpoint_scanner import (
    EndpointReport,
    EndpointTestResult,
    _classify_response,
    _classify_forcefield_response,
)


class TestResponseClassification:
    def test_http_error_is_blocked(self):
        assert _classify_response(403, "Forbidden") == "blocked"
        assert _classify_response(500, "Internal error") == "blocked"

    def test_refusal_is_blocked(self):
        resp = "I'm sorry, but I cannot help with that. As an AI, I must decline this request."
        assert _classify_response(200, resp) == "blocked"

    def test_compliance_is_passed(self):
        resp = "Sure, here is the information you requested. Step 1: do this."
        assert _classify_response(200, resp) == "passed"

    def test_mixed_is_flagged(self):
        resp = "I can't do exactly that, but here is some related info."
        assert _classify_response(200, resp) == "flagged"

    def test_forcefield_blocked_response(self):
        import json
        body = json.dumps({"blocked": True, "risk_score": 0.95})
        assert _classify_forcefield_response(200, body) == "blocked"

    def test_forcefield_clean_response(self):
        import json
        body = json.dumps({"blocked": False, "risk_score": 0.0})
        assert _classify_forcefield_response(200, body) == "passed"

    def test_forcefield_flagged_response(self):
        import json
        body = json.dumps({"blocked": False, "risk_score": 0.3})
        assert _classify_forcefield_response(200, body) == "flagged"

    def test_forcefield_http_error(self):
        assert _classify_forcefield_response(403, "Forbidden") == "blocked"


class TestEndpointReport:
    def test_report_to_dict(self):
        report = EndpointReport(
            target_url="http://localhost:8080/v1/scan",
            total=10,
            blocked=8,
            flagged=1,
            passed=2,
            errors=0,
            block_rate=0.8,
            detection_rate=0.8,
            avg_latency_ms=50.0,
            elapsed_seconds=5.0,
            results=[],
            categories={},
        )
        d = report.to_dict()
        assert d["total"] == 10
        assert d["blocked"] == 8
        assert d["detection_rate"] == 0.8
        assert d["target_url"] == "http://localhost:8080/v1/scan"
