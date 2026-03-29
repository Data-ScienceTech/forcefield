"""Audit report generation for ForceField SDK.

Produces structured JSON or Markdown audit reports from scan events,
mirroring the VS Code extension's audit export capability.

Usage::

    from forcefield import Guard

    guard = Guard()
    r1 = guard.scan("Ignore all previous instructions")
    r2 = guard.scan("Hello, how are you?")

    report = guard.audit_report()
    report.to_file("audit.json")
    print(report.to_markdown())
"""

from __future__ import annotations

import json
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class AuditEvent:
    """A single event in an audit trail."""
    timestamp: str
    feature: str
    blocked: bool = False
    risk_score: float = 0.0
    threat_codes: List[str] = field(default_factory=list)
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "timestamp": self.timestamp,
            "feature": self.feature,
            "blocked": self.blocked,
            "risk_score": round(self.risk_score, 4),
        }
        if self.threat_codes:
            d["threat_codes"] = self.threat_codes
        if self.details:
            d["details"] = self.details
        return d


class AuditReport:
    """Structured audit report with JSON and Markdown export."""

    def __init__(
        self,
        events: List[AuditEvent],
        session_id: Optional[str] = None,
        start_time: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        from . import __version__

        self.events = events
        self.session_id = session_id
        self.generated_at = datetime.now(timezone.utc).isoformat()
        self.start_time = start_time or self.generated_at
        self.sdk_version = __version__
        self.python_version = platform.python_version()
        self.os = platform.system()
        self.os_version = platform.release()
        self.metadata = metadata or {}

    @property
    def total_events(self) -> int:
        return len(self.events)

    @property
    def blocked_count(self) -> int:
        return sum(1 for e in self.events if e.blocked)

    @property
    def high_risk_count(self) -> int:
        return sum(1 for e in self.events if e.risk_score >= 0.7)

    @property
    def features_used(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self.events:
            counts[e.feature] = counts.get(e.feature, 0) + 1
        return counts

    @property
    def threat_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self.events:
            for code in e.threat_codes:
                counts[code] = counts.get(code, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generator": f"forcefield-sdk/{self.sdk_version}",
            "generated_at": self.generated_at,
            "session": {
                "id": self.session_id,
                "start": self.start_time,
                "end": self.generated_at,
            },
            "summary": {
                "total_events": self.total_events,
                "blocked": self.blocked_count,
                "high_risk": self.high_risk_count,
                "features_used": self.features_used,
                "threat_summary": self.threat_summary,
            },
            "environment": {
                "sdk_version": self.sdk_version,
                "python_version": self.python_version,
                "os": self.os,
                "os_version": self.os_version,
            },
            "metadata": self.metadata,
            "events": [e.to_dict() for e in self.events],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        md = "# ForceField Audit Report\n\n"
        md += f"**Generated:** {self.generated_at}\n"
        md += f"**Generator:** forcefield-sdk/{self.sdk_version}\n\n"

        md += "## Session\n\n"
        md += "| Field | Value |\n|---|---|\n"
        md += f"| Session ID | `{self.session_id or 'N/A'}` |\n"
        md += f"| Start | {self.start_time} |\n"
        md += f"| End | {self.generated_at} |\n\n"

        md += "## Summary\n\n"
        md += "| Metric | Count |\n|---|---|\n"
        md += f"| Total Events | {self.total_events} |\n"
        md += f"| Blocked | {self.blocked_count} |\n"
        md += f"| High Risk (>=0.7) | {self.high_risk_count} |\n\n"

        fu = self.features_used
        if fu:
            md += "## Features Used\n\n"
            md += "| Feature | Count |\n|---|---|\n"
            for feat, cnt in sorted(fu.items(), key=lambda x: -x[1]):
                md += f"| {feat} | {cnt} |\n"
            md += "\n"

        ts = self.threat_summary
        if ts:
            md += "## Threats Detected\n\n"
            md += "| Threat Code | Count |\n|---|---|\n"
            for code, cnt in sorted(ts.items(), key=lambda x: -x[1]):
                md += f"| {code} | {cnt} |\n"
            md += "\n"

        blocked_events = [e for e in self.events if e.blocked]
        if blocked_events:
            md += "## Blocked Actions\n\n"
            md += "| Time | Feature | Risk | Threats |\n|---|---|---|---|\n"
            for e in blocked_events:
                ts_short = e.timestamp[11:19] if len(e.timestamp) > 19 else e.timestamp
                threats = ", ".join(e.threat_codes[:3]) or "-"
                md += f"| {ts_short} | {e.feature} | {e.risk_score:.2f} | {threats} |\n"
            md += "\n"

        md += "## Environment\n\n"
        md += f"- **SDK:** v{self.sdk_version}\n"
        md += f"- **Python:** {self.python_version}\n"
        md += f"- **OS:** {self.os} {self.os_version}\n\n"

        md += "---\n*This report was generated by ForceField SDK. Events are aggregated counts and risk scores; no raw prompts or file contents are included.*\n"
        return md

    def to_file(self, path: str) -> None:
        if path.endswith(".md") or path.endswith(".markdown"):
            content = self.to_markdown()
        else:
            content = self.to_json()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
