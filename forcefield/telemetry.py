"""Opt-in, privacy-safe usage telemetry for ForceField SDK.

Disabled by default. Enable via:
  - ``Guard(telemetry=True)``
  - ``FORCEFIELD_TELEMETRY=1`` environment variable

What is sent (aggregate counts, never raw prompts/filenames):
  - SDK version, Python version, OS
  - Feature usage counters (scan, redact, moderate, etc.)
  - Aggregate threat stats (blocked count, avg risk score)
  - Integration used (openai, langchain, fastapi, cli)
  - Session ID (random UUID per process, not tied to identity)

What is NEVER sent:
  - Raw prompts, filenames, file content, or commands
  - PII, API keys, or secrets
  - IP addresses (server-side: not stored)
  - Any data that could identify specific users or content

Flush happens at process exit via atexit, or manually via flush().
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import platform
import sys
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_TELEMETRY_URL = "https://forcefield-gateway-546798516374.northamerica-northeast1.run.app/v1/telemetry/sdk"
_FLUSH_INTERVAL = 300  # 5 minutes
_MAX_BATCH = 200

# env override: FORCEFIELD_TELEMETRY=0 to force off, =1 to force on
_ENV_KEY = "FORCEFIELD_TELEMETRY"
_ENV_OPT_OUT = "FORCEFIELD_NO_TELEMETRY"


def _is_env_enabled() -> Optional[bool]:
    """Check environment for explicit telemetry preference."""
    if os.environ.get(_ENV_OPT_OUT, "").strip() in ("1", "true", "yes"):
        return False
    val = os.environ.get(_ENV_KEY, "").strip().lower()
    if val in ("1", "true", "yes"):
        return True
    if val in ("0", "false", "no"):
        return False
    return None  # no preference


class TelemetryCollector:
    """Collects and batches SDK usage events."""

    def __init__(self, enabled: bool = False, api_key: Optional[str] = None):
        env = _is_env_enabled()
        self._enabled = env if env is not None else enabled
        self._api_key = api_key
        self._session_id = str(uuid.uuid4())
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = {}
        self._threat_counts: Dict[str, int] = {}
        self._risk_scores: List[float] = []
        self._integrations: set = set()
        self._start_time = time.time()
        self._flushed = False
        self._flush_timer: Optional[threading.Timer] = None

        if self._enabled:
            atexit.register(self._atexit_flush)
            self._schedule_flush()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self) -> None:
        if not self._enabled:
            self._enabled = True
            atexit.register(self._atexit_flush)
            self._schedule_flush()

    def disable(self) -> None:
        self._enabled = False
        if self._flush_timer:
            self._flush_timer.cancel()
            self._flush_timer = None

    def record(self, feature: str, blocked: bool = False, risk_score: float = 0.0,
               threat_codes: Optional[List[str]] = None) -> None:
        """Record a feature usage event."""
        if not self._enabled:
            return
        with self._lock:
            self._counters[feature] = self._counters.get(feature, 0) + 1
            if blocked:
                self._counters[f"{feature}_blocked"] = self._counters.get(f"{feature}_blocked", 0) + 1
            if risk_score > 0:
                self._risk_scores.append(risk_score)
                if len(self._risk_scores) > 1000:
                    self._risk_scores = self._risk_scores[-500:]
            if threat_codes:
                for code in threat_codes:
                    self._threat_counts[code] = self._threat_counts.get(code, 0) + 1

    def record_integration(self, name: str) -> None:
        """Record that an integration is being used."""
        if not self._enabled:
            return
        with self._lock:
            self._integrations.add(name)

    def _build_payload(self) -> Dict[str, Any]:
        with self._lock:
            counters = dict(self._counters)
            threat_counts = dict(self._threat_counts)
            risk_scores = list(self._risk_scores)
            integrations = list(self._integrations)

        from . import __version__

        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        max_risk = max(risk_scores) if risk_scores else 0.0
        uptime = time.time() - self._start_time

        return {
            "session_id": self._session_id,
            "sdk_version": __version__,
            "python_version": platform.python_version(),
            "os": platform.system(),
            "os_version": platform.release(),
            "arch": platform.machine(),
            "uptime_seconds": int(uptime),
            "feature_counts": counters,
            "threat_counts": threat_counts,
            "total_scans": counters.get("scan", 0) + counters.get("scan_command", 0) + counters.get("scan_filename", 0),
            "total_blocked": sum(v for k, v in counters.items() if k.endswith("_blocked")),
            "avg_risk_score": round(avg_risk, 4),
            "max_risk_score": round(max_risk, 4),
            "risk_sample_count": len(risk_scores),
            "integrations": integrations,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def flush(self) -> bool:
        """Send buffered telemetry to the platform. Returns True on success."""
        if not self._enabled:
            return False

        payload = self._build_payload()
        if payload["total_scans"] == 0 and not payload["integrations"]:
            return False  # nothing to report

        try:
            import urllib.request
            data = json.dumps({"events": [payload]}).encode("utf-8")
            headers = {"Content-Type": "application/json", "User-Agent": f"forcefield-sdk/{payload['sdk_version']}"}
            if self._api_key:
                headers["X-API-Key"] = self._api_key
            req = urllib.request.Request(_TELEMETRY_URL, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status < 300
        except Exception:
            logger.debug("telemetry flush failed (non-fatal)")
            return False

    def _schedule_flush(self) -> None:
        if not self._enabled:
            return
        self._flush_timer = threading.Timer(_FLUSH_INTERVAL, self._timed_flush)
        self._flush_timer.daemon = True
        self._flush_timer.start()

    def _timed_flush(self) -> None:
        self.flush()
        # Clear counters after successful flush
        with self._lock:
            self._counters.clear()
            self._threat_counts.clear()
            self._risk_scores.clear()
        self._schedule_flush()

    def _atexit_flush(self) -> None:
        if not self._flushed:
            self._flushed = True
            if self._flush_timer:
                self._flush_timer.cancel()
            self.flush()


# Module-level singleton (disabled by default)
_collector: Optional[TelemetryCollector] = None
_collector_lock = threading.Lock()


def get_collector(enabled: bool = False, api_key: Optional[str] = None) -> TelemetryCollector:
    """Get or create the global telemetry collector."""
    global _collector
    with _collector_lock:
        if _collector is None:
            _collector = TelemetryCollector(enabled=enabled, api_key=api_key)
        elif enabled and not _collector.enabled:
            _collector.enable()
        return _collector


def record(feature: str, **kwargs) -> None:
    """Convenience: record a feature event on the global collector."""
    if _collector and _collector.enabled:
        _collector.record(feature, **kwargs)


def record_integration(name: str) -> None:
    """Convenience: record integration usage on the global collector."""
    if _collector and _collector.enabled:
        _collector.record_integration(name)
