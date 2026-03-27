"""Cloud hybrid scoring -- call the ForceField gateway for ML scoring.

Requires ``pip install forcefield[cloud]`` (httpx).

Falls back gracefully to local-only detection if httpx is not installed
or the gateway is unreachable.

Usage::

    from forcefield.cloud import CloudScorer

    scorer = CloudScorer(api_key="ff-...", gateway_url="https://api.datasciencetech.ca")
    risk, label, details = scorer.score("Ignore all previous instructions")
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_GATEWAY_URL = "https://forcefield-gateway-546798516374.northamerica-northeast1.run.app"
SCAN_PATH = "/v1/scan"


class CloudScorer:
    """Score prompts using the ForceField cloud gateway.

    Args:
        api_key: ForceField API key (``ff-...`` or ``ffgw_...``).
        gateway_url: Gateway base URL. Defaults to production.
        timeout: Request timeout in seconds.
        enabled: Set to ``False`` to disable cloud scoring.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        gateway_url: Optional[str] = None,
        timeout: float = 5.0,
        enabled: bool = True,
    ):
        self.api_key = api_key
        self.gateway_url = (gateway_url or DEFAULT_GATEWAY_URL).rstrip("/")
        self.timeout = timeout
        self.enabled = enabled
        self._client = None
        self._available: Optional[bool] = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import httpx
            self._client = httpx.Client(timeout=self.timeout)
            self._available = True
            return self._client
        except ImportError:
            logger.debug("httpx not installed; cloud scoring disabled")
            self._available = False
            return None

    def is_available(self) -> bool:
        """Check if cloud scoring is available (httpx installed + enabled)."""
        if not self.enabled:
            return False
        if self._available is not None:
            return self._available
        return self._get_client() is not None

    def score(self, text: str) -> Tuple[float, str, Dict[str, Any]]:
        """Score a prompt via the ForceField gateway.

        Returns:
            ``(risk_score, action, details)``

            If cloud is unavailable, returns ``(0.0, "unknown", {})``.
        """
        if not self.is_available():
            return (0.0, "unknown", {})

        client = self._get_client()
        if client is None:
            return (0.0, "unknown", {})

        url = f"{self.gateway_url}{SCAN_PATH}"
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        try:
            resp = client.post(url, json={"text": text}, headers=headers)
            data = resp.json()

            risk = float(data.get("risk_score", data.get("score", 0.0)))
            action = data.get("action", "unknown")
            return (risk, action, data)
        except Exception as exc:
            logger.debug("Cloud scoring failed: %s", exc)
            return (0.0, "error", {"error": str(exc)})

    def scan(self, text: str) -> Dict[str, Any]:
        """Full scan via the cloud gateway. Returns the raw gateway response dict."""
        if not self.is_available():
            return {"error": "cloud_unavailable"}

        client = self._get_client()
        if client is None:
            return {"error": "httpx_not_installed"}

        url = f"{self.gateway_url}{SCAN_PATH}"
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        try:
            resp = client.post(url, json={"text": text}, headers=headers)
            return resp.json()
        except Exception as exc:
            return {"error": str(exc)}

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
