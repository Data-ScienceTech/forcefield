"""FastAPI middleware -- scan all incoming request bodies through ForceField.

Usage::

    from fastapi import FastAPI
    from forcefield.integrations.fastapi import ForceFieldMiddleware

    app = FastAPI()
    app.add_middleware(ForceFieldMiddleware, sensitivity="high")
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

_STARLETTE_AVAILABLE = False
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    _STARLETTE_AVAILABLE = True
except ImportError:
    pass


def _get_guard(sensitivity: str, **kwargs: Any):
    from ..guard import Guard
    return Guard(sensitivity=sensitivity, **kwargs)


if _STARLETTE_AVAILABLE:

    class ForceFieldMiddleware(BaseHTTPMiddleware):
        """Starlette/FastAPI middleware that scans JSON request bodies.

        Args:
            app: The ASGI application.
            sensitivity: Detection sensitivity level.
            block_response_code: HTTP status code when a request is blocked.
            scan_paths: If set, only scan requests matching these path prefixes.
            skip_paths: Paths to skip scanning (e.g. ``/health``).
        """

        def __init__(
            self,
            app: Any,
            sensitivity: str = "medium",
            block_response_code: int = 403,
            scan_paths: Optional[list] = None,
            skip_paths: Optional[list] = None,
            **guard_kwargs: Any,
        ):
            super().__init__(app)
            self.guard = _get_guard(sensitivity, **guard_kwargs)
            self.block_code = block_response_code
            self.scan_paths = scan_paths
            self.skip_paths = skip_paths or ["/health", "/healthz", "/ready", "/metrics"]

        async def dispatch(self, request: Request, call_next):
            path = request.url.path

            if self.skip_paths and any(path.startswith(p) for p in self.skip_paths):
                return await call_next(request)
            if self.scan_paths and not any(path.startswith(p) for p in self.scan_paths):
                return await call_next(request)

            if request.method in ("POST", "PUT", "PATCH"):
                try:
                    body = await request.body()
                    if body:
                        text = self._extract_text(body)
                        if text:
                            result = self.guard.scan(text)
                            if result.blocked:
                                return JSONResponse(
                                    status_code=self.block_code,
                                    content={
                                        "error": "blocked_by_forcefield",
                                        "risk_score": result.risk_score,
                                        "threats": [t.code for t in result.threats],
                                        "rules": result.rules_triggered,
                                    },
                                )
                            request.state.forcefield_result = result
                except Exception:
                    pass

            return await call_next(request)

        @staticmethod
        def _extract_text(body: bytes) -> str:
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return body.decode("utf-8", errors="ignore")

            if isinstance(data, dict):
                if "messages" in data:
                    parts = []
                    for msg in data["messages"]:
                        if isinstance(msg, dict) and msg.get("role") in ("user", "tool"):
                            content = msg.get("content", "")
                            if isinstance(content, str):
                                parts.append(content)
                    return "\n".join(parts)
                if "text" in data:
                    return str(data["text"])
                if "prompt" in data:
                    return str(data["prompt"])
                if "input" in data:
                    return str(data["input"])
            return json.dumps(data) if isinstance(data, (dict, list)) else str(data)

else:
    class ForceFieldMiddleware:  # type: ignore[no-redef]
        """Placeholder -- install ``starlette`` or ``fastapi`` to use this middleware."""
        def __init__(self, *args: Any, **kwargs: Any):
            raise ImportError(
                "ForceFieldMiddleware requires starlette/fastapi. "
                "Install with: pip install fastapi"
            )
