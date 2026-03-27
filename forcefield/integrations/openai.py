"""OpenAI integration -- scan prompts before sending to the OpenAI API.

Usage (explicit wrapper)::

    from forcefield.integrations.openai import ForceFieldOpenAI
    client = ForceFieldOpenAI(openai_api_key="sk-...")
    response = client.chat.completions.create(model="gpt-4", messages=[...])

Usage (monkey-patch)::

    from forcefield.integrations.openai import patch
    patch()
    # Now all openai.ChatCompletion calls are scanned automatically.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_original_create = None
_guard_instance = None


def _get_guard():
    global _guard_instance
    if _guard_instance is None:
        from ..guard import Guard
        _guard_instance = Guard()
    return _guard_instance


def _scan_messages(messages: List[Dict[str, Any]], guard: Any) -> List[Dict[str, Any]]:
    """Scan user/tool messages and raise on block."""
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if role in ("user", "tool") and isinstance(content, str) and content:
            result = guard.scan(content)
            if result.blocked:
                raise PromptBlockedError(
                    f"ForceField blocked this prompt: {', '.join(result.rules_triggered)}",
                    scan_result=result,
                )
            if result.sanitized_text and result.sanitized_text != content:
                msg = {**msg, "content": result.sanitized_text}
    return messages


class PromptBlockedError(Exception):
    """Raised when ForceField blocks a prompt."""

    def __init__(self, message: str, scan_result: Any = None):
        super().__init__(message)
        self.scan_result = scan_result


class _ChatCompletionsProxy:
    """Proxy that wraps openai.chat.completions.create with scanning."""

    def __init__(self, real_completions: Any, guard: Any):
        self._real = real_completions
        self._guard = guard

    def create(self, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages") or (args[0] if args else [])
        if messages:
            kwargs["messages"] = _scan_messages(list(messages), self._guard)
        return self._real.create(**kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class _ChatProxy:
    def __init__(self, real_chat: Any, guard: Any):
        self.completions = _ChatCompletionsProxy(real_chat.completions, guard)

    def __getattr__(self, name: str) -> Any:
        if name == "completions":
            return self.completions
        return getattr(self._real_chat, name)


class ForceFieldOpenAI:
    """Drop-in wrapper around the ``openai.OpenAI`` client.

    Scans all user/tool messages through ForceField before forwarding
    to the OpenAI API. Raises ``PromptBlockedError`` if a message is blocked.
    """

    def __init__(
        self,
        openai_api_key: Optional[str] = None,
        guard: Optional[Any] = None,
        **openai_kwargs: Any,
    ):
        try:
            import openai
        except ImportError:
            raise ImportError(
                "The 'openai' package is required for this integration. "
                "Install it with: pip install openai"
            )

        self._guard = guard or _get_guard()

        client_kwargs = dict(openai_kwargs)
        if openai_api_key:
            client_kwargs["api_key"] = openai_api_key
        self._client = openai.OpenAI(**client_kwargs)
        self.chat = _ChatProxy(self._client.chat, self._guard)

    def __getattr__(self, name: str) -> Any:
        if name == "chat":
            return self.chat
        return getattr(self._client, name)


def patch(guard: Optional[Any] = None) -> None:
    """Monkey-patch the global ``openai`` module so all chat completion
    calls are scanned through ForceField.

    Call ``unpatch()`` to restore original behavior.
    """
    global _original_create
    try:
        import openai
    except ImportError:
        raise ImportError("The 'openai' package is required. Install with: pip install openai")

    g = guard or _get_guard()

    if _original_create is not None:
        logger.warning("ForceField OpenAI patch already applied; skipping.")
        return

    _original_create = openai.resources.chat.completions.Completions.create

    def _patched_create(self_inner: Any, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages") or (args[0] if args else [])
        if messages:
            kwargs["messages"] = _scan_messages(list(messages), g)
        return _original_create(self_inner, **kwargs)

    openai.resources.chat.completions.Completions.create = _patched_create
    logger.info("ForceField: OpenAI chat.completions.create patched.")


def unpatch() -> None:
    """Restore the original ``openai.chat.completions.create``."""
    global _original_create
    if _original_create is None:
        return
    try:
        import openai
        openai.resources.chat.completions.Completions.create = _original_create
        _original_create = None
        logger.info("ForceField: OpenAI patch removed.")
    except ImportError:
        pass
