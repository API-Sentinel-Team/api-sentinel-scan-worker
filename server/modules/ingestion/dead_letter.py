from __future__ import annotations

import json
import re
from typing import Any

from server.modules.utils.redactor import Redactor

_HEADER_KEYS = {"headers", "request_headers", "response_headers"}
_SENSITIVE_KEY_PARTS = {"password", "secret", "token", "key", "auth", "cvv", "credit_card", "cookie"}
_SENSITIVE_ERROR_FIELD_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
        ['"]?
        (?:password|passwd|secret|token|api[_-]?key|x-api-key|cookie|set-cookie)
        ['"]?
        \s*[:=]\s*
    )
    ['"]?
    (?P<value>[^'",\s}\]]+)
    """,
)


def _redact(value: Any, *, parent_key: str | None = None) -> Any:
    if isinstance(value, dict):
        if parent_key and parent_key.lower() in _HEADER_KEYS:
            return Redactor.redact_headers(value)

        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(part in key_text for part in _SENSITIVE_KEY_PARTS):
                redacted[key] = Redactor.REDACT_VALUE
            else:
                redacted[key] = _redact(item, parent_key=str(key))
        return redacted

    if isinstance(value, list):
        return [_redact(item, parent_key=parent_key) for item in value]

    if isinstance(value, str):
        return Redactor.redact_text(value)

    return value


def redact_dead_letter_payload(payload: Any) -> Any:
    """Keep dead-letter payloads reproducible without preserving credentials."""
    return _redact(payload)


def redact_dead_letter_error(message: Any) -> str:
    """Redact exception text before storing it on jobs or dead letters."""
    errors = getattr(message, "errors", None)
    if callable(errors):
        try:
            message = json.dumps(errors(include_input=False), default=str)
        except TypeError:
            message = json.dumps(errors(), default=str)

    redacted = _SENSITIVE_ERROR_FIELD_RE.sub(
        lambda match: f"{match.group('prefix')}{Redactor.REDACT_VALUE}",
        str(message),
    )
    return Redactor.redact_text(redacted)
