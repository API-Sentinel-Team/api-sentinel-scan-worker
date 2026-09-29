from __future__ import annotations

import re
from typing import Any

from server.modules.utils.redactor import Redactor


_SECRET_ASSIGNMENT_RE = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|cookie)\s*=\s*\*+")
_ROLE_KEY_SEPARATOR_RE = re.compile(r"[^A-Za-z0-9]+")


def _redacted_role_value(value: Any) -> str | None:
    if value is None:
        return None
    return Redactor.redact_text(str(value))


def authorization_role_key(account: Any | None) -> str | None:
    """Return a stable role key for authorization lookup, classification, and fingerprints."""

    if account is None:
        return None
    role_value = account.get("role") if isinstance(account, dict) else getattr(account, "role", None)
    role = _redacted_role_value(role_value)
    if not role:
        return None
    role = _SECRET_ASSIGNMENT_RE.sub("", role)
    role = _ROLE_KEY_SEPARATOR_RE.sub("_", role).strip("_").upper()
    return role or None
