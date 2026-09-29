from __future__ import annotations

from typing import Any

from server.modules.utils.redactor import Redactor


def redact_ingestion_path(path: Any) -> str:
    """Redact query values from API paths before persistence or UI broadcast."""
    if path is None:
        return "/"
    value = str(path)
    if "?" in value:
        return Redactor.redact_url(value)
    return Redactor.redact_text(value)
