from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

_TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def normalize_template_ids(values: Iterable[Any] | None, *, limit: int = 100) -> list[str]:
    return _normalize_values(
        values,
        field_name="template_ids",
        pattern=_TEMPLATE_ID_RE,
        limit=limit,
        lowercase=False,
    )


def normalize_tags(values: Iterable[Any] | None, *, limit: int = 50) -> list[str]:
    return _normalize_values(
        values,
        field_name="tags",
        pattern=_TAG_RE,
        limit=limit,
        lowercase=True,
    )


def normalize_severities(values: Iterable[Any] | None, *, limit: int = 5) -> list[str]:
    normalized = _normalize_values(
        values,
        field_name="severity",
        pattern=_TAG_RE,
        limit=limit,
        lowercase=True,
    )
    invalid = [item for item in normalized if item not in _SEVERITIES]
    if invalid:
        raise ValueError(f"severity contains unsupported value: {invalid[0]}")
    return normalized


def safe_template_filename(template_id: Any, fallback: Any) -> str:
    raw = str(template_id or fallback or "custom-template").strip()
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")
    if not slug or "/" in slug or "\\" in slug:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(fallback or "custom-template")).strip("._-")
    return f"{(slug or 'custom-template')[:96]}.yaml"


def _normalize_values(
    values: Iterable[Any] | None,
    *,
    field_name: str,
    pattern: re.Pattern[str],
    limit: int,
    lowercase: bool,
) -> list[str]:
    if isinstance(values, str):
        items = [values]
    else:
        items = list(values or [])
    if len(items) > limit:
        raise ValueError(f"{field_name} may contain at most {limit} entries")

    normalized: list[str] = []
    seen: set[str] = set()
    for raw in items:
        value = str(raw or "").strip()
        if not value:
            continue
        value = value.lower() if lowercase else value
        if not pattern.fullmatch(value):
            raise ValueError(f"{field_name} contains unsupported value: {value[:80]}")
        dedupe_key = value.lower()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        normalized.append(value)
    return normalized
