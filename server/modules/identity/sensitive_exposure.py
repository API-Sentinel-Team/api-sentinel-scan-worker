"""Detect API endpoints that expose sensitive data (credential / bulk-PII dumps).

Motivating real case: VAmPI's ``GET /users/v1/_debug`` returns ALL users
INCLUDING password fields, with no auth. This detector fetches an endpoint and
scans the JSON response for:

  * sensitive FIELD NAMES (password, token, secret, ...) anywhere in the body
    (recursively, including inside lists), and
  * "bulk PII exposure" -- a list/array of >=3 objects each carrying an email or
    username, i.e. a mass data dump even when no credential fields are present.

Only FIELD NAMES are ever persisted in evidence -- never raw values or bodies.
"""
from __future__ import annotations

from typing import Any

import httpx

from server.modules.test_executor.target_guard import (
    TargetGuard,
    TargetGuardError,
    endpoint_target_url,
)
from server.modules.utils.redactor import Redactor

# Field names that, if present, mean sensitive data is being exposed.
SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "ssn",
    "credit_card",
}
# Field names that, in bulk, indicate a mass PII dump even without credentials.
_PII_HANDLE_NAMES = {"email", "username"}
# Strong-signal credential field names -> HIGH severity.
_CREDENTIAL_FIELD_NAMES = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
}
_BULK_PII_THRESHOLD = 3


def _is_sensitive_key(key: str) -> bool:
    return str(key).strip().lower() in SENSITIVE_FIELD_NAMES


def _is_pii_handle_key(key: str) -> bool:
    return str(key).strip().lower() in _PII_HANDLE_NAMES


def _walk(node: Any, found: set[str]) -> None:
    """Recursively collect sensitive field names from a JSON-like structure."""
    if isinstance(node, dict):
        for key, value in node.items():
            if _is_sensitive_key(key):
                found.add(str(key).strip().lower())
            _walk(value, found)
    elif isinstance(node, list):
        for item in node:
            _walk(item, found)


def _largest_pii_list(node: Any) -> int:
    """Return the size of the largest list of objects that each carry PII handles.

    Used to detect bulk dumps (mass data exposure) independent of credentials.
    """
    best = 0
    if isinstance(node, list):
        pii_objects = 0
        for item in node:
            if isinstance(item, dict) and any(
                _is_pii_handle_key(k) for k in item.keys()
            ):
                pii_objects += 1
        best = max(best, pii_objects)
        for item in node:
            best = max(best, _largest_pii_list(item))
    elif isinstance(node, dict):
        for value in node.values():
            best = max(best, _largest_pii_list(value))
    return best


def _count_records(node: Any) -> int:
    """Best-effort count of records exposed by the body (largest list seen)."""
    best = 0
    if isinstance(node, list):
        best = max(best, len(node))
        for item in node:
            best = max(best, _count_records(item))
    elif isinstance(node, dict):
        for value in node.values():
            best = max(best, _count_records(value))
    return best


def scan_sensitive_fields(body_json: Any) -> dict:
    """Pure, network-free scan of a parsed JSON body for sensitive exposure.

    Returns ``{"sensitive_fields": [...], "record_count": N, "has_credentials": bool}``.

    ``sensitive_fields`` is a sorted, de-duplicated list of sensitive field
    NAMES found. When a bulk-PII dump is detected (a list of >=3 objects each
    carrying an email/username), the synthetic field name ``"bulk_pii"`` is
    included so callers can render evidence. ``has_credentials`` is True when any
    credential-grade field (password/secret/token/...) is present.
    """
    found: set[str] = set()
    _walk(body_json, found)

    has_credentials = bool(found & _CREDENTIAL_FIELD_NAMES)

    bulk_pii_count = _largest_pii_list(body_json)
    if bulk_pii_count >= _BULK_PII_THRESHOLD:
        found.add("bulk_pii")

    record_count = _count_records(body_json)

    return {
        "sensitive_fields": sorted(found),
        "record_count": record_count,
        "has_credentials": has_credentials,
    }


async def _http_get(url: str, headers: dict, timeout: float) -> dict:
    """Perform the GET request. Isolated so tests can monkeypatch the network."""
    async with httpx.AsyncClient(verify=True, timeout=timeout) as client:
        response = await client.get(url, headers=headers)
    try:
        body = response.json()
    except Exception:
        body = response.text
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": body,
        "url": str(response.url),
    }


async def detect_sensitive_exposure(
    *,
    endpoint: dict,
    timeout: float = 10.0,
    target_guard=None,
) -> dict:
    """Detect a sensitive-data-exposure (credential / bulk-PII dump) endpoint.

    ``endpoint`` is a mapping like
    ``{"id","method","path","host","protocol"}``. The endpoint is fetched with a
    GET request and its JSON body scanned. Only field NAMES are returned as
    evidence; raw values and bodies are never persisted. Never raises.
    """
    url = endpoint_target_url(endpoint)
    guard = target_guard or TargetGuard.from_settings()

    try:
        guard.validate_url(url, base_url=url)
    except TargetGuardError as exc:
        return {
            "is_vulnerable": False,
            "skip_reason": "target_guard",
            "error": Redactor.redact_text(str(exc)),
        }

    try:
        result = await _http_get(url, {}, timeout)
    except Exception as exc:  # network errors, etc. -- never raise.
        return {
            "is_vulnerable": False,
            "error": Redactor.redact_text(str(exc)),
        }

    status_code = result.get("status_code")
    body = result.get("body")

    scan = scan_sensitive_fields(body)
    sensitive_fields = scan["sensitive_fields"]

    if not sensitive_fields:
        return {
            "is_vulnerable": False,
            "skip_reason": "no_sensitive_exposure",
            "status_code": status_code,
        }

    severity = "HIGH" if scan["has_credentials"] else "MEDIUM"
    return {
        "is_vulnerable": True,
        "type": "SENSITIVE_DATA_EXPOSURE",
        "severity": severity,
        "evidence": {
            "engine": "sensitive_exposure",
            "exposed_fields": sensitive_fields,
            "record_count": scan["record_count"],
            "status_code": status_code,
        },
    }
