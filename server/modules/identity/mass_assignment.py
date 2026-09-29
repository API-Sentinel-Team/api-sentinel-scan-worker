"""Mass-assignment (BOPLA / OWASP API3:2023) detector.

A write endpoint is vulnerable to mass assignment when it lets a client set
internal/privileged fields it should never control. The motivating real case is
VAmPI's ``POST /users/v1/register``, which honors a client-supplied
``admin: true`` and escalates the new account to administrator.

Technique
---------
For each candidate privileged field, send ``base_payload`` augmented with that
field set to an escalated value (``True`` for boolean-ish names, ``"admin"`` for
``role``-like names). A hit is *deterministic*: the response must be a success
(2xx) AND the injected field name must appear in the response JSON with the
escalated value (or the response otherwise confirms the field was set). That is
the server accepting and reflecting privilege the caller injected.

Safety
------
This is a state-changing (write) test, so egress is gated by both
:class:`StateChangeGuard` (blocks writes unless ``allow_state_change``) and
:class:`TargetGuard` (scope/SSRF). A safety block returns a non-vulnerable
result with a ``skip_reason`` and never raises. Network errors are caught,
redacted, and returned as a non-vulnerable result.
"""
from __future__ import annotations

from typing import Any

import httpx

from server.modules.test_executor.state_change_guard import (
    StateChangeBlocked,
    StateChangeGuard,
)
from server.modules.test_executor.target_guard import (
    TargetGuard,
    TargetGuardError,
    endpoint_target_url,
)
from server.modules.utils.redactor import Redactor

DEFAULT_PRIVILEGED_FIELDS: list[str] = [
    "admin",
    "is_admin",
    "isAdmin",
    "role",
    "is_staff",
    "superuser",
    "account_id",
    "verified",
    "email_verified",
    "balance",
    "credits",
]

_SUCCESS_MIN, _SUCCESS_MAX = 200, 299

# Field names whose escalated value is a role string rather than a boolean.
_ROLE_FIELDS = {"role"}


def _escalated_value(field: str) -> Any:
    """The privileged value to inject for ``field``.

    ``role``-like fields escalate to the ``"admin"`` role; everything else is a
    boolean-ish privilege flag and escalates to ``True``.
    """
    if field.lower() in _ROLE_FIELDS:
        return "admin"
    return True


def _is_success(status_code: Any) -> bool:
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return False
    return _SUCCESS_MIN <= code <= _SUCCESS_MAX


def detect_privileged_reflection(
    response_body_json: Any,
    injected_field: str,
    escalated_value: Any,
) -> bool:
    """Pure check: does the response confirm the injected privileged field was set?

    Returns ``True`` when the response body (parsed JSON) contains the injected
    field name set to the escalated value — i.e. the server accepted and echoed
    the privilege the caller injected. Searches the top level and nested dicts/
    lists so wrappers like ``{"user": {...}}`` are handled. No network involved,
    so this is fully unit-testable.
    """
    if response_body_json is None:
        return False
    target = injected_field.lower()
    return _reflects(response_body_json, target, escalated_value)


def _reflects(node: Any, target_field: str, escalated_value: Any) -> bool:
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).lower() == target_field and _values_match(value, escalated_value):
                return True
            if _reflects(value, target_field, escalated_value):
                return True
        return False
    if isinstance(node, list):
        return any(_reflects(item, target_field, escalated_value) for item in node)
    return False


def _values_match(actual: Any, escalated_value: Any) -> bool:
    """Match the echoed value against the escalated value, tolerant of encodings.

    Handles booleans serialized as ``true``/``1``/``"true"`` and role strings
    compared case-insensitively, so a real server's echo still counts as a hit.
    """
    if isinstance(escalated_value, bool):
        if isinstance(actual, bool):
            return actual is escalated_value
        if isinstance(actual, (int, float)) and not isinstance(actual, bool):
            return bool(actual) is escalated_value
        if isinstance(actual, str):
            truthy = actual.strip().lower() in {"true", "1", "yes", "admin"}
            return truthy is escalated_value
        return False
    if isinstance(escalated_value, str):
        return isinstance(actual, str) and actual.strip().lower() == escalated_value.strip().lower()
    return actual == escalated_value


async def _http_request(
    method: str,
    url: str,
    headers: dict[str, Any],
    json_body: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    """Single HTTP egress point — tests monkeypatch this to stub the network."""
    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
        resp = await client.request(method=method, url=url, headers=headers, json=json_body)
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text,
            "url": str(resp.url),
        }


def _parse_body(response: dict[str, Any]) -> Any:
    """Best-effort JSON parse of a response body (dict already, or text)."""
    body = response.get("body")
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return body
    if isinstance(body, (bytes, bytearray)):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception:
            return None
    if isinstance(body, str):
        text = body.strip()
        if not text:
            return None
        import json

        try:
            return json.loads(text)
        except (ValueError, TypeError):
            return None
    return None


async def detect_mass_assignment(
    *,
    endpoint: dict,
    base_payload: dict,
    privileged_fields: list[str] | None = None,
    timeout: float = 10.0,
    target_guard=None,
    allow_state_change: bool = True,
) -> dict:
    """Probe a write endpoint for mass assignment (BOPLA / OWASP API3).

    ``endpoint`` is ``{"id","method","path","host","protocol"}`` with a write
    method (POST/PUT/PATCH). ``base_payload`` is the legitimate request body the
    endpoint expects (e.g. the registration fields); each privileged field is
    layered on top of it one at a time.

    Returns an engine-shaped dict. On a confirmed hit::

        {"is_vulnerable": True, "type": "MASS_ASSIGNMENT", "severity": "HIGH",
         "evidence": {"engine": "mass_assignment", "injected_field": <name>,
                      "status_code": <code>, "reflected": True}}

    No secrets or raw bodies are placed in evidence — only field names + status.
    Never raises: safety blocks return a ``skip_reason``; network errors return a
    redacted ``error``.
    """
    method = str(endpoint.get("method", "POST")).upper()
    fields = list(privileged_fields) if privileged_fields else list(DEFAULT_PRIVILEGED_FIELDS)

    # Mass assignment is inherently a write probe (POST/PUT/PATCH are all
    # "destructive" methods to the guard), so when the caller permits state
    # change we must also permit the destructive method; otherwise the guard
    # would block every mass-assignment test. When allow_state_change is False
    # the guard still blocks before any egress.
    state_guard = StateChangeGuard(
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_state_change,
    )
    try:
        state_guard.validate_request({"method": method, "headers": {}})
    except StateChangeBlocked as exc:
        return {
            "is_vulnerable": False,
            "skip_reason": "state_change_guard",
            "error": Redactor.redact_text(str(exc)),
        }

    guard = target_guard or TargetGuard.from_settings()
    url = endpoint_target_url(endpoint)
    try:
        guard.validate_url(url, base_url=url)
    except TargetGuardError as exc:
        return {
            "is_vulnerable": False,
            "skip_reason": "target_guard",
            "error": Redactor.redact_text(str(exc)),
        }

    base = dict(base_payload or {})
    try:
        for field in fields:
            escalated = _escalated_value(field)
            json_body = {**base, field: escalated}
            response = await _http_request(method, url, {}, json_body, timeout)
            if not _is_success(response.get("status_code")):
                continue
            parsed = _parse_body(response)
            if detect_privileged_reflection(parsed, field, escalated):
                return {
                    "is_vulnerable": True,
                    "type": "MASS_ASSIGNMENT",
                    "severity": "HIGH",
                    "evidence": {
                        "engine": "mass_assignment",
                        "injected_field": field,
                        "status_code": int(response.get("status_code")),
                        "reflected": True,
                    },
                }
    except Exception as exc:  # network/transport errors — never raise
        return {"is_vulnerable": False, "error": Redactor.redact_text(str(exc))}

    return {"is_vulnerable": False, "skip_reason": "no_mass_assignment"}
