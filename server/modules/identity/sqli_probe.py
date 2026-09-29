"""Error-based SQL injection probe for a single path/query parameter.

Motivating real case: VAmPI passes the ``username`` path param straight into a
raw SQL query, so injecting a single quote yields a database error
(error-based SQLi). This probe mutates one injection point with a small set of
boundary-breaking payloads and flags ONLY when the response carries a known SQL
error signature — deterministic and low false-positive (no status-only or
length-diff heuristics).

The probe is READ-only: it issues GET (or the endpoint's given non-destructive
method) requests and never sends destructive payloads, so no state-change guard
is required. Every mutated URL is validated against the :class:`TargetGuard`
before any traffic is sent.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from server.modules.test_executor.target_guard import (
    TargetGuard,
    TargetGuardError,
    endpoint_target_url,
)
from server.modules.utils.redactor import Redactor

# Boundary-breaking payloads, tried in order; first signature hit wins. These are
# READ-safe (no UNION/DROP/etc.) — they only try to break out of a quoted string
# so a raw-SQL backend emits a parse/operational error.
_PAYLOADS = ["'", '"', "' OR '1'='1", "1' OR '1'='1"]

# Case-insensitive SQL error signatures. A match in the body (optionally with a
# 5xx status) is treated as a confirmed error-based SQLi.
_SIGNATURES = [
    "sqlite3.OperationalError",
    "OperationalError",
    "SQL syntax",
    "syntax error",
    "unrecognized token",
    "psycopg2",
    "mysql_fetch",
    "ORA-0",
    "SQLITE_ERROR",
    'near "',
]

# Templated/placeholder path segments we treat as the injection point.
_PLACEHOLDERS = {"1", "id", "{id}"}


def match_sql_error(body: str, status_code: int) -> str | None:
    """Return the matched SQL error signature, or ``None``.

    Pure and network-free so it is unit-testable in isolation. Matching is
    case-insensitive; a 5xx status is allowed but never required (the signature
    itself is the deterministic signal).
    """
    if not body:
        return None
    haystack = body.lower()
    for signature in _SIGNATURES:
        if signature.lower() in haystack:
            return signature
    return None


def _is_placeholder_segment(seg: str) -> bool:
    return (seg.startswith("{") and seg.endswith("}")) or seg in _PLACEHOLDERS


def _build_injection_url(
    base_url: str, payload: str, inject_segment: str | None
) -> str:
    """Mutate one injection point of ``base_url`` with ``payload``.

    Priority:
      1. If ``inject_segment`` is given, replace that exact path segment.
      2. Otherwise replace the first templated/placeholder path segment.
      3. If none found, append the payload as a new last path segment, or — when
         the path already ends in a slash — fall back to a ``?q=<payload>`` query
         parameter.
    """
    encoded = quote(payload, safe="")
    parts = urlsplit(base_url)
    segments = parts.path.split("/")

    substituted = False
    for index, seg in enumerate(segments):
        if not seg:
            continue
        if inject_segment is not None:
            if seg == inject_segment:
                segments[index] = encoded
                substituted = True
                break
        elif _is_placeholder_segment(seg):
            segments[index] = encoded
            substituted = True
            break

    if substituted:
        new_path = "/".join(segments)
        return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))

    # No injection segment found — append as last path segment, unless the path
    # ends in a slash, in which case use a query parameter.
    if parts.path.endswith("/"):
        new_query = parts.query
        q_param = f"q={encoded}"
        new_query = f"{new_query}&{q_param}" if new_query else q_param
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    segments.append(encoded)
    new_path = "/".join(segments)
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))


async def _http_get(url: str, headers: dict | None, timeout: float) -> dict:
    """Issue a single GET and return a normalized response dict.

    Isolated at module level so tests can monkeypatch it without any network.
    """
    async with httpx.AsyncClient(verify=True) as client:
        response = await client.get(url, headers=headers or {}, timeout=timeout)
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "url": str(response.url),
        }


async def detect_error_based_sqli(
    *,
    endpoint: dict,
    inject_segment: str | None = None,
    timeout: float = 10.0,
    target_guard=None,
    headers: dict | None = None,
) -> dict:
    """Probe one endpoint parameter for error-based SQL injection.

    ``endpoint`` is ``{"id","method","path","host","protocol"}``. Each payload's
    mutated URL is validated through the :class:`TargetGuard` before any request;
    a guard rejection yields ``skip_reason="target_guard"`` with no traffic sent.

    Returns an engine-shaped dict. On a confirmed hit::

        {"is_vulnerable": True, "type": "SQLI", "severity": "HIGH",
         "evidence": {"engine": "sqli_probe", "matched_signature": <sig>,
                      "status_code": <code>, "payload": <payload>}}

    On no hit after all payloads: ``{"is_vulnerable": False,
    "skip_reason": "no_sqli_signature"}``. Network errors never raise; they
    return ``{"is_vulnerable": False, "error": <redacted>}``.
    """
    guard = target_guard or TargetGuard.from_settings()
    base_url = endpoint_target_url(endpoint)
    method = str(endpoint.get("method", "GET")).upper()

    try:
        for payload in _PAYLOADS:
            url = _build_injection_url(base_url, payload, inject_segment)
            try:
                guard.validate_url(url, base_url=base_url)
            except TargetGuardError as exc:
                return {
                    "is_vulnerable": False,
                    "skip_reason": "target_guard",
                    "error": Redactor.redact_text(str(exc)),
                }

            response = await _http_get(url, headers, timeout)
            body = response.get("body") or ""
            status_code = response.get("status_code")
            signature = match_sql_error(body, status_code)
            if signature is not None:
                return {
                    "is_vulnerable": True,
                    "type": "SQLI",
                    "severity": "HIGH",
                    "evidence": {
                        "engine": "sqli_probe",
                        "matched_signature": signature,
                        "status_code": status_code,
                        "payload": payload,
                    },
                }
    except Exception as exc:  # never raise; redact any network/error detail
        return {"is_vulnerable": False, "error": Redactor.redact_text(str(exc))}

    return {"is_vulnerable": False, "skip_reason": "no_sqli_signature"}


# Boolean-based SQLi: true-condition payload should behave like baseline;
# false-condition payload should return a detectably different response.
_BOOL_TRUE_PAYLOADS = ["1' AND '1'='1", "1 AND 1=1"]
_BOOL_FALSE_PAYLOADS = ["1' AND '1'='2", "1 AND 1=2"]

# Minimum relative response-size difference to call "different".
_BOOL_SIZE_DELTA_RATIO = 0.15


async def detect_boolean_based_sqli(
    *,
    endpoint: dict,
    inject_segment: str | None = None,
    timeout: float = 10.0,
    target_guard=None,
    headers: dict | None = None,
) -> dict:
    """Probe for boolean-based blind SQL injection.

    Fires three requests per parameter injection point:
      1. Baseline (original URL)
      2. TRUE condition  → should return same size as baseline
      3. FALSE condition → should return notably different size than baseline

    A finding is raised only when BOTH conditions hold, making this
    deterministic and low-false-positive.  Never sends destructive payloads.
    """
    guard = target_guard or TargetGuard.from_settings()
    base_url = endpoint_target_url(endpoint)

    try:
        # Baseline request.
        try:
            guard.validate_url(base_url, base_url=base_url)
        except TargetGuardError as exc:
            return {"is_vulnerable": False, "skip_reason": "target_guard",
                    "error": Redactor.redact_text(str(exc))}

        baseline = await _http_get(base_url, headers, timeout)
        baseline_len = len(baseline.get("body") or "")
        if baseline.get("status_code", 0) >= 400:
            # Baseline itself errors → can't distinguish boolean response
            return {"is_vulnerable": False, "skip_reason": "baseline_error"}

        for true_payload, false_payload in zip(_BOOL_TRUE_PAYLOADS, _BOOL_FALSE_PAYLOADS):
            true_url = _build_injection_url(base_url, true_payload, inject_segment)
            false_url = _build_injection_url(base_url, false_payload, inject_segment)

            # Guard both before any traffic.
            for url in (true_url, false_url):
                try:
                    guard.validate_url(url, base_url=base_url)
                except TargetGuardError as exc:
                    return {"is_vulnerable": False, "skip_reason": "target_guard",
                            "error": Redactor.redact_text(str(exc))}

            true_resp = await _http_get(true_url, headers, timeout)
            false_resp = await _http_get(false_url, headers, timeout)

            true_len = len(true_resp.get("body") or "")
            false_len = len(false_resp.get("body") or "")

            # TRUE condition: status and size similar to baseline.
            # FALSE condition: size differs by at least the threshold ratio.
            true_similar = abs(true_len - baseline_len) <= max(10, baseline_len * 0.1)
            if baseline_len > 0:
                delta = abs(false_len - baseline_len) / baseline_len
            else:
                delta = 1.0 if false_len != baseline_len else 0.0
            false_different = delta >= _BOOL_SIZE_DELTA_RATIO

            # Also check for SQL error signatures on either payload response
            # (error-based fallthrough for blind probes).
            true_sig = match_sql_error(true_resp.get("body") or "", true_resp.get("status_code", 0))
            false_sig = match_sql_error(false_resp.get("body") or "", false_resp.get("status_code", 0))

            if true_sig or false_sig:
                return {
                    "is_vulnerable": True,
                    "type": "SQLI",
                    "severity": "HIGH",
                    "evidence": {
                        "engine": "sqli_probe",
                        "sub_type": "boolean_error_fallthrough",
                        "matched_signature": true_sig or false_sig,
                        "payload": true_payload if true_sig else false_payload,
                    },
                }

            if true_similar and false_different:
                return {
                    "is_vulnerable": True,
                    "type": "SQLI",
                    "severity": "HIGH",
                    "evidence": {
                        "engine": "sqli_probe",
                        "sub_type": "boolean_based",
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "baseline_body_length": baseline_len,
                        "true_body_length": true_len,
                        "false_body_length": false_len,
                        "size_delta_ratio": round(delta, 3),
                    },
                }

    except Exception as exc:
        return {"is_vulnerable": False, "error": Redactor.redact_text(str(exc))}

    return {"is_vulnerable": False, "skip_reason": "no_boolean_sqli_signal"}
