"""Business-logic abuse probes: OTP spam and coupon reuse detection.

These probes exercise rate-limit and deduplication controls on endpoints that
handle one-time operations.  They are READ-safe where possible (dry-run / probe
flows) but may POST to test flows — always guarded by TargetGuard and the
allow_state_change flag.

OTP-spam probe
--------------
Fires the same OTP-request endpoint N times in rapid succession.  A
vulnerable endpoint returns 2xx on every attempt with no rate-limit response
(429 / 400 / "already sent" body hint).  Sends no destructive payload; the
target can discard the OTPs without consequence.

Coupon-abuse probe
------------------
Applies the same coupon-style payload twice to a checkout/discount endpoint.
If both attempts succeed with 2xx and no "already used" body hint, the
endpoint likely lacks per-user or per-coupon deduplication.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from server.modules.test_executor.target_guard import (
    TargetGuard,
    TargetGuardError,
    endpoint_target_url,
)
from server.modules.utils.redactor import Redactor

# ── path pattern detection ─────────────────────────────────────────────────
_OTP_PATH_RE = re.compile(
    r"/(otp|mfa|2fa|verify|verification|sms|phone|code|pin|totp)(/|$)",
    re.IGNORECASE,
)
_COUPON_PATH_RE = re.compile(
    r"/(coupon|promo|discount|voucher|redeem|apply|cart|checkout|order)(/|$)",
    re.IGNORECASE,
)

# Responses that indicate server-side protection is active.
_RATE_LIMIT_BODY_HINTS = {"too many", "rate limit", "already sent", "wait", "throttl"}
_COUPON_USED_HINTS = {"already used", "already applied", "invalid", "expired", "used coupon"}

# Number of rapid-fire requests for OTP-spam probe.
_OTP_BURST = 3


async def _http_post(url: str, body: dict, headers: dict | None, timeout: float) -> dict:
    """POST with JSON body; isolated for monkeypatching in tests."""
    async with httpx.AsyncClient(verify=True) as client:
        response = await client.post(url, json=body, headers=headers or {}, timeout=timeout)
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "url": str(response.url),
        }


def _body_hints_protection(body: str, hints: set[str]) -> bool:
    lowered = body.lower()
    return any(hint in lowered for hint in hints)


def _is_success(status_code: int) -> bool:
    return 200 <= status_code < 300


async def detect_otp_spam(
    *,
    endpoint: dict[str, Any],
    probe_payload: dict[str, Any] | None = None,
    burst_count: int = _OTP_BURST,
    timeout: float = 8.0,
    target_guard: Any = None,
    headers: dict | None = None,
    allow_state_change: bool = False,
) -> dict[str, Any]:
    """Probe an OTP/verification endpoint for missing rate limiting.

    Fires ``burst_count`` identical requests.  If every response is 2xx with
    no rate-limit body hint, the endpoint is flagged as OTP_SPAM_POSSIBLE.

    Returns a standard engine-shaped dict.
    """
    if not allow_state_change:
        return {"is_vulnerable": False, "skip_reason": "state_change_not_armed"}

    path = str(endpoint.get("path") or endpoint.get("url") or "")
    if not _OTP_PATH_RE.search(path):
        return {"is_vulnerable": False, "skip_reason": "not_an_otp_endpoint"}

    guard = target_guard or TargetGuard.from_settings()
    base_url = endpoint_target_url(endpoint)

    try:
        guard.validate_url(base_url, base_url=base_url)
    except TargetGuardError as exc:
        return {"is_vulnerable": False, "skip_reason": "target_guard",
                "error": Redactor.redact_text(str(exc))}

    payload = probe_payload or {"phone": "+15550000000"}

    try:
        responses = await asyncio.gather(*[
            _http_post(base_url, payload, headers, timeout)
            for _ in range(burst_count)
        ])
    except Exception as exc:
        return {"is_vulnerable": False, "error": Redactor.redact_text(str(exc))}

    success_count = sum(1 for r in responses if _is_success(r.get("status_code", 0)))
    rate_limited = any(
        r.get("status_code") == 429
        or _body_hints_protection(r.get("body") or "", _RATE_LIMIT_BODY_HINTS)
        for r in responses
    )

    if success_count == burst_count and not rate_limited:
        return {
            "is_vulnerable": True,
            "type": "BUSINESS_LOGIC:OTP_SPAM",
            "severity": "MEDIUM",
            "evidence": {
                "engine": "business_abuse_probe",
                "sub_type": "otp_spam",
                "burst_count": burst_count,
                "success_count": success_count,
                "rate_limited": False,
            },
        }

    return {"is_vulnerable": False, "skip_reason": "rate_limit_present_or_not_all_success"}


async def detect_coupon_reuse(
    *,
    endpoint: dict[str, Any],
    probe_payload: dict[str, Any] | None = None,
    timeout: float = 8.0,
    target_guard: Any = None,
    headers: dict | None = None,
    allow_state_change: bool = False,
) -> dict[str, Any]:
    """Probe a coupon/discount endpoint for missing per-use deduplication.

    Applies the same coupon code twice.  Both 2xx + no "already used" hint
    signals a missing deduplication control.
    """
    if not allow_state_change:
        return {"is_vulnerable": False, "skip_reason": "state_change_not_armed"}

    path = str(endpoint.get("path") or endpoint.get("url") or "")
    if not _COUPON_PATH_RE.search(path):
        return {"is_vulnerable": False, "skip_reason": "not_a_coupon_endpoint"}

    guard = target_guard or TargetGuard.from_settings()
    base_url = endpoint_target_url(endpoint)

    try:
        guard.validate_url(base_url, base_url=base_url)
    except TargetGuardError as exc:
        return {"is_vulnerable": False, "skip_reason": "target_guard",
                "error": Redactor.redact_text(str(exc))}

    payload = probe_payload or {"coupon_code": "SENTINEL_PROBE_10OFF"}

    try:
        first = await _http_post(base_url, payload, headers, timeout)
        second = await _http_post(base_url, payload, headers, timeout)
    except Exception as exc:
        return {"is_vulnerable": False, "error": Redactor.redact_text(str(exc))}

    first_ok = _is_success(first.get("status_code", 0))
    second_ok = _is_success(second.get("status_code", 0))
    second_blocked = _body_hints_protection(second.get("body") or "", _COUPON_USED_HINTS)

    if first_ok and second_ok and not second_blocked:
        return {
            "is_vulnerable": True,
            "type": "BUSINESS_LOGIC:COUPON_REUSE",
            "severity": "MEDIUM",
            "evidence": {
                "engine": "business_abuse_probe",
                "sub_type": "coupon_reuse",
                "first_status": first.get("status_code"),
                "second_status": second.get("status_code"),
                "deduplication_present": False,
            },
        }

    return {"is_vulnerable": False, "skip_reason": "deduplication_present_or_first_failed"}
