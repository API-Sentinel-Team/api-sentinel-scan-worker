"""Multi-identity BOLA/BFLA replay against a live target.

This is the recall lever the benchmark identified: generic templates cannot
*confirm* an authorization bug because proving one requires replaying one
identity's request with another identity's credentials and diffing the
responses. This module does exactly that against a live endpoint, reusing the
existing evidence-grade evaluation in :mod:`authorization_replay`.

Flow for one endpoint + (victim, attacker) identity pair:

  1. issue the VICTIM request (victim's auth) -> original_request / response
  2. build the ATTACKER replay (swap in attacker's auth) via build_replay_request
  3. execute the attacker request
  4. evaluate_authorization_replay -> is_vulnerable + confidence + BOLA/BFLA class
  5. build redacted, hashed evidence with a curl repro

All network egress goes through TargetGuard; state-changing replays go through
StateChangeGuard. A safety block returns a non-vulnerable result, never raises.
"""
from __future__ import annotations

from typing import Any

import httpx

from server.models.core import TestAccount
from server.modules.identity.authorization_replay import (
    auth_headers_for_account,
    build_authorization_replay_evidence,
    build_replay_request,
    classify_authorization_issue,
    evaluate_authorization_replay,
)
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


async def _execute(request: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
        resp = await client.request(
            method=request.get("method", "GET"),
            url=request["url"],
            headers=request.get("headers", {}),
            content=request.get("body") or None,
        )
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text,
            "url": str(resp.url),
        }


_AUTH_HEADER_NAMES = {"authorization", "x-api-key", "x-auth-token", "cookie", "token", "x-access-token"}
_SUCCESS_MIN, _SUCCESS_MAX = 200, 299
_CONTROL_SIMILARITY_THRESHOLD = 70.0


def _anonymous_request(original_request: dict[str, Any]) -> dict[str, Any]:
    """Strip all auth material to probe whether the resource is publicly readable."""
    headers = {
        key: value
        for key, value in (original_request.get("headers") or {}).items()
        if str(key).strip().lower() not in _AUTH_HEADER_NAMES
    }
    return {**original_request, "headers": headers}


def _status(response: dict[str, Any] | None) -> int:
    try:
        return int((response or {}).get("status_code") or 0)
    except (TypeError, ValueError):
        return 0


def _control_indicates_public(
    original_response: dict[str, Any] | None, control_response: dict[str, Any] | None
) -> bool:
    """True when the no-auth control returns the same data the victim sees.

    That means the endpoint is public, so cross-identity 'access' is not an
    authorization-boundary violation — suppress the BOLA/BFLA finding.
    """
    control_code = _status(control_response)
    if not (_SUCCESS_MIN <= control_code <= _SUCCESS_MAX):
        return False  # anonymous request was denied -> access IS gated -> real finding

    from server.modules.test_executor.response_validator import ResponseValidator

    validator = ResponseValidator()
    original_body = str((original_response or {}).get("body") or "")
    control_body = str((control_response or {}).get("body") or "")
    similarity = validator._percentage_match(original_body, control_body)
    schema = validator._percentage_match_schema(original_body, control_body)
    # Empty-but-successful (e.g. 204) also counts as publicly accessible.
    if not original_body and not control_body:
        return True
    return similarity >= _CONTROL_SIMILARITY_THRESHOLD or schema >= _CONTROL_SIMILARITY_THRESHOLD


def _victim_request(endpoint: dict[str, Any], victim: TestAccount) -> dict[str, Any]:
    return {
        "method": str(endpoint.get("method", "GET")).upper(),
        "url": _victim_object_url(endpoint, victim),
        "headers": dict(auth_headers_for_account(victim)),
        "body": endpoint.get("last_request_body") or "",
    }


def _victim_object_url(endpoint: dict[str, Any], victim: TestAccount) -> str:
    """Build a URL targeting an object the VICTIM owns.

    Correct BOLA setup: the victim legitimately accesses their own resource, then
    the attacker replays the same request. So a templated id segment (``{...}`` or
    a placeholder) is filled with the victim's own identifier (their name), giving
    a request the victim is authorized for. The attacker replaying it and getting
    the same resource back is the vulnerability.
    """
    base = endpoint_target_url(endpoint)
    victim_id = str(getattr(victim, "name", "") or "").strip()
    if not victim_id:
        return base

    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(base)
    segments = parts.path.split("/")
    substituted = []
    for seg in segments:
        if (seg.startswith("{") and seg.endswith("}")) or seg in {"1", "id", "{id}"}:
            substituted.append(victim_id)
        else:
            substituted.append(seg)
    new_path = "/".join(substituted)
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))


async def run_multi_identity_replay(
    *,
    endpoint: dict[str, Any],
    victim: TestAccount,
    attacker: TestAccount,
    target_guard: TargetGuard | None = None,
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Replay an endpoint across two identities and return a confirmation result.

    Returns a dict shaped like an engine result: ``is_vulnerable`` plus the rich
    authorization-replay evidence/assessment. Confirms BOLA (same role) or BFLA
    (privileged victim, lower-priv attacker) when the attacker gets the victim's
    resource back.
    """
    guard = target_guard or TargetGuard.from_settings()
    state_guard = StateChangeGuard(
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )

    original_request = _victim_request(endpoint, victim)
    replay_request = build_replay_request(original_request, attacker)

    # Safety gates first — same guards the deterministic engine uses.
    try:
        guard.validate_url(replay_request["url"], base_url=original_request["url"])
        state_guard.validate_request(replay_request)
    except TargetGuardError as exc:
        return {"is_vulnerable": False, "skip_reason": "target_guard", "error": Redactor.redact_text(str(exc))}
    except StateChangeBlocked as exc:
        return {"is_vulnerable": False, "skip_reason": "state_change_guard", "error": Redactor.redact_text(str(exc))}

    try:
        original_response = await _execute(original_request, timeout=timeout)
        attacker_response = await _execute(replay_request, timeout=timeout)
        # Control: an unauthenticated request to the same resource. If anonymous
        # access ALSO succeeds with the same data, the endpoint is public — not an
        # authorization bug. This is the key false-positive killer (identical
        # responses across identities only matter if access is actually gated).
        control_response = await _execute(_anonymous_request(original_request), timeout=timeout)
    except Exception as exc:
        return {"is_vulnerable": False, "error": Redactor.redact_text(str(exc))}

    assessment = evaluate_authorization_replay(original_response, attacker_response)
    public_access = _control_indicates_public(original_response, control_response)
    assessment = {
        **assessment,
        "control_status_code": _status(control_response),
        "control_indicates_public": public_access,
    }

    reclassified_type: str | None = None
    if assessment.get("is_vulnerable") and public_access:
        # The no-auth control succeeded with matching data: this is NOT a
        # cross-identity authorization bug — the endpoint is unauthenticated. That
        # is still a real, often more severe finding, so we RECLASSIFY it as
        # broken authentication / unauthenticated sensitive-data exposure rather
        # than silently dropping it.
        assessment = {
            **assessment,
            "is_vulnerable": True,
            "reason": "endpoint returns the resource with NO authentication "
            "(no-auth control returned matching data) — missing authentication, "
            "not a cross-identity authorization boundary violation",
            "reclassified_from": "authorization_replay",
        }
        reclassified_type = "BROKEN_AUTH"
        issue_type = "BROKEN_AUTH"
    else:
        issue_type = classify_authorization_issue(victim=victim, attacker=attacker, assessment=assessment)

    evidence = build_authorization_replay_evidence(
        endpoint_id=str(endpoint.get("id") or ""),
        issue_type=issue_type,
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )

    if reclassified_type == "BROKEN_AUTH":
        severity = "HIGH"  # unauthenticated sensitive-data exposure
    else:
        severity = "HIGH" if assessment.get("confidence") == "HIGH" else "MEDIUM"

    return {
        "is_vulnerable": bool(assessment.get("is_vulnerable")),
        "type": reclassified_type or issue_type or "BOLA",
        "severity": severity,
        "confidence": assessment.get("confidence"),
        "assessment": assessment,
        "evidence": evidence,
    }


def pick_identity_pair(
    accounts: list[TestAccount],
    *,
    issue: str = "BOLA",
) -> tuple[TestAccount, TestAccount] | None:
    """Choose a (victim, attacker) pair from configured test accounts.

    BOLA: two distinct same-or-any-role accounts (cross-object access).
    BFLA: a privileged victim and a lower-privilege attacker (function access).
    Returns None when no suitable pair exists.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    usable = [
        a for a in accounts
        if auth_headers_for_account(a)
        and str(getattr(a, "status", "ACTIVE") or "ACTIVE").upper() == "ACTIVE"
        and (getattr(a, "expired_at", None) is None or getattr(a, "expired_at") > now)
    ]
    if len(usable) < 2:
        return None

    privileged = {"ADMIN", "OWNER", "ROOT", "SUPERADMIN", "SUPER_ADMIN", "PLATFORM_ADMIN"}
    if issue.upper() == "BFLA":
        priv = [a for a in usable if str(a.role or "").upper() in privileged]
        low = [a for a in usable if str(a.role or "").upper() not in privileged]
        if priv and low:
            return priv[0], low[0]
        # No clear privilege boundary — still worth a cross-identity replay; the
        # issue is classified BOLA-vs-BFLA post-hoc from roles by the evaluator.
        return usable[0], usable[1]

    # BOLA: any two distinct identities.
    return usable[0], usable[1]
