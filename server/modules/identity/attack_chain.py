"""Multi-step attack-chain executor: capture an ID, then reuse it cross-identity.

Single-request replay can only confirm "attacker can access the resource the
request already names". Real BOLA often needs two steps:

  Step 1 (capture):  as the VICTIM, call a source endpoint that RETURNS object
                     ids (e.g. GET /users -> [{id: 42}, ...]). Capture a real id.
  Step 2 (reuse):    as the ATTACKER, call a target endpoint that CONSUMES that
                     id kind (e.g. GET /users/{id}) with the captured id.
  Control:           an unauthenticated request to the same target. If anon also
                     succeeds, it is missing-auth (BROKEN_AUTH), not cross-object
                     BOLA — same false-positive killer as single-step replay.

This turns the knowledge graph's *static* chains() (source exposes K, target
consumes K) into *executed* attack journeys with real captured state. It reuses
the multi_identity_replay primitives (execution, no-auth control, evidence) so a
confirmed chain finding has the same evidence grade as a single-step finding.
"""
from __future__ import annotations

import json
import re
from typing import Any

from server.models.core import TestAccount
from server.modules.identity.authorization_replay import (
    auth_headers_for_account,
    evaluate_authorization_replay,
)
from server.modules.identity.multi_identity_replay import (
    _anonymous_request,
    _control_indicates_public,
    _execute,
    _status,
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

# Field names whose values are object identifiers worth reusing across endpoints.
_ID_FIELD_RE = re.compile(r"(^id$|_id$|^uuid$|guid|^[a-z]*id$)", re.IGNORECASE)
# Names that act as object handles even without an "id" suffix (REST APIs often
# key resources by username/slug/name/handle rather than a numeric id). Ordered
# by how likely they are to be a routable path identifier (username/slug first,
# email last — emails are rarely path segments).
_HANDLE_FIELD_ORDER = ["username", "user", "slug", "handle", "name", "key", "title", "email"]
_HANDLE_FIELD_NAMES = set(_HANDLE_FIELD_ORDER)


def capture_object_ids(response: dict[str, Any] | None, id_kind: str | None = None) -> list[str]:
    """Pull candidate object-id values from a (list or object) JSON response body.

    Walks the body for fields that look like identifiers (``*_id``, ``uuid``) AND
    common resource handles (``username``, ``slug``, ``name``, ...), since many
    REST APIs address objects by handle, not a numeric id. Deterministic and
    side-effect free; values returned most-specific (id-like) first.
    """
    body = (response or {}).get("body")
    if not body:
        return []
    try:
        data = json.loads(body) if isinstance(body, str) else body
    except (ValueError, TypeError):
        return []

    id_like: list[str] = []
    handle_by_name: dict[str, list[str]] = {name: [] for name in _HANDLE_FIELD_ORDER}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                key_str = str(key)
                low = key_str.strip().lower()
                if isinstance(value, (str, int)) and _ID_FIELD_RE.search(key_str):
                    id_like.append(str(value))
                elif isinstance(value, (str, int)) and low in _HANDLE_FIELD_NAMES:
                    handle_by_name[low].append(str(value))
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node[:50]:
                walk(item)

    walk(data)
    # id-like first, then handles in routable-likelihood order (username before email).
    found = list(id_like)
    for name in _HANDLE_FIELD_ORDER:
        found.extend(handle_by_name[name])
    # De-dup, preserve order.
    seen: set[str] = set()
    ordered = []
    for v in found:
        if v not in seen:
            seen.add(v)
            ordered.append(v)
    return ordered


def _fill_target_url(target_endpoint: dict[str, Any], object_id: str) -> str:
    """Substitute a captured id into the target endpoint's templated/placeholder seg."""
    from urllib.parse import urlsplit, urlunsplit

    base = endpoint_target_url(target_endpoint)
    parts = urlsplit(base)
    segments = []
    substituted = False
    for seg in parts.path.split("/"):
        if (seg.startswith("{") and seg.endswith("}")) or seg in {"1", "id", "{id}"}:
            segments.append(object_id)
            substituted = True
        else:
            segments.append(seg)
    if not substituted:
        # No templated segment — append the id (best effort for /resource style).
        if not parts.path.endswith("/"):
            segments.append(object_id)
        else:
            segments[-1] = object_id
    new_path = "/".join(segments)
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))


async def run_attack_chain(
    *,
    source_endpoint: dict[str, Any],
    target_endpoint: dict[str, Any],
    victim: TestAccount,
    attacker: TestAccount,
    id_kind: str | None = None,
    target_guard: TargetGuard | None = None,
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Execute a 2-step capture->reuse chain and return a confirmation result.

    Returns an engine-shaped dict: ``is_vulnerable`` plus the chain assessment and
    redacted evidence. ``is_vulnerable`` is True only when the attacker accesses
    the victim-owned captured object AND an unauthenticated control is denied
    (otherwise the target is public -> reclassified BROKEN_AUTH).
    """
    guard = target_guard or TargetGuard.from_settings()
    state_guard = StateChangeGuard(
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )

    # ── Step 1: capture an object id as the victim ────────────────────────────
    source_request = {
        "method": str(source_endpoint.get("method", "GET")).upper(),
        "url": endpoint_target_url(source_endpoint),
        "headers": dict(auth_headers_for_account(victim)),
        "body": source_endpoint.get("last_request_body") or "",
    }
    try:
        guard.validate_url(source_request["url"], base_url=source_request["url"])
    except TargetGuardError as exc:
        return _blocked("target_guard", exc)
    try:
        source_response = await _execute(source_request, timeout=timeout)
    except Exception as exc:
        return _blocked("source_execution_error", exc, vulnerable=False)

    object_ids = capture_object_ids(source_response, id_kind)
    if not object_ids:
        return {
            "is_vulnerable": False,
            "skip_reason": "no_object_id_captured",
            "chain": {"step1_status": _status(source_response), "captured_ids": 0},
        }
    object_id = object_ids[0]

    # ── Step 2: reuse the captured id as the attacker ─────────────────────────
    target_url = _fill_target_url(target_endpoint, object_id)
    target_method = str(target_endpoint.get("method", "GET")).upper()
    victim_target_request = {
        "method": target_method,
        "url": target_url,
        "headers": dict(auth_headers_for_account(victim)),
        "body": target_endpoint.get("last_request_body") or "",
    }
    attacker_target_request = {
        "method": target_method,
        "url": target_url,
        "headers": dict(auth_headers_for_account(attacker)),
        "body": target_endpoint.get("last_request_body") or "",
    }

    try:
        guard.validate_url(target_url, base_url=source_request["url"])
        state_guard.validate_request(attacker_target_request)
    except TargetGuardError as exc:
        return _blocked("target_guard", exc)
    except StateChangeBlocked as exc:
        return _blocked("state_change_guard", exc)

    try:
        victim_target_response = await _execute(victim_target_request, timeout=timeout)
        attacker_target_response = await _execute(attacker_target_request, timeout=timeout)
        control_response = await _execute(_anonymous_request(victim_target_request), timeout=timeout)
    except Exception as exc:
        return _blocked("target_execution_error", exc, vulnerable=False)

    assessment = evaluate_authorization_replay(victim_target_response, attacker_target_response)
    public_access = _control_indicates_public(victim_target_response, control_response)

    chain_meta = {
        "engine": "attack_chain",
        "steps": 2,
        "source_endpoint_id": str(source_endpoint.get("id") or ""),
        "target_endpoint_id": str(target_endpoint.get("id") or ""),
        "id_kind": id_kind,
        "captured_id": Redactor.redact_text(object_id),
        "step1_status": _status(source_response),
        "victim_target_status": _status(victim_target_response),
        "attacker_target_status": _status(attacker_target_response),
        "control_status": _status(control_response),
        "control_indicates_public": public_access,
        "similarity_pct": assessment.get("similarity_pct"),
    }

    if assessment.get("is_vulnerable") and public_access:
        return {
            "is_vulnerable": True,
            "type": "BROKEN_AUTH",
            "severity": "HIGH",
            "confidence": assessment.get("confidence"),
            "chain": {**chain_meta, "reason": "target object is unauthenticated (no-auth control matched)"},
        }

    issue_type = "BOLA"
    victim_role = str(getattr(victim, "role", "") or "").upper()
    attacker_role = str(getattr(attacker, "role", "") or "").upper()
    if assessment.get("is_vulnerable") and victim_role and attacker_role and victim_role != attacker_role:
        issue_type = "BFLA"

    return {
        "is_vulnerable": bool(assessment.get("is_vulnerable")),
        "type": issue_type,
        "severity": "HIGH" if assessment.get("confidence") == "HIGH" else "MEDIUM",
        "confidence": assessment.get("confidence"),
        "chain": chain_meta,
    }


def _blocked(reason: str, exc: Exception, *, vulnerable: bool = False) -> dict[str, Any]:
    return {
        "is_vulnerable": vulnerable,
        "skip_reason": reason,
        "error": Redactor.redact_text(str(exc)),
    }
