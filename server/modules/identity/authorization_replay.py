from __future__ import annotations

import copy
import json
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

from server.models.core import TestAccount
from server.modules.identity.auth_rotator import AuthRotator
from server.modules.identity.role_keys import authorization_role_key
from server.modules.identity.test_account_secrets import TestAccountSecretCodec
from server.modules.pentest.target_policy import validated_pentest_evidence_scope
from server.modules.test_executor.evidence import (
    build_redacted_curl,
    evidence_digest,
    evidence_reproducibility_contract,
)
from server.modules.test_executor.response_validator import ResponseValidator
from server.modules.test_executor.state_change_guard import StateChangeGuard
from server.modules.utils.redactor import Redactor

_AUTH_HEADER_NAMES = {"authorization", "x-api-key", "x-auth-token", "cookie", "token", "x-access-token"}
_BOUNDARY_HEADER_NAMES = (
    "x-tenant-id",
    "x-tenant",
    "x-account-id",
    "x-org-id",
    "x-organization-id",
    "x-customer-id",
    "x-workspace-id",
    "x-role",
    "x-roles",
    "x-principal-id",
    "x-subject-id",
    "x-user-id",
    "x-user-role",
    "x-user-roles",
    "x-auth-role",
    "x-principal-role",
    "x-scope",
    "x-scopes",
    "x-oauth-scope",
    "x-oauth-scopes",
    "x-permission",
    "x-permissions",
)
_SUCCESS_MIN = 200
_SUCCESS_MAX = 299
_DEFAULT_AUTHZ_REMEDIATION = (
    "Enforce object and function-level authorization on every request using server-side ownership, tenant, "
    "and role checks. Deny by default when the authenticated principal does not own the object or lacks the "
    "required role."
)
_AUTHZ_EVIDENCE_COMPLETENESS_FIELDS = [
    "status",
    "matched_rule",
    "sent_request",
    "received_response",
    "similarity",
    "reproduction",
    "remediation",
]
_ANONYMOUS_ROLE_KEYS = {"ANONYMOUS", "UNAUTHENTICATED", "PUBLIC", "GUEST"}
_OWNERSHIP_FIELD_HINTS = (
    "id",
    "tenant",
    "owner",
    "account",
    "org",
    "organization",
    "customer",
    "workspace",
    "user",
)
_OBJECT_REFERENCE_HEADER_NAMES = {
    "x-tenant-id",
    "x-tenant",
    "x-account-id",
    "x-org-id",
    "x-organization-id",
    "x-customer-id",
    "x-workspace-id",
    "x-principal-id",
    "x-subject-id",
    "x-user-id",
}
_SENSITIVE_FIELD_HINTS = (
    "email",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "authorization",
    "auth",
    "cookie",
    "private_key",
)


def _body_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return value
        if isinstance(parsed, (dict, list)):
            return json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    return str(value)


def _status_code(response: dict[str, Any] | None) -> int:
    if not response:
        return 0
    value = response.get("status_code", response.get("status", response.get("response_code", 0)))
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _is_success(code: int) -> bool:
    return _SUCCESS_MIN <= code <= _SUCCESS_MAX


def _body_sha256(value: Any) -> str | None:
    body = _body_text(value)
    if not body:
        return None
    return sha256(body.encode("utf-8")).hexdigest()


def _response_summary(response: dict[str, Any] | None) -> dict[str, Any]:
    response = response or {}
    body = response.get("body")
    return {
        "status_code": _status_code(response),
        "headers": _redacted_response_headers(response),
        "body_sha256": _body_sha256(body),
        "body_length": len(_body_text(body)),
        "url": Redactor.redact_url(str(response["url"])) if response.get("url") else None,
    }


def _redacted_response_headers(response: dict[str, Any] | None) -> dict[str, str]:
    headers = (response or {}).get("headers")
    if not isinstance(headers, dict):
        return {}
    return {str(key): Redactor.REDACT_VALUE for key in sorted(headers.keys(), key=lambda item: str(item).lower())}


def _response_observation_metadata(
    *,
    original_response: dict[str, Any] | None,
    attacker_response: dict[str, Any] | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if isinstance(original_response, dict) and original_response.get("duration_ms") is not None:
        metadata["captured_response_duration_ms"] = original_response.get("duration_ms")
    if isinstance(attacker_response, dict) and attacker_response.get("duration_ms") is not None:
        metadata["replay_response_duration_ms"] = attacker_response.get("duration_ms")
    return metadata


def _redacted_identity_value(value: Any) -> str | None:
    if value is None:
        return None
    return Redactor.redact_text(str(value))


def authorization_identity_summary(account: TestAccount | None) -> dict[str, str | None]:
    """Return non-secret identity metadata suitable for evidence and API responses."""

    if account is None:
        return {"id": None, "role": None, "name": None}
    return {
        "id": _redacted_identity_value(getattr(account, "id", None)),
        "role": _redacted_identity_value(getattr(account, "role", None)),
        "name": _redacted_identity_value(getattr(account, "name", None)),
    }


def authorization_identity_label(account: TestAccount | None) -> str:
    """Return a short redacted identity label for generated descriptions."""

    summary = authorization_identity_summary(account)
    return summary.get("role") or summary.get("name") or summary.get("id") or "unknown"


def _is_anonymous_account(account: TestAccount | None) -> bool:
    return authorization_role_key(account) in _ANONYMOUS_ROLE_KEYS


def _replay_scope_validation(
    *,
    original_request: dict[str, Any],
    replay_request: dict[str, Any],
) -> dict[str, object]:
    target_url = str((original_request or {}).get("url") or "")
    replay_url = str((replay_request or {}).get("url") or target_url)
    _, scope_validation = validated_pentest_evidence_scope(replay_url, target_url=target_url)
    for key in ("target", "evidence_url"):
        if isinstance(scope_validation.get(key), str):
            scope_validation[key] = _redact_authorization_replay_url(scope_validation[key])
    return scope_validation


def auth_headers_for_account(account: TestAccount) -> dict[str, str]:
    """Return replayable auth headers for a configured test account."""

    auth_headers = TestAccountSecretCodec.auth_headers(account)
    if auth_headers:
        return auth_headers
    auth_token = TestAccountSecretCodec.auth_token(account)
    if auth_token:
        token = str(auth_token)
        if token.lower().startswith(("bearer ", "basic ")):
            return {"Authorization": token}
        return {"Authorization": f"Bearer {token}"}
    if _is_anonymous_account(account):
        return {"Authorization": ""}
    return {}


def build_replay_request(original_request: dict[str, Any], attacker: TestAccount) -> dict[str, Any]:
    """Replace all existing auth material on a captured request with attacker auth."""

    attacker_headers = auth_headers_for_account(attacker)
    replay_request = AuthRotator().apply_auth(copy.deepcopy(original_request or {}), attacker_headers)
    headers = replay_request.get("headers")
    if not isinstance(headers, dict):
        return replay_request

    attacker_boundary_headers = {
        str(key).strip().lower(): (key, value)
        for key, value in attacker_headers.items()
        if str(key).strip().lower() in _BOUNDARY_HEADER_NAMES and value not in (None, "")
    }
    attacker_auth_headers = {
        str(key).strip().lower(): (key, value)
        for key, value in attacker_headers.items()
        if str(key).strip().lower() in _AUTH_HEADER_NAMES and value not in (None, "")
    }
    cleaned_headers = {
        key: value
        for key, value in headers.items()
        if str(key).strip().lower() not in _BOUNDARY_HEADER_NAMES
        and str(key).strip().lower() not in _AUTH_HEADER_NAMES
        and value not in (None, "")
    }
    for _, (key, value) in attacker_auth_headers.items():
        cleaned_headers[key] = value
    for _, (key, value) in attacker_boundary_headers.items():
        cleaned_headers[key] = value
    replay_request["headers"] = cleaned_headers
    return replay_request


def build_authorization_replay_evidence(
    *,
    endpoint_id: str,
    issue_type: str | None,
    victim: TestAccount | None,
    attacker: TestAccount,
    original_request: dict[str, Any],
    original_response: dict[str, Any] | None,
    replay_request: dict[str, Any],
    attacker_response: dict[str, Any] | None,
    assessment: dict[str, Any],
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
) -> dict[str, Any]:
    """Build deterministic, redacted evidence for BOLA/BFLA authorization replay."""

    safe_original_request = _redact_replay_request(original_request)
    safe_replay_request = _redact_replay_request(replay_request)
    scope_validation = _replay_scope_validation(
        original_request=original_request,
        replay_request=replay_request,
    )
    matched_rule = _authorization_matched_rule(
        issue_type=issue_type,
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        replay_request=replay_request,
    )
    evidence: dict[str, Any] = {
        "engine": "authorization_replay",
        "issue_type": issue_type,
        "finding_status": _authorization_finding_status(issue_type=issue_type, assessment=assessment),
        "endpoint_id": endpoint_id,
        "identity_pair": {
            "victim": authorization_identity_summary(victim),
            "attacker": authorization_identity_summary(attacker),
        },
        "assessment": Redactor.redact_json(assessment),
        "matched_rule": matched_rule,
        "authorization_issue_classification": _authorization_issue_classification(
            issue_type=issue_type,
            victim=victim,
            attacker=attacker,
            matched_rule=matched_rule,
        ),
        "similarity": _authorization_similarity(assessment),
        "scope_validation": scope_validation,
        "safety_policies": _authorization_safety_policies(
            original_request=original_request,
            replay_request=replay_request,
            scope_validation=scope_validation,
            allow_state_change=allow_state_change,
            allow_destructive_methods=allow_destructive_methods,
        ),
        "captured_request": safe_original_request,
        "replay_request": safe_replay_request,
        "captured_response": _response_summary(original_response),
        "replay_response": _response_summary(attacker_response),
        "request_object_reference": _request_object_reference_summary(original_request),
        "response_diff": _authorization_response_diff(
            original_response=original_response,
            attacker_response=attacker_response,
            assessment=assessment,
            identity_boundary=matched_rule.get("identity_boundary")
            if isinstance(matched_rule.get("identity_boundary"), dict)
            else {},
        ),
    }
    identity_boundary = matched_rule.get("identity_boundary")
    if isinstance(identity_boundary, dict):
        boundary_coverage = _authorization_boundary_coverage(identity_boundary)
        if boundary_coverage:
            evidence["authorization_boundary_coverage"] = boundary_coverage

    observation_metadata = _response_observation_metadata(
        original_response=original_response,
        attacker_response=attacker_response,
    )
    if observation_metadata:
        evidence["observation_metadata"] = observation_metadata

    curl = build_redacted_curl(safe_replay_request)
    if curl:
        evidence["reproduction"] = {"curl": curl}

    evidence["remediation"] = Redactor.redact_text(_DEFAULT_AUTHZ_REMEDIATION)
    evidence["retest_support"] = _authorization_retest_support()
    evidence["evidence_completeness"] = _authorization_evidence_completeness(evidence)
    evidence["hash_algorithm"] = "sha256"
    evidence["evidence_reproducibility"] = evidence_reproducibility_contract(evidence)
    evidence["evidence_hash"] = evidence_digest(evidence)
    return evidence


def infer_victim_account(
    test_accounts: list[TestAccount],
    original_request: dict[str, Any] | None,
) -> TestAccount | None:
    """Best-effort match of captured request auth to a configured victim account."""

    request_headers = {
        str(key).lower(): str(value)
        for key, value in (original_request or {}).get("headers", {}).items()
        if str(key).lower() in _AUTH_HEADER_NAMES
    }
    if not request_headers:
        return None

    for account in test_accounts:
        for key, value in auth_headers_for_account(account).items():
            if request_headers.get(str(key).lower()) == str(value):
                return account
        auth_token = TestAccountSecretCodec.auth_token(account)
        if auth_token and any(str(auth_token) in header for header in request_headers.values()):
            return account
    return None


def evaluate_authorization_replay(
    original_response: dict[str, Any] | None,
    attacker_response: dict[str, Any] | None,
    *,
    body_similarity_threshold: float = 70.0,
    schema_similarity_threshold: float = 70.0,
    require_response_similarity: bool = True,
) -> dict[str, Any]:
    """Decide whether an auth-swapped replay proves unauthorized access."""

    validator = ResponseValidator()
    original_code = _status_code(original_response)
    attacker_code = _status_code(attacker_response)
    original_body = _body_text((original_response or {}).get("body"))
    attacker_body = _body_text((attacker_response or {}).get("body"))
    body_similarity = validator._percentage_match(original_body, attacker_body)
    schema_similarity = validator._percentage_match_schema(original_body, attacker_body)
    original_success = _is_success(original_code)
    attacker_success = _is_success(attacker_code)
    empty_success = not original_body and not attacker_body and original_success and attacker_success
    response_similar = body_similarity >= body_similarity_threshold or schema_similarity >= schema_similarity_threshold
    is_vulnerable = bool(
        original_success
        and attacker_success
        and (response_similar or empty_success or not require_response_similarity)
    )

    if is_vulnerable and (response_similar or empty_success):
        confidence = "HIGH"
        reason = "attacker received a successful response matching the victim response"
    elif is_vulnerable:
        confidence = "MEDIUM"
        reason = "attacker received a successful response, but response similarity was below threshold"
    elif not attacker_success:
        confidence = "LOW"
        reason = "attacker replay was denied"
    else:
        confidence = "LOW"
        reason = "attacker response did not meet replay evidence thresholds"

    return {
        "is_vulnerable": is_vulnerable,
        "access_granted": attacker_success,
        "original_status_code": original_code,
        "attacker_status_code": attacker_code,
        "similarity_pct": body_similarity,
        "schema_match_pct": schema_similarity,
        "response_similar": response_similar,
        "confidence": confidence,
        "reason": reason,
        "require_response_similarity": require_response_similarity,
        "body_similarity_threshold": body_similarity_threshold,
        "schema_similarity_threshold": schema_similarity_threshold,
    }


def _authorization_finding_status(*, issue_type: str | None, assessment: dict[str, Any]) -> str:
    if issue_type and assessment.get("is_vulnerable"):
        return "CONFIRMED"
    if assessment.get("access_granted") is False:
        return "DISPROVEN"
    return "UNCONFIRMED"


def _authorization_matched_rule(
    *,
    issue_type: str | None,
    victim: TestAccount | None,
    attacker: TestAccount,
    original_request: dict[str, Any] | None = None,
    replay_request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    victim_role = authorization_role_key(victim)
    attacker_role = authorization_role_key(attacker)
    metadata = {
        "rule_id": "authorization_replay_successful_cross_identity"
        if issue_type
        else "authorization_replay_cross_identity",
        "issue_type": issue_type,
        "victim_role": victim_role,
        "attacker_role": attacker_role,
    }
    boundary = _authorization_boundary_context(
        original_request=original_request,
        replay_request=replay_request,
    )
    if not boundary and victim_role and attacker_role and victim_role != attacker_role:
        boundary = {
            "boundary_kind": "cross_role",
            "same_boundary": False,
            "compared_fields": ["x-user-role"],
            "changed_fields": ["x-user-role"],
            "unchanged_fields": [],
            "inferred_from_identity_matrix": True,
        }
    if not boundary and _distinct_configured_identity(victim, attacker):
        boundary = {
            "boundary_kind": "identity_boundary_changed",
            "same_boundary": False,
            "compared_fields": ["x-principal-id"],
            "changed_fields": ["x-principal-id"],
            "unchanged_fields": [],
            "inferred_from_identity_matrix": True,
        }
    if boundary:
        metadata["identity_boundary"] = boundary
    redacted = Redactor.redact_json({key: value for key, value in metadata.items() if value not in (None, "")})
    return redacted if isinstance(redacted, dict) else {}


def _authorization_issue_classification(
    *,
    issue_type: str | None,
    victim: TestAccount | None,
    attacker: TestAccount,
    matched_rule: dict[str, Any],
) -> dict[str, Any]:
    boundary = matched_rule.get("identity_boundary") if isinstance(matched_rule, dict) else {}
    boundary = boundary if isinstance(boundary, dict) else {}
    compared_fields = _boundary_field_list(boundary.get("compared_fields"))
    changed_fields = _boundary_field_list(boundary.get("changed_fields"))
    boundary_kinds = _authorization_boundary_kinds(changed_fields)

    victim_role = authorization_role_key(victim)
    attacker_role = authorization_role_key(attacker)
    if victim_role and attacker_role and victim_role != attacker_role and "cross_role" not in boundary_kinds:
        boundary_kinds.append("cross_role")
    boundary_kinds = [
        kind
        for kind in (
            "cross_tenant",
            "cross_account",
            "cross_role",
            "cross_scope",
            "cross_permission",
            "identity_boundary_changed",
            "same_identity_boundary",
        )
        if kind in boundary_kinds
    ]

    issue_types: list[str] = []
    if set(boundary_kinds).intersection({"cross_tenant", "cross_account", "identity_boundary_changed"}):
        issue_types.append("BOLA")
    if set(boundary_kinds).intersection({"cross_role", "cross_scope", "cross_permission"}):
        issue_types.append("BFLA")
    if issue_type and issue_type not in issue_types:
        issue_types.append(issue_type)

    primary = issue_type or (issue_types[0] if issue_types else "AUTHORIZATION_REPLAY")
    has_object_boundary = "BOLA" in issue_types
    has_function_boundary = "BFLA" in issue_types
    if has_object_boundary and has_function_boundary:
        reason = "cross_identity_replay_with_object_and_function_boundaries"
    elif has_object_boundary:
        reason = "cross_identity_replay_with_object_boundary"
    elif has_function_boundary:
        reason = "cross_identity_replay_with_function_boundary"
    else:
        reason = "cross_identity_replay"

    classification = {
        "primary_issue_type": str(primary),
        "issue_types": [item for item in ("BOLA", "BFLA") if item in issue_types],
        "boundary_kinds": boundary_kinds,
        "boundary_field_count": len(compared_fields),
        "classification_reason": reason,
        "value_material_retained": False,
    }
    redacted = Redactor.redact_json(classification)
    return redacted if isinstance(redacted, dict) else classification


def _authorization_boundary_context(
    *,
    original_request: dict[str, Any] | None,
    replay_request: dict[str, Any] | None,
) -> dict[str, Any]:
    original_headers = _boundary_headers(original_request)
    replay_headers = _boundary_headers(replay_request)
    compared_fields: list[str] = []
    changed_fields: list[str] = []
    unchanged_fields: list[str] = []

    for key in _BOUNDARY_HEADER_NAMES:
        original_value = original_headers.get(key)
        replay_value = replay_headers.get(key)
        if original_value in (None, "") and replay_value in (None, ""):
            continue
        compared_fields.append(key)
        if str(original_value or "") == str(replay_value or ""):
            unchanged_fields.append(key)
        else:
            changed_fields.append(key)

    if not compared_fields:
        return {}

    return {
        "boundary_kind": _authorization_boundary_kind(changed_fields),
        "same_boundary": not changed_fields,
        "compared_fields": compared_fields,
        "changed_fields": changed_fields,
        "unchanged_fields": unchanged_fields,
    }


def _distinct_configured_identity(victim: TestAccount | None, attacker: TestAccount | None) -> bool:
    if victim is None or attacker is None:
        return False
    victim_id = str(getattr(victim, "id", "") or "").strip()
    attacker_id = str(getattr(attacker, "id", "") or "").strip()
    return bool(victim_id and attacker_id and victim_id != attacker_id)


def _authorization_boundary_coverage(boundary: dict[str, Any]) -> dict[str, Any]:
    compared_fields = _boundary_field_list(boundary.get("compared_fields"))
    changed_fields = _boundary_field_list(boundary.get("changed_fields"))
    unchanged_fields = _boundary_field_list(boundary.get("unchanged_fields"))
    if not compared_fields:
        return {}

    primary_kind = Redactor.redact_text(str(boundary.get("boundary_kind") or _authorization_boundary_kind(changed_fields)))
    boundary_kinds = _authorization_boundary_kinds(changed_fields)
    if primary_kind not in boundary_kinds:
        boundary_kinds.insert(0, primary_kind)

    return {
        "complete": True,
        "field_names_only": True,
        "value_material_retained": False,
        "primary_boundary_kind": primary_kind,
        "boundary_kinds": boundary_kinds,
        "compared_field_count": len(compared_fields),
        "changed_field_count": len(changed_fields),
        "unchanged_field_count": len(unchanged_fields),
        "compared_fields": compared_fields,
        "changed_fields": changed_fields,
        "unchanged_fields": unchanged_fields,
    }


def _authorization_response_diff(
    *,
    original_response: dict[str, Any] | None,
    attacker_response: dict[str, Any] | None,
    assessment: dict[str, Any],
    identity_boundary: dict[str, Any],
) -> dict[str, Any]:
    captured_status = _status_code(original_response)
    replay_status = _status_code(attacker_response)
    captured_headers = _normalized_response_headers(original_response)
    replay_headers = _normalized_response_headers(attacker_response)
    captured_header_fields = set(captured_headers)
    replay_header_fields = set(replay_headers)
    common_header_fields = sorted(captured_header_fields & replay_header_fields)
    changed_header_fields = [
        field
        for field in common_header_fields
        if str(captured_headers.get(field) or "") != str(replay_headers.get(field) or "")
    ]

    captured_body_fields = set(_response_body_field_paths(original_response))
    replay_body_fields = set(_response_body_field_paths(attacker_response))
    all_body_fields = sorted(captured_body_fields | replay_body_fields)
    captured_only_body_fields = sorted(captured_body_fields - replay_body_fields)
    replay_only_body_fields = sorted(replay_body_fields - captured_body_fields)

    changed_boundary_fields = _boundary_field_list(identity_boundary.get("changed_fields"))
    boundary_kinds = _authorization_boundary_kinds(changed_boundary_fields)

    diff = {
        "status": {
            "captured_status_code": captured_status,
            "replay_status_code": replay_status,
            "changed": captured_status != replay_status,
            "both_successful": _is_success(captured_status) and _is_success(replay_status),
        },
        "headers": {
            "captured_only": sorted(captured_header_fields - replay_header_fields),
            "replay_only": sorted(replay_header_fields - captured_header_fields),
            "common_fields": common_header_fields,
            "changed_fields": changed_header_fields,
            "changed": bool(
                captured_header_fields - replay_header_fields
                or replay_header_fields - captured_header_fields
                or changed_header_fields
            ),
            "value_material_retained": False,
        },
        "body_schema": {
            "schema_match_pct": assessment.get("schema_match_pct"),
            "captured_only": captured_only_body_fields,
            "replay_only": replay_only_body_fields,
            "common_fields": sorted(captured_body_fields & replay_body_fields),
            "changed": bool(captured_only_body_fields or replay_only_body_fields),
            "value_material_retained": False,
        },
        "object_ownership": _response_field_summary(all_body_fields, _is_object_ownership_field),
        "sensitive_fields": _response_field_summary(all_body_fields, _is_sensitive_response_field),
        "identity_boundary": {
            "boundary_kinds": boundary_kinds,
            "boundary_labels": [f"{_authorization_boundary_kind([field])}:{field}" for field in changed_boundary_fields],
            "changed_fields": changed_boundary_fields,
            "value_material_retained": False,
        },
    }
    redacted = Redactor.redact_json(diff)
    return redacted if isinstance(redacted, dict) else diff


def _request_object_reference_summary(request: dict[str, Any] | None) -> dict[str, Any]:
    references = _request_object_references(request)
    location_counts: dict[str, int] = {}
    for reference in references:
        location = str(reference.get("location") or "unknown")
        location_counts[location] = location_counts.get(location, 0) + 1

    return {
        "observed": bool(references),
        "field_names_only": True,
        "value_material_retained": False,
        "reference_count": len(references),
        "location_counts": {key: location_counts[key] for key in sorted(location_counts)},
        "references": references[:50],
        "reference_report_truncated": len(references) > 50,
    }


def _request_object_references(request: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(request, dict):
        return []
    references: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add_reference(location: str, name: str, value: Any) -> None:
        if value in (None, ""):
            return
        value_text = _body_text(value)
        fingerprint = sha256(value_text.encode("utf-8")).hexdigest()
        key = (location, name, fingerprint)
        if key in seen:
            return
        seen.add(key)
        references.append(
            {
                "location": location,
                "name": Redactor.redact_text(name)[:120],
                "value_sha256": fingerprint,
            }
        )

    parsed = urlparse(str(request.get("url") or ""))
    for index, segment in enumerate([item for item in parsed.path.split("/") if item], start=1):
        add_reference("path", f"segment[{index}]", unquote(segment))

    for name, value in parse_qsl(parsed.query, keep_blank_values=False):
        normalized_name = str(name).strip()
        if normalized_name and _is_object_ownership_field(normalized_name):
            add_reference("query", normalized_name, value)

    headers = request.get("headers")
    if isinstance(headers, dict):
        for raw_name, value in headers.items():
            normalized_name = str(raw_name).strip().lower()
            if normalized_name in _OBJECT_REFERENCE_HEADER_NAMES:
                add_reference("header", normalized_name, value)

    for field, value in _request_body_object_reference_values(request.get("body")):
        add_reference("body", field, value)

    return sorted(references, key=lambda item: (str(item["location"]), str(item["name"]), str(item["value_sha256"])))


def _request_body_object_reference_values(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    parsed = _response_body_json(value)
    if isinstance(parsed, dict):
        items: list[tuple[str, Any]] = []
        for key, item in parsed.items():
            key_text = str(key).strip()
            if not key_text:
                continue
            field = f"{prefix}.{key_text}" if prefix else key_text
            if _is_object_ownership_field(field):
                items.append((field, item))
            items.extend(_request_body_object_reference_values(item, field))
        return items
    if isinstance(parsed, list):
        items: list[tuple[str, Any]] = []
        for item in parsed[:20]:
            items.extend(_request_body_object_reference_values(item, prefix))
        return items
    return []


def _normalized_response_headers(response: dict[str, Any] | None) -> dict[str, str]:
    headers = (response or {}).get("headers")
    if not isinstance(headers, dict):
        return {}
    return {
        str(key).strip().lower(): str(value)
        for key, value in headers.items()
        if str(key).strip()
    }


def _response_body_field_paths(response: dict[str, Any] | None) -> list[str]:
    body = _response_body_json((response or {}).get("body"))
    return sorted(_json_field_paths(body))


def _response_body_json(body: Any) -> Any:
    if isinstance(body, str):
        try:
            return json.loads(body)
        except (TypeError, ValueError):
            return None
    return body


def _json_field_paths(value: Any, prefix: str = "") -> set[str]:
    if isinstance(value, dict):
        fields: set[str] = set()
        for key, item in value.items():
            key_text = str(key).strip()
            if not key_text:
                continue
            path = f"{prefix}.{key_text}" if prefix else key_text
            nested = _json_field_paths(item, path)
            if nested:
                fields.update(nested)
            else:
                fields.add(path)
        return fields
    if isinstance(value, list):
        fields: set[str] = set()
        for item in value:
            fields.update(_json_field_paths(item, prefix))
        if fields:
            return fields
    return {prefix} if prefix else set()


def _response_field_summary(fields: list[str], predicate: Any) -> dict[str, Any]:
    matched = [field for field in fields if predicate(field)]
    return {
        "observed": bool(matched),
        "field_names": matched,
        "field_count": len(matched),
        "value_material_retained": False,
    }


def _is_object_ownership_field(field: str) -> bool:
    leaf = field.rsplit(".", 1)[-1].lower()
    normalized = leaf.replace("-", "_")
    if _is_sensitive_response_field(field) and normalized not in {"user_id", "owner_id", "tenant_id"}:
        return False
    return normalized == "id" or any(hint in normalized for hint in _OWNERSHIP_FIELD_HINTS)


def _is_sensitive_response_field(field: str) -> bool:
    leaf = field.rsplit(".", 1)[-1].lower()
    normalized = leaf.replace("-", "_")
    return any(hint in normalized for hint in _SENSITIVE_FIELD_HINTS)


def _boundary_field_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    fields: list[str] = []
    for item in value:
        if item is None:
            continue
        normalized = str(item).strip().lower()
        if normalized in _BOUNDARY_HEADER_NAMES and normalized not in fields:
            fields.append(Redactor.redact_text(normalized))
    return fields


def _redact_replay_request(request: dict[str, Any] | None) -> dict[str, Any]:
    redacted = Redactor.redact_http_message(request) or {}
    if redacted.get("url"):
        redacted["url"] = _redact_authorization_replay_url(str(redacted["url"]))
    headers = redacted.get("headers")
    if isinstance(headers, dict):
        for key in list(headers.keys()):
            if str(key).strip().lower() in _BOUNDARY_HEADER_NAMES:
                headers[key] = Redactor.REDACT_VALUE
    if "body" in redacted:
        redacted["body"] = _redact_request_object_reference_body(redacted.get("body"))
    return redacted


def _redact_authorization_replay_url(url: str) -> str:
    redacted = Redactor.redact_url(str(url))
    parsed = urlparse(redacted)
    if not parsed.path:
        return redacted
    segments = [
        Redactor.REDACT_VALUE if _path_segment_requires_redaction(unquote(segment)) else segment
        for segment in parsed.path.split("/")
    ]
    return parsed._replace(path="/".join(segments)).geturl()


def _path_segment_requires_redaction(segment: str) -> bool:
    lowered = str(segment or "").lower()
    return any(marker in lowered for marker in ("secret", "token", "password", "passwd", "api_key", "apikey", "cookie"))


def _redact_request_object_reference_body(value: Any, prefix: str = "") -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            field = f"{prefix}.{key_text}" if prefix else key_text
            if _is_object_ownership_field(field):
                redacted[key] = Redactor.REDACT_VALUE
            else:
                redacted[key] = _redact_request_object_reference_body(item, field)
        return redacted
    if isinstance(value, list):
        return [_redact_request_object_reference_body(item, prefix) for item in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return Redactor.redact_text(value)
        redacted = _redact_request_object_reference_body(parsed, prefix)
        return json.dumps(redacted, sort_keys=True)
    return value


def _boundary_headers(request: dict[str, Any] | None) -> dict[str, str]:
    headers = (request or {}).get("headers")
    if not isinstance(headers, dict):
        return {}
    return {
        str(key).strip().lower(): str(value)
        for key, value in headers.items()
        if str(key).strip().lower() in _BOUNDARY_HEADER_NAMES and value not in (None, "")
    }


def _authorization_boundary_kind(changed_keys: list[str]) -> str:
    if not changed_keys:
        return "same_identity_boundary"
    if any("tenant" in key for key in changed_keys):
        return "cross_tenant"
    if any(key in {"x-account-id", "x-org-id", "x-organization-id", "x-customer-id", "x-workspace-id"} for key in changed_keys):
        return "cross_account"
    if any("role" in key for key in changed_keys):
        return "cross_role"
    if any("scope" in key for key in changed_keys):
        return "cross_scope"
    if any("permission" in key for key in changed_keys):
        return "cross_permission"
    return "identity_boundary_changed"


def _authorization_boundary_kinds(changed_keys: list[str]) -> list[str]:
    if not changed_keys:
        return ["same_identity_boundary"]

    kinds: list[str] = []
    if any("tenant" in key for key in changed_keys):
        kinds.append("cross_tenant")
    if any(
        key in {"x-account-id", "x-org-id", "x-organization-id", "x-customer-id", "x-workspace-id"}
        for key in changed_keys
    ):
        kinds.append("cross_account")
    if any("role" in key for key in changed_keys):
        kinds.append("cross_role")
    if any("scope" in key for key in changed_keys):
        kinds.append("cross_scope")
    if any("permission" in key for key in changed_keys):
        kinds.append("cross_permission")
    return kinds or ["identity_boundary_changed"]


def _authorization_similarity(assessment: dict[str, Any]) -> dict[str, Any]:
    metadata = {
        "similarity_pct": assessment.get("similarity_pct"),
        "schema_match_pct": assessment.get("schema_match_pct"),
        "body_similarity_threshold": assessment.get("body_similarity_threshold"),
        "schema_similarity_threshold": assessment.get("schema_similarity_threshold"),
    }
    redacted = Redactor.redact_json({key: value for key, value in metadata.items() if value is not None})
    return redacted if isinstance(redacted, dict) else {}


def _authorization_safety_policies(
    *,
    original_request: dict[str, Any],
    replay_request: dict[str, Any],
    scope_validation: dict[str, Any],
    allow_state_change: bool,
    allow_destructive_methods: bool,
) -> dict[str, Any]:
    replay_url = str((replay_request or {}).get("url") or "")
    base_url = str((original_request or {}).get("url") or replay_url)
    method = str((replay_request or {}).get("method") or "GET").upper()
    policies = {
        "target_guard_policy": {
            "policy": "target_guard",
            "blocked": False,
            "url": _redact_authorization_replay_url(replay_url),
            "base_url": _redact_authorization_replay_url(base_url),
            "scope": scope_validation.get("scope"),
        },
        "state_change_policy": {
            "policy": "state_change_guard",
            "method": method,
            "destructive_method": StateChangeGuard.is_destructive_method(method),
            "allow_state_change": bool(allow_state_change),
            "allow_destructive_methods": bool(allow_destructive_methods),
        },
    }
    redacted = Redactor.redact_scan_result({"safety_policies": policies}).get("safety_policies")
    return redacted if isinstance(redacted, dict) else {}


def _authorization_evidence_completeness(evidence: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "status": bool(evidence.get("finding_status")),
        "matched_rule": bool(evidence.get("matched_rule")),
        "sent_request": _has_replay_request(evidence.get("replay_request")),
        "received_response": _has_replay_response(evidence.get("replay_response")),
        "similarity": bool(evidence.get("similarity")),
        "reproduction": bool((evidence.get("reproduction") or {}).get("curl")),
        "remediation": bool(evidence.get("remediation")),
    }
    present = [field for field in _AUTHZ_EVIDENCE_COMPLETENESS_FIELDS if checks[field]]
    missing = [field for field in _AUTHZ_EVIDENCE_COMPLETENESS_FIELDS if not checks[field]]
    return {
        "complete": not missing,
        "required": list(_AUTHZ_EVIDENCE_COMPLETENESS_FIELDS),
        "present": present,
        "missing": missing,
    }


def _authorization_retest_support() -> dict[str, Any]:
    return {
        "supported": True,
        "queued_scan_supported": True,
        "manual_outcome_supported": True,
        "reason": "authorization_replay_matrix_available",
        "missing_fields": [],
    }


def _has_replay_request(value: Any) -> bool:
    return isinstance(value, dict) and bool(value.get("method")) and bool(value.get("url"))


def _has_replay_response(value: Any) -> bool:
    return isinstance(value, dict) and bool(value.get("status_code"))


def _authorization_boundary_issue_type(
    *,
    original_request: dict[str, Any] | None,
    replay_request: dict[str, Any] | None,
) -> str | None:
    boundary = _authorization_boundary_context(
        original_request=original_request,
        replay_request=replay_request,
    )
    changed_fields = _boundary_field_list(boundary.get("changed_fields"))
    if not changed_fields:
        return None

    boundary_kinds = set(_authorization_boundary_kinds(changed_fields))
    if boundary_kinds.intersection({"cross_role", "cross_scope", "cross_permission"}):
        return "BFLA"
    return "BOLA"


def classify_authorization_issue(
    *,
    victim: TestAccount | None,
    attacker: TestAccount,
    assessment: dict[str, Any],
    original_request: dict[str, Any] | None = None,
    replay_request: dict[str, Any] | None = None,
) -> str | None:
    if not assessment.get("is_vulnerable"):
        return None
    if victim is not None and getattr(victim, "id", None) == getattr(attacker, "id", None):
        return None
    victim_role = authorization_role_key(victim)
    attacker_role = authorization_role_key(attacker)
    if victim_role and attacker_role and victim_role != attacker_role:
        return "BFLA"
    boundary_issue_type = _authorization_boundary_issue_type(
        original_request=original_request,
        replay_request=replay_request,
    )
    if boundary_issue_type:
        return boundary_issue_type
    return "BOLA"
