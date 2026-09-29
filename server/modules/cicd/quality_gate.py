from __future__ import annotations

import hashlib
import hmac
import json
from typing import Iterable

from server.config import settings
from server.models.core import TestResult, TestRun
from server.modules.pentest.execution_artifacts import (
    artifact_content_governance_summary,
    verify_execution_artifact_payload,
)
from server.modules.utils.redactor import Redactor
from server.modules.vulnerability_detector.lifecycle import (
    confirmation_result_from_evidence,
    verify_vulnerability_evidence,
)

_DEFAULT_FAIL_ON = ("CRITICAL", "HIGH")
_TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELED"}
_IN_PROGRESS_STATUSES = {"PENDING", "DISPATCHED", "RUNNING", "CANCEL_REQUESTED"}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
_REQUIRED_STATE_CHANGE_POLICY_FIELDS = (
    "allow_state_change",
    "allow_destructive_methods",
    "destructive_method",
)
_REQUIRED_AUTH_SCOPE_POLICY_FIELDS = (
    "blocked",
    "url",
    "base_url",
    "reason",
    "scope_domains_configured",
    "scope_domain_count",
)
_AUTHORIZATION_BOUNDARY_KIND_VALUES = {
    "same_identity_boundary",
    "cross_tenant",
    "cross_account",
    "cross_role",
    "cross_scope",
    "cross_permission",
    "identity_boundary_changed",
}
_AUTHORIZATION_BOUNDARY_FIELD_KEYS = (
    "compared_boundary_fields",
    "changed_boundary_fields",
    "unchanged_boundary_fields",
)
_AUTHORIZATION_REPLAY_ISSUE_TYPES = {"BOLA", "BFLA"}
_AUTHORIZATION_BOLA_BOUNDARY_KINDS = {"cross_tenant", "cross_account", "identity_boundary_changed"}
_AUTHORIZATION_BFLA_BOUNDARY_KINDS = {"cross_role", "cross_scope", "cross_permission"}
_LLM_SIGNAL_FAMILY_ACCEPTED_SIGNALS = {
    "prompt_injection": {
        "PROMPT_INJECTION",
        "PROMPT_INJECTION_ATTEMPT",
        "PROMPT_INJECTION_SUCCESS",
        "SYSTEM_PROMPT_LEAKAGE",
        "LLM_SECRET_EXPOSURE",
    },
    "rag_exfiltration": {"RAG_EXFILTRATION", "LLM_RAG_EXFILTRATION"},
    "indirect_prompt_injection": {"INDIRECT_PROMPT_INJECTION", "LLM_INDIRECT_PROMPT_INJECTION"},
    "dangerous_tool_invocation": {"DANGEROUS_TOOL_INVOCATION", "LLM_DANGEROUS_TOOL_INVOCATION"},
    "privilege_escalating_tool_invocation": {
        "PRIVILEGE_ESCALATING_TOOL_INVOCATION",
        "LLM_PRIVILEGE_ESCALATING_TOOL_INVOCATION",
    },
    "tool_chain_injection": {"TOOL_CHAIN_PROMPT_INJECTION", "LLM_TOOL_CHAIN_PROMPT_INJECTION"},
}
_LLM_SIGNAL_FAMILY_MARKERS = (
    ("tool_chain_injection", ("TOOL_CHAIN_PROMPT_INJECTION", "TOOL_CHAIN_INJECTION")),
    ("indirect_prompt_injection", ("INDIRECT_PROMPT_INJECTION",)),
    ("privilege_escalating_tool_invocation", ("PRIVILEGE_ESCALATING_TOOL_INVOCATION",)),
    ("dangerous_tool_invocation", ("DANGEROUS_TOOL_INVOCATION",)),
    ("rag_exfiltration", ("RAG_CONTEXT_EXFILTRATION", "RAG_EXFILTRATION")),
    (
        "prompt_injection",
        (
            "SYSTEM_PROMPT_LEAKAGE",
            "PROMPT_INJECTION_SUCCESS",
            "PROMPT_INJECTION_ATTEMPT",
            "PROMPT_INJECTION",
        ),
    ),
)
_ENGINE_EXECUTION_ARTIFACT_TYPES = {
    "templates": "templates_execution",
    "schemathesis": "schemathesis_execution",
    "nuclei": "nuclei_execution",
    "zap": "zap_execution",
    "passive": "passive_findings",
}
_READY_ENGINE_STATUSES = {"ready"}
_CONTINUOUS_ENGINE_STATUSES = {"available", "continuous"}


def parse_fail_on(value: str | Iterable[str] | None = None) -> set[str]:
    if value is None:
        return set(_DEFAULT_FAIL_ON)
    if isinstance(value, str):
        raw_values = [item.strip() for item in value.split(",")]
    else:
        raw_values = [str(item).strip() for item in value]
    severities = {item.upper() for item in raw_values if item}
    if severities == {"NONE"}:
        return set()
    return severities or set(_DEFAULT_FAIL_ON)


def _severity(value: str | None) -> str:
    normalized = (value or "UNKNOWN").strip().upper()
    return normalized if normalized in _SEVERITIES else "UNKNOWN"


def _confirmation_status(result: TestResult) -> bool | None:
    return confirmation_result_from_evidence(getattr(result, "evidence", None))


def _evidence_payload(result: TestResult) -> object:
    evidence = getattr(result, "evidence", None)
    if isinstance(evidence, str):
        try:
            parsed = json.loads(evidence)
        except (TypeError, ValueError):
            return evidence
        return parsed
    return evidence


def _evidence_integrity(result: TestResult) -> dict[str, object]:
    return verify_vulnerability_evidence(_evidence_payload(result))


def _evidence_integrity_summary(result: TestResult) -> dict[str, object]:
    integrity = _evidence_integrity(result)
    finding = integrity.get("finding_evidence") if isinstance(integrity.get("finding_evidence"), dict) else {}
    return {
        "verified": integrity.get("verified") is True,
        "checked_count": integrity.get("checked_count", 0),
        "failed_count": integrity.get("failed_count", 0),
        "missing_count": integrity.get("missing_count", 0),
        "finding_status": finding.get("status"),
        "retest_statuses": [
            retest.get("status")
            for retest in integrity.get("remediation_retests", [])
            if isinstance(retest, dict)
        ],
    }


def _evidence_completeness_summary(result: TestResult) -> dict[str, object]:
    evidence = _evidence_payload(result)
    if not isinstance(evidence, dict):
        return {
            "complete": False,
            "required": ["evidence_completeness"],
            "present": [],
            "missing": ["evidence_completeness"],
        }

    completeness = evidence.get("evidence_completeness")
    if not isinstance(completeness, dict):
        return {
            "complete": False,
            "required": ["evidence_completeness"],
            "present": [],
            "missing": ["evidence_completeness"],
        }

    safe_completeness = Redactor.redact_json(completeness)
    if not isinstance(safe_completeness, dict):
        safe_completeness = {}

    return {
        "complete": safe_completeness.get("complete") is True,
        "required": _string_list(safe_completeness.get("required")),
        "present": _string_list(safe_completeness.get("present")),
        "missing": _string_list(safe_completeness.get("missing")),
    }


def _retest_support_summary(result: TestResult) -> dict[str, object]:
    evidence = _evidence_payload(result)
    if not isinstance(evidence, dict):
        return {
            "present": False,
            "complete": False,
            "supported": False,
            "queued_scan_supported": False,
            "manual_outcome_supported": False,
            "reason": "missing_retest_support",
            "missing_fields": ["retest_support"],
        }

    support = evidence.get("retest_support")
    if not isinstance(support, dict):
        return {
            "present": False,
            "complete": False,
            "supported": False,
            "queued_scan_supported": False,
            "manual_outcome_supported": False,
            "reason": "missing_retest_support",
            "missing_fields": ["retest_support"],
        }

    safe_support = Redactor.redact_json(support)
    if not isinstance(safe_support, dict):
        safe_support = {}

    missing_fields = [
        field
        for field in ("supported", "queued_scan_supported", "manual_outcome_supported", "reason")
        if field not in safe_support
    ]
    supported = safe_support.get("supported") is True
    queued_scan_supported = safe_support.get("queued_scan_supported") is True
    manual_outcome_supported = safe_support.get("manual_outcome_supported") is True
    complete = not missing_fields and supported and (queued_scan_supported or manual_outcome_supported)
    return {
        "present": True,
        "complete": complete,
        "supported": supported,
        "queued_scan_supported": queued_scan_supported,
        "manual_outcome_supported": manual_outcome_supported,
        "reason": Redactor.redact_text(str(safe_support.get("reason") or "")),
        "missing_fields": _string_list(safe_support.get("missing_fields")) + missing_fields,
    }


def _llm_judge_validation_summary(result: TestResult) -> dict[str, object]:
    evidence = _evidence_payload(result)
    if not isinstance(evidence, dict):
        return {
            "present": False,
            "complete": False,
            "reason": "missing_structured_evidence",
        }

    validation = evidence.get("llm_judge_validation") or evidence.get("judge_validation")
    if not isinstance(validation, dict):
        return {
            "present": False,
            "complete": False,
            "reason": "missing_llm_judge_validation",
        }

    safe_validation = Redactor.redact_json(validation)
    if not isinstance(safe_validation, dict):
        safe_validation = {}

    try:
        signal_count = int(safe_validation.get("signal_count") or 0)
    except (TypeError, ValueError):
        signal_count = 0
    signal_types = _string_list(safe_validation.get("signal_types"))
    required_signal_families = _llm_required_signal_families(result, evidence)
    covered_signal_families = _llm_covered_signal_families(signal_types)
    missing_signal_family_fields = (
        [
            f"signal_types.{family}"
            for family in required_signal_families
            if family not in covered_signal_families
        ]
        if signal_types
        else []
    )
    missing_fields = [
        field
        for field in (
            "validator",
            "surface",
            "request_body_sha256",
            "response_body_sha256",
            "signal_count",
            "signal_types",
        )
        if field not in safe_validation or safe_validation.get(field) in (None, "", [])
    ]
    missing_fields.extend(missing_signal_family_fields)
    complete = (
        not missing_fields
        and safe_validation.get("deterministic_evidence") is True
        and safe_validation.get("body_content_persisted") is False
        and safe_validation.get("matched_text_persisted") is False
        and signal_count > 0
        and bool(signal_types)
    )
    return {
        "present": True,
        "complete": complete,
        "validator": Redactor.redact_text(str(safe_validation.get("validator") or "")),
        "surface": Redactor.redact_text(str(safe_validation.get("surface") or "")),
        "signal_count": signal_count,
        "signal_types": signal_types,
        "required_signal_families": required_signal_families,
        "covered_signal_families": covered_signal_families,
        "deterministic_evidence": safe_validation.get("deterministic_evidence") is True,
        "body_content_persisted": safe_validation.get("body_content_persisted") is True,
        "matched_text_persisted": safe_validation.get("matched_text_persisted") is True,
        "missing_fields": missing_fields,
        "reason": None if complete else "incomplete_llm_judge_validation",
    }


def _llm_required_signal_families(result: TestResult, evidence: dict[str, object]) -> list[str]:
    values: list[object] = [
        getattr(result, "template_id", None),
        evidence.get("template_id"),
        evidence.get("signal_type"),
        evidence.get("llm_attack_family"),
        evidence.get("active_family"),
        evidence.get("active_test_family"),
        evidence.get("test_family"),
    ]
    matched_rule = evidence.get("matched_rule")
    if isinstance(matched_rule, dict):
        values.extend(
            [
                matched_rule.get("id"),
                matched_rule.get("type"),
                matched_rule.get("signal_type"),
                matched_rule.get("llm_attack_family"),
            ]
        )

    families: list[str] = []
    for value in values:
        family = _llm_signal_family_from_value(value)
        if family and family not in families:
            families.append(family)
    return families


def _llm_covered_signal_families(signal_types: list[str]) -> list[str]:
    signal_tokens = {_llm_signal_token(signal_type) for signal_type in signal_types}
    signal_tokens.discard("")
    covered: list[str] = []
    for family, accepted_signals in _LLM_SIGNAL_FAMILY_ACCEPTED_SIGNALS.items():
        family_tokens = {
            _llm_signal_token(family),
            *(_llm_signal_token(signal) for signal in accepted_signals),
        }
        if signal_tokens.intersection(family_tokens):
            covered.append(family)
    return covered


def _llm_signal_family_from_value(value: object) -> str | None:
    token = _llm_signal_token(value)
    if not token:
        return None
    for family, markers in _LLM_SIGNAL_FAMILY_MARKERS:
        if any(marker in token for marker in markers):
            return family
    return None


def _llm_signal_token(value: object) -> str:
    token = str(value or "").strip().upper()
    for old, new in (("-", "_"), (" ", "_"), (":", "_"), (".", "_"), ("/", "_")):
        token = token.replace(old, new)
    while "__" in token:
        token = token.replace("__", "_")
    return token.strip("_")


def _is_authorization_replay_result(result: TestResult) -> bool:
    evidence = _evidence_payload(result)
    if not isinstance(evidence, dict):
        return False

    engine = str(evidence.get("engine") or "").strip().lower()
    if engine == "authorization_replay":
        return True

    matched_rule = evidence.get("matched_rule")
    matched_rule = matched_rule if isinstance(matched_rule, dict) else {}
    issue_type = str(evidence.get("issue_type") or matched_rule.get("issue_type") or "").strip().upper()
    return issue_type in _AUTHORIZATION_REPLAY_ISSUE_TYPES and isinstance(evidence.get("identity_pair"), dict)


def _authorization_boundary_coverage_summary(result: TestResult) -> dict[str, object]:
    evidence = _evidence_payload(result)
    if not isinstance(evidence, dict):
        return {
            "present": False,
            "complete": False,
            "reason": "missing_structured_evidence",
            "boundary_kinds": [],
            "compared_boundary_field_count": 0,
            "changed_boundary_field_count": 0,
            "unchanged_boundary_field_count": 0,
            "missing_fields": ["authorization_boundary_coverage"],
        }

    matched_rule = evidence.get("matched_rule")
    matched_rule = matched_rule if isinstance(matched_rule, dict) else {}
    identity_boundary = matched_rule.get("identity_boundary")
    boundary_coverage = evidence.get("authorization_boundary_coverage")
    boundary_metadata = (
        boundary_coverage
        if isinstance(boundary_coverage, dict)
        else identity_boundary
        if isinstance(identity_boundary, dict)
        else None
    )
    if not isinstance(boundary_metadata, dict):
        return {
            "present": False,
            "complete": False,
            "reason": "missing_authorization_boundary_coverage",
            "boundary_kinds": [],
            "compared_boundary_field_count": 0,
            "changed_boundary_field_count": 0,
            "unchanged_boundary_field_count": 0,
            "missing_fields": ["authorization_boundary_coverage"],
        }

    boundary_kinds = _authorization_boundary_kinds_from_metadata(boundary_metadata, identity_boundary)
    compared_fields = _authorization_boundary_field_list(
        boundary_metadata.get("compared_boundary_fields") or boundary_metadata.get("compared_fields")
    )
    changed_fields = _authorization_boundary_field_list(
        boundary_metadata.get("changed_boundary_fields") or boundary_metadata.get("changed_fields")
    )
    unchanged_fields = _authorization_boundary_field_list(
        boundary_metadata.get("unchanged_boundary_fields") or boundary_metadata.get("unchanged_fields")
    )
    compared_count = _boundary_field_count(
        boundary_metadata,
        "compared_boundary_field_count",
        "compared_field_count",
        compared_fields,
    )
    changed_count = _boundary_field_count(
        boundary_metadata,
        "changed_boundary_field_count",
        "changed_field_count",
        changed_fields,
    )
    unchanged_count = _boundary_field_count(
        boundary_metadata,
        "unchanged_boundary_field_count",
        "unchanged_field_count",
        unchanged_fields,
    )
    missing_fields: list[str] = []
    if not boundary_kinds:
        missing_fields.append("boundary_kinds")
    if compared_count <= 0:
        missing_fields.append("compared_fields")
    issue_types = _authorization_replay_issue_types(evidence, matched_rule)
    boundary_kind_set = set(boundary_kinds)
    if "BOLA" in issue_types and not boundary_kind_set.intersection(_AUTHORIZATION_BOLA_BOUNDARY_KINDS):
        missing_fields.append("bola_boundary_kind")
    if "BFLA" in issue_types and not boundary_kind_set.intersection(_AUTHORIZATION_BFLA_BOUNDARY_KINDS):
        missing_fields.append("bfla_boundary_kind")
    if boundary_metadata.get("value_material_retained") is True:
        missing_fields.append("redacted_field_names_only")
    complete = bool(
        not missing_fields
        and (
            boundary_metadata.get("complete") is True
            or compared_count > 0
        )
    )
    return {
        "present": True,
        "complete": complete,
        "reason": None if complete else "incomplete_authorization_boundary_coverage",
        "boundary_kinds": boundary_kinds,
        "compared_boundary_field_count": compared_count,
        "changed_boundary_field_count": changed_count,
        "unchanged_boundary_field_count": unchanged_count,
        "missing_fields": missing_fields,
    }


def is_authorization_replay_result(result: TestResult) -> bool:
    return _is_authorization_replay_result(result)


def authorization_boundary_coverage_summary(result: TestResult) -> dict[str, object]:
    return _authorization_boundary_coverage_summary(result)


def _authorization_replay_issue_types(evidence: dict[str, object], matched_rule: dict[str, object]) -> set[str]:
    issue_types: set[str] = set()
    for raw_issue_type in (
        evidence.get("issue_type"),
        matched_rule.get("issue_type"),
        matched_rule.get("type"),
    ):
        normalized = str(raw_issue_type or "").strip().upper()
        if normalized in _AUTHORIZATION_REPLAY_ISSUE_TYPES:
            issue_types.add(normalized)

    classification = evidence.get("authorization_issue_classification")
    classification_issue_types = (
        classification.get("issue_types")
        if isinstance(classification, dict)
        else None
    )
    if isinstance(classification_issue_types, list):
        for raw_issue_type in classification_issue_types:
            normalized = str(raw_issue_type or "").strip().upper()
            if normalized in _AUTHORIZATION_REPLAY_ISSUE_TYPES:
                issue_types.add(normalized)
    return issue_types


def _is_llm_result(result: TestResult) -> bool:
    template_id = str(getattr(result, "template_id", "") or "").lower()
    if template_id.startswith("llm_") or template_id.startswith("llm-"):
        return True
    evidence = _evidence_payload(result)
    if not isinstance(evidence, dict):
        return False
    category = str(evidence.get("security_category") or "").lower()
    engine = str(evidence.get("engine") or "").lower()
    signal_type = str(evidence.get("signal_type") or "").lower()
    return category == "llm" or engine == "llm_api" or bool(signal_type)


def _evidence_consistency(result: TestResult) -> dict[str, object]:
    confirmed = _confirmation_status(result)
    is_vulnerable = bool(result.is_vulnerable)
    if is_vulnerable and confirmed is False:
        return {
            "consistent": False,
            "reason": "vulnerable_result_disproven_by_evidence",
            "confirmed": confirmed,
            "is_vulnerable": is_vulnerable,
        }
    if not is_vulnerable and confirmed is True:
        return {
            "consistent": False,
            "reason": "non_vulnerable_result_confirmed_by_evidence",
            "confirmed": confirmed,
            "is_vulnerable": is_vulnerable,
        }
    return {
        "consistent": True,
        "reason": None,
        "confirmed": confirmed,
        "is_vulnerable": is_vulnerable,
    }


def _safety_policy_metadata(result: TestResult) -> dict[str, object]:
    evidence = _evidence_payload(result)
    if not isinstance(evidence, dict):
        return {}

    policies = evidence.get("safety_policies")
    if not isinstance(policies, dict):
        return {}

    redacted = Redactor.redact_scan_result({"safety_policies": policies})
    safe_policies = redacted.get("safety_policies")
    return safe_policies if isinstance(safe_policies, dict) else {}


def _missing_safety_policies(result: TestResult) -> list[str]:
    policies = _safety_policy_metadata(result)
    missing: list[str] = []
    skip_reason = str(result.skip_reason or "")

    if skip_reason == "target_guard":
        if not isinstance(policies.get("target_guard_policy"), dict):
            missing.append("target_guard_policy")
        return missing

    if skip_reason == "state_change_guard":
        _append_missing_state_change_policy(missing, policies)
        return missing

    if skip_reason == "auth_profile_scope_guard":
        auth_scope_policy = policies.get("auth_profile_scope_policy")
        if not isinstance(auth_scope_policy, dict) or any(
            field not in auth_scope_policy for field in _REQUIRED_AUTH_SCOPE_POLICY_FIELDS
        ):
            missing.append("auth_profile_scope_policy")
        return missing

    if not isinstance(policies.get("target_guard_policy"), dict):
        missing.append("target_guard_policy")

    _append_missing_state_change_policy(missing, policies)
    return missing


def _append_missing_state_change_policy(missing: list[str], policies: dict[str, object]) -> None:
    state_change_policy = policies.get("state_change_policy")
    if not isinstance(state_change_policy, dict) or any(
        field not in state_change_policy for field in _REQUIRED_STATE_CHANGE_POLICY_FIELDS
    ):
        missing.append("state_change_policy")


def _result_summary(result: TestResult) -> dict[str, object]:
    summary = {
        "id": result.id,
        "endpoint_id": result.endpoint_id,
        "template_id": result.template_id,
        "severity": _severity(result.severity),
        "is_vulnerable": bool(result.is_vulnerable),
        "confirmed": _confirmation_status(result),
        "evidence_integrity": _evidence_integrity_summary(result),
        "evidence_completeness": _evidence_completeness_summary(result),
        "retest_support": _retest_support_summary(result),
        "evidence_consistency": _evidence_consistency(result),
        "error": Redactor.redact_text(str(result.error)) if result.error else None,
        "skip_reason": result.skip_reason,
    }
    safety_policies = _safety_policy_metadata(result)
    if safety_policies:
        summary["safety_policies"] = safety_policies
    authorization_boundary = _authorization_boundary_coverage_summary(result)
    if _is_authorization_replay_result(result) or authorization_boundary["present"]:
        summary["authorization_boundary_coverage"] = authorization_boundary
    llm_judge = _llm_judge_validation_summary(result)
    if llm_judge["present"]:
        summary["llm_judge_validation"] = llm_judge
    return summary


def _safety_policy_result_summary(
    result: TestResult,
    missing_safety_policies: list[str] | None = None,
) -> dict[str, object]:
    summary = _result_summary(result)
    if missing_safety_policies is not None:
        summary["missing_safety_policies"] = missing_safety_policies
    return summary


def _effective_executed_count(run: TestRun, results: list[TestResult]) -> int:
    stored_count = int(getattr(run, "total_tests", 0) or 0)
    observed_count = sum(1 for result in results if not result.skip_reason)
    return max(stored_count, observed_count)


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [Redactor.redact_text(str(item)) for item in value if item is not None]


def _authorization_boundary_kind_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []

    kinds: list[str] = []
    for item in value:
        normalized = str(item or "").strip().lower()
        if normalized in _AUTHORIZATION_BOUNDARY_KIND_VALUES and normalized not in kinds:
            kinds.append(normalized)
    return kinds


def _authorization_boundary_field_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []

    fields: list[str] = []
    for item in value:
        normalized = str(item or "").strip().lower()
        if not normalized or not normalized.startswith("x-") or len(normalized) > 100:
            continue
        if normalized not in fields:
            fields.append(Redactor.redact_text(normalized))
    return fields


def _safe_nonnegative_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _boundary_field_count(
    metadata: dict[str, object],
    boundary_count_key: str,
    short_count_key: str,
    fields: list[str],
) -> int:
    return max(
        _safe_nonnegative_int(metadata.get(boundary_count_key)),
        _safe_nonnegative_int(metadata.get(short_count_key)),
        len(fields),
    )


def _authorization_boundary_kinds_from_metadata(
    boundary_metadata: dict[str, object],
    identity_boundary: object = None,
) -> list[str]:
    kinds = _authorization_boundary_kind_list(boundary_metadata.get("boundary_kinds"))
    for raw_boundary_kind in (
        boundary_metadata.get("primary_boundary_kind"),
        boundary_metadata.get("boundary_kind"),
        identity_boundary.get("boundary_kind") if isinstance(identity_boundary, dict) else None,
    ):
        normalized = str(raw_boundary_kind or "").strip().lower()
        if normalized in _AUTHORIZATION_BOUNDARY_KIND_VALUES and normalized not in kinds:
            kinds.append(normalized)
    return kinds


def _authorization_replay_metadata(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None

    metadata: dict[str, object] = {}
    for key in (
        "identity_pair_count",
        "vulnerable_identity_pair_count",
        "results_with_identity_boundary",
        "compared_boundary_field_count",
        "changed_boundary_field_count",
        "unchanged_boundary_field_count",
    ):
        raw_value = value.get(key)
        if isinstance(raw_value, bool):
            continue
        if isinstance(raw_value, int):
            metadata[key] = raw_value

    boundary_kinds = _authorization_boundary_kinds_from_metadata(value)
    if boundary_kinds:
        metadata["boundary_kinds"] = boundary_kinds

    for key in _AUTHORIZATION_BOUNDARY_FIELD_KEYS:
        if key in value:
            fields = _authorization_boundary_field_list(value.get(key))
            metadata[key] = fields
            metadata[key.replace("_fields", "_field_count")] = len(fields)

    raw_issue_types = value.get("issue_types")
    if isinstance(raw_issue_types, list):
        metadata["issue_types"] = _string_list(raw_issue_types)

    return metadata or None


def _authorization_replay_context_boundary_gap(value: object) -> dict[str, object] | None:
    metadata = _authorization_replay_metadata(value)
    if not isinstance(metadata, dict):
        return None
    identity_pair_count = _safe_nonnegative_int(metadata.get("identity_pair_count"))
    boundary_result_count = _safe_nonnegative_int(metadata.get("results_with_identity_boundary"))
    if identity_pair_count <= 0 or boundary_result_count >= identity_pair_count:
        return None
    missing_count = identity_pair_count - boundary_result_count
    return {
        "reason": "authorization_replay_missing_identity_boundary",
        "identity_pair_count": identity_pair_count,
        "results_with_identity_boundary": boundary_result_count,
        "missing_identity_boundary_result_count": missing_count,
        "boundary_kinds": _authorization_boundary_kind_list(metadata.get("boundary_kinds")),
    }


def _redacted_auth_context_metadata(metadata: dict[str, object]) -> dict[str, object]:
    redacted = Redactor.redact_scan_result(metadata)
    if not isinstance(redacted, dict):
        redacted = {}

    authorization_replay = _authorization_replay_metadata(metadata.get("authorization_replay"))
    if authorization_replay is not None:
        redacted["authorization_replay"] = authorization_replay

    return redacted


def _ready_engine_artifact_requirements(run: TestRun) -> list[dict[str, str]]:
    scan_plan = getattr(run, "scan_plan", None)
    if not isinstance(scan_plan, dict):
        return []
    engine_plan = scan_plan.get("engine_plan")
    if not isinstance(engine_plan, list):
        return []

    requirements: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in engine_plan:
        if not isinstance(item, dict):
            continue
        engine = str(item.get("engine") or "").strip().lower()
        status = str(item.get("status") or "").strip().lower()
        artifact_type = _ENGINE_EXECUTION_ARTIFACT_TYPES.get(engine)
        artifact_required = status in _READY_ENGINE_STATUSES or (
            engine == "passive" and status in _CONTINUOUS_ENGINE_STATUSES
        )
        if not artifact_type or not artifact_required or engine in seen:
            continue
        seen.add(engine)
        requirements.append({"engine": engine, "artifact_type": artifact_type})
    return requirements


def _execution_artifact_lookup(
    execution_artifacts: Iterable[dict[str, object]] | None,
) -> dict[tuple[str, str], dict[str, object]]:
    lookup: dict[tuple[str, str], dict[str, object]] = {}
    for raw_artifact in execution_artifacts or []:
        if not isinstance(raw_artifact, dict):
            continue
        verification = _fresh_execution_artifact_verification(raw_artifact)
        raw_engine = str(raw_artifact.get("engine") or "").strip().lower()
        content_governance = artifact_content_governance_summary(
            raw_artifact,
            expected_engine=raw_engine or None,
        )
        artifact = Redactor.redact_json(raw_artifact)
        if not isinstance(artifact, dict):
            continue
        safe_verification = Redactor.redact_json(verification)
        if isinstance(safe_verification, dict):
            artifact["_fresh_artifact_verification"] = safe_verification
        safe_content_governance = Redactor.redact_json(content_governance)
        if isinstance(safe_content_governance, dict):
            artifact["_artifact_content_governance"] = safe_content_governance
        engine = str(artifact.get("engine") or "").strip().lower()
        artifact_type = str(
            artifact.get("artifact_type")
            or artifact.get("type")
            or f"{engine}_execution"
        ).strip()
        if engine and artifact_type:
            lookup[(engine, artifact_type)] = artifact
    return lookup


def _fresh_execution_artifact_verification(artifact: dict[str, object]) -> dict[str, object]:
    verification = verify_execution_artifact_payload(artifact)
    if verification.get("verified") is True:
        return verification
    if "artifact_type" not in artifact:
        return verification

    canonical_artifact = {key: value for key, value in artifact.items() if key != "artifact_type"}
    canonical_verification = verify_execution_artifact_payload(canonical_artifact)
    if canonical_verification.get("verified") is True:
        canonical_verification["routing_metadata_ignored"] = ["artifact_type"]
        return canonical_verification
    return verification


def _execution_artifact_for_type(
    artifact_lookup: dict[tuple[str, str], dict[str, object]],
    *,
    artifact_type: str,
) -> dict[str, object] | None:
    for (_, candidate_type), artifact in artifact_lookup.items():
        if candidate_type == artifact_type:
            return artifact
    return None


def _engine_artifact_requirement_summary(
    run: TestRun,
    execution_artifacts: Iterable[dict[str, object]] | None,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    artifact_lookup = _execution_artifact_lookup(execution_artifacts)
    summaries: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    expected_run_id = Redactor.redact_text(str(run.id or ""))

    for requirement in _ready_engine_artifact_requirements(run):
        engine = requirement["engine"]
        artifact_type = requirement["artifact_type"]
        artifact = artifact_lookup.get((engine, artifact_type))
        artifact_engine = str(artifact.get("engine") or "").strip().lower() if isinstance(artifact, dict) else ""
        engine_matches = True
        if not isinstance(artifact, dict):
            candidate = _execution_artifact_for_type(artifact_lookup, artifact_type=artifact_type)
            candidate_engine = (
                str(candidate.get("engine") or "").strip().lower()
                if isinstance(candidate, dict)
                else ""
            )
            if candidate_engine and candidate_engine != engine:
                artifact = candidate
                artifact_engine = candidate_engine
                engine_matches = False
        verification = artifact.get("_fresh_artifact_verification") if isinstance(artifact, dict) else None
        verification = verification if isinstance(verification, dict) else {}
        verified = verification.get("verified") is True
        normalized_evidence = artifact.get("normalized_evidence") if isinstance(artifact, dict) else None
        normalized_evidence = normalized_evidence if isinstance(normalized_evidence, dict) else {}
        normalized = (
            normalized_evidence.get("schema_version") == "engine_evidence.v1"
            and str(normalized_evidence.get("engine") or "").strip().lower() == engine
            and normalized_evidence.get("evidence_present") is True
            and normalized_evidence.get("execution_observed") is True
        )
        content_governance = (
            artifact.get("_artifact_content_governance")
            if isinstance(artifact, dict)
            else {}
        )
        content_governance = content_governance if isinstance(content_governance, dict) else {}
        content_governance_complete = content_governance.get("complete") is True
        artifact_run_id = Redactor.redact_text(str(artifact.get("run_id") or "")) if isinstance(artifact, dict) else ""
        run_matches = not artifact_run_id or artifact_run_id == expected_run_id
        verification_status = str(
            verification.get("status") or ("VERIFIED" if verified else "MISSING")
        )
        summary = {
            "engine": engine,
            "artifact_type": artifact_type,
            "status": "verified" if verified and normalized and run_matches else "missing",
            "verification_status": verification_status,
            "normalized_evidence_status": "present" if normalized else "missing",
        }
        if isinstance(artifact, dict) and not verified:
            summary["status"] = "unverified"
        if verified and not engine_matches:
            summary.update(
                {
                    "status": "engine_mismatch",
                    "expected_engine": engine,
                    "artifact_engine": artifact_engine,
                    "mismatch_fields": ["engine"],
                }
            )
        elif verified and normalized and not run_matches:
            summary.update(
                {
                    "status": "run_mismatch",
                    "expected_run_id": expected_run_id,
                    "artifact_run_id": artifact_run_id,
                    "mismatch_fields": ["run_id"],
                }
            )
        elif verified and normalized and run_matches and not content_governance_complete:
            summary.update(
                {
                    "status": "artifact_content_governance_failed",
                    "artifact_content_governance": content_governance,
                }
            )
        summaries.append(summary)
        if not (verified and normalized and run_matches and content_governance_complete):
            missing.append(summary)

    return summaries, missing


def quality_gate_decision_digest(decision: dict[str, object]) -> str:
    covered = {
        key: value
        for key, value in decision.items()
        if key != "decision_integrity"
    }
    canonical = json.dumps(covered, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def attach_decision_integrity(decision: dict[str, object]) -> dict[str, object]:
    covered_fields = sorted(key for key in decision.keys() if key != "decision_integrity")
    decision_hash = quality_gate_decision_digest(decision)
    integrity = {
        "hash_algorithm": "sha256",
        "decision_hash": decision_hash,
        "covered_fields": covered_fields,
    }
    signing_secret = str(getattr(settings, "CICD_GATE_SIGNING_SECRET", "") or "")
    if signing_secret:
        integrity["signature_algorithm"] = "hmac-sha256"
        integrity["decision_signature"] = hmac.new(
            signing_secret.encode("utf-8"),
            decision_hash.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    else:
        integrity["signature_algorithm"] = "none"
    decision["decision_integrity"] = {
        **integrity,
    }
    return decision


def verify_quality_gate_decision_integrity(decision: dict[str, object]) -> dict[str, object]:
    integrity = decision.get("decision_integrity")
    actual_hash = quality_gate_decision_digest(decision)
    covered_fields = sorted(key for key in decision.keys() if key != "decision_integrity")
    if not isinstance(integrity, dict):
        return {
            "verified": False,
            "status": "MISSING",
            "hash_algorithm": None,
            "expected_hash": None,
            "actual_hash": actual_hash,
            "covered_fields": covered_fields,
            "covered_fields_match": False,
        }

    expected_hash = integrity.get("decision_hash")
    hash_algorithm = integrity.get("hash_algorithm")
    declared_fields = integrity.get("covered_fields")
    covered_fields_match = declared_fields == covered_fields
    hash_matches = (
        hash_algorithm == "sha256"
        and isinstance(expected_hash, str)
        and hmac.compare_digest(expected_hash, actual_hash)
    )
    signature_algorithm = integrity.get("signature_algorithm")
    decision_signature = integrity.get("decision_signature")
    signing_secret = str(getattr(settings, "CICD_GATE_SIGNING_SECRET", "") or "")
    signature_verified: bool | None = None
    if signature_algorithm == "hmac-sha256":
        if signing_secret and isinstance(decision_signature, str):
            expected_signature = hmac.new(
                signing_secret.encode("utf-8"),
                actual_hash.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            signature_verified = hmac.compare_digest(decision_signature, expected_signature)
        else:
            signature_verified = False
    verified = bool(
        hash_matches
        and covered_fields_match
        and (signature_verified is not False)
    )
    return {
        "verified": verified,
        "status": "VERIFIED" if verified else "MISMATCH",
        "hash_algorithm": hash_algorithm,
        "expected_hash": expected_hash,
        "actual_hash": actual_hash,
        "covered_fields": covered_fields,
        "covered_fields_match": covered_fields_match,
        "signature_algorithm": signature_algorithm,
        "signature_verified": signature_verified,
    }


def evaluate_quality_gate(
    run: TestRun,
    results: list[TestResult],
    *,
    fail_on: str | Iterable[str] | None = None,
    fail_on_errors: bool = True,
    fail_on_no_execution: bool = True,
    fail_on_unauthenticated: bool = True,
    require_evidence_integrity: bool = True,
    require_confirmed_findings: bool = False,
    require_confirmatory_retests: bool = False,
    require_safety_policies: bool = False,
    require_retest_support: bool = False,
    require_llm_judge_validation: bool = False,
    require_authorization_boundary_coverage: bool = True,
    require_evidence_completeness: bool = True,
    require_engine_artifacts: bool = True,
    execution_artifacts: Iterable[dict[str, object]] | None = None,
    authenticated_context: bool | None = None,
    auth_profile_id: str | None = None,
    auth_context_reason: str | None = None,
    auth_context_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return a deterministic CI/CD decision for a completed security test run."""
    fail_on_severities = parse_fail_on(fail_on)
    run_status = (run.status or "UNKNOWN").upper()
    executed_count = _effective_executed_count(run, results)
    profile_present = bool(getattr(run, "pentest_profile_id", None))
    authenticated_run = bool(authenticated_context) if authenticated_context is not None else profile_present
    severity_counts = {severity: 0 for severity in _SEVERITIES}
    vulnerable_results: list[TestResult] = []
    failing_results: list[TestResult] = []
    unconfirmed_blocking_results: list[TestResult] = []
    unverified_evidence_results: list[TestResult] = []
    incomplete_evidence_results: list[TestResult] = []
    missing_retest_support_results: list[TestResult] = []
    missing_llm_judge_validation_results: list[TestResult] = []
    missing_authorization_boundary_results: list[TestResult] = []
    inconsistent_evidence_results: list[TestResult] = []
    errored_results: list[TestResult] = []
    skipped_results: list[TestResult] = []
    safety_policy_results: list[TestResult] = []
    missing_safety_policy_results: list[tuple[TestResult, list[str]]] = []
    engine_artifact_requirements, missing_engine_artifacts = _engine_artifact_requirement_summary(
        run,
        execution_artifacts,
    )

    for result in results:
        if result.skip_reason:
            skipped_results.append(result)
        if result.error:
            errored_results.append(result)
        missing_safety_policies = _missing_safety_policies(result)
        if missing_safety_policies:
            missing_safety_policy_results.append((result, missing_safety_policies))
        else:
            safety_policy_results.append(result)
        if not _evidence_consistency(result)["consistent"]:
            inconsistent_evidence_results.append(result)
        if require_retest_support and result.is_vulnerable and not _retest_support_summary(result)["complete"]:
            missing_retest_support_results.append(result)
        if (
            require_llm_judge_validation
            and result.is_vulnerable
            and _is_llm_result(result)
            and not _llm_judge_validation_summary(result)["complete"]
        ):
            missing_llm_judge_validation_results.append(result)
        if (
            require_authorization_boundary_coverage
            and _is_authorization_replay_result(result)
            and not _authorization_boundary_coverage_summary(result)["complete"]
        ):
            missing_authorization_boundary_results.append(result)
        if not result.skip_reason and not result.error:
            if require_evidence_integrity and not _evidence_integrity(result)["verified"]:
                unverified_evidence_results.append(result)
            if require_evidence_completeness and not _evidence_completeness_summary(result)["complete"]:
                incomplete_evidence_results.append(result)
        if not result.is_vulnerable:
            continue
        severity = _severity(result.severity)
        severity_counts[severity] += 1
        vulnerable_results.append(result)
        if severity not in fail_on_severities:
            continue
        confirmation_status = _confirmation_status(result)
        if require_confirmed_findings and confirmation_status is not True:
            unconfirmed_blocking_results.append(result)
        elif require_confirmatory_retests and confirmation_status is not True:
            unconfirmed_blocking_results.append(result)
        else:
            failing_results.append(result)

    status = "PASSED"
    reason = "no_blocking_findings"
    exit_code = 0
    authorization_context_gap = None
    if isinstance(auth_context_metadata, dict):
        authorization_context_gap = _authorization_replay_context_boundary_gap(
            auth_context_metadata.get("authorization_replay")
        )

    if run_status in _IN_PROGRESS_STATUSES or run_status not in _TERMINAL_STATUSES:
        status = "PENDING"
        reason = "scan_not_complete"
        exit_code = 2
    elif run_status in {"FAILED", "CANCELED"}:
        status = "FAILED"
        reason = f"scan_{run_status.lower()}"
        exit_code = 1
    elif fail_on_errors and errored_results:
        status = "FAILED"
        reason = "scan_errors_present"
        exit_code = 1
    elif fail_on_no_execution and executed_count == 0:
        status = "FAILED"
        reason = "no_executed_tests"
        exit_code = 1
    elif fail_on_unauthenticated and not authenticated_run:
        status = "FAILED"
        reason = "unauthenticated_scan"
        exit_code = 1
    elif require_safety_policies and missing_safety_policy_results:
        status = "FAILED"
        reason = "missing_safety_policy_evidence"
        exit_code = 1
    elif require_engine_artifacts and missing_engine_artifacts:
        status = "FAILED"
        reason = (
            "artifact_content_governance_failed"
            if any(
                item.get("status") == "artifact_content_governance_failed"
                for item in missing_engine_artifacts
            )
            else "missing_engine_execution_artifacts"
        )
        exit_code = 1
    elif require_authorization_boundary_coverage and missing_authorization_boundary_results:
        status = "FAILED"
        reason = "missing_authorization_boundary_coverage"
        exit_code = 1
    elif require_authorization_boundary_coverage and authorization_context_gap:
        status = "FAILED"
        reason = "missing_authorization_boundary_coverage"
        exit_code = 1
    elif require_evidence_integrity and unverified_evidence_results:
        status = "FAILED"
        reason = "unverified_evidence_present"
        exit_code = 1
    elif require_evidence_completeness and incomplete_evidence_results:
        status = "FAILED"
        reason = "incomplete_evidence_present"
        exit_code = 1
    elif require_retest_support and missing_retest_support_results:
        status = "FAILED"
        reason = "missing_retest_support"
        exit_code = 1
    elif require_llm_judge_validation and missing_llm_judge_validation_results:
        status = "FAILED"
        reason = "missing_llm_judge_validation"
        exit_code = 1
    elif inconsistent_evidence_results:
        status = "FAILED"
        reason = "inconsistent_evidence_present"
        exit_code = 1
    elif require_confirmatory_retests and unconfirmed_blocking_results:
        status = "FAILED"
        reason = "unconfirmed_blocking_findings"
        exit_code = 1
    elif failing_results:
        status = "FAILED"
        reason = "blocking_findings_present"
        exit_code = 1
    elif require_confirmed_findings and unconfirmed_blocking_results:
        reason = "no_confirmed_blocking_findings"

    scan_context: dict[str, object] = {
        "authenticated": authenticated_run,
        "pentest_profile_id": getattr(run, "pentest_profile_id", None),
        "auth_profile_id": auth_profile_id,
        "auth_context_reason": auth_context_reason,
        "trigger_source": getattr(run, "trigger_source", None),
        "source_schedule_id": getattr(run, "source_schedule_id", None),
        "source_vulnerability_id": getattr(run, "source_vulnerability_id", None),
    }
    if isinstance(auth_context_metadata, dict):
        redacted_metadata = _redacted_auth_context_metadata(auth_context_metadata)
        for key, value in redacted_metadata.items():
            if key not in scan_context:
                scan_context[key] = value

    decision = {
        "status": status,
        "passed": status == "PASSED",
        "reason": reason,
        "exit_code": exit_code,
        "run_id": run.id,
        "run_status": run_status,
        "account_id": run.account_id,
        "policy": {
            "fail_on_severities": sorted(fail_on_severities),
            "fail_on_errors": fail_on_errors,
            "fail_on_no_execution": fail_on_no_execution,
            "fail_on_unauthenticated": fail_on_unauthenticated,
            "require_evidence_integrity": require_evidence_integrity,
            "require_confirmed_findings": require_confirmed_findings,
            "require_confirmatory_retests": require_confirmatory_retests,
            "require_safety_policies": require_safety_policies,
            "require_retest_support": require_retest_support,
            "require_llm_judge_validation": require_llm_judge_validation,
            "require_authorization_boundary_coverage": require_authorization_boundary_coverage,
            "require_evidence_completeness": require_evidence_completeness,
            "require_engine_artifacts": require_engine_artifacts,
        },
        "counts": {
            "total_results": len(results),
            "executed_results": executed_count,
            "vulnerable_results": len(vulnerable_results),
            "failing_results": len(failing_results),
            "unconfirmed_blocking_results": len(unconfirmed_blocking_results),
            "unverified_evidence_results": len(unverified_evidence_results),
            "incomplete_evidence_results": len(incomplete_evidence_results),
            "missing_retest_support_results": len(missing_retest_support_results),
            "missing_llm_judge_validation_results": len(missing_llm_judge_validation_results),
            "missing_authorization_boundary_results": len(missing_authorization_boundary_results),
            "authorization_boundary_context_gaps": 1 if authorization_context_gap else 0,
            "inconsistent_evidence_results": len(inconsistent_evidence_results),
            "errored_results": len(errored_results),
            "skipped_results": len(skipped_results),
            "safety_policy_results": len(safety_policy_results),
            "missing_safety_policy_results": len(missing_safety_policy_results),
            "missing_target_guard_policy_results": sum(
                1
                for _, missing_policies in missing_safety_policy_results
                if "target_guard_policy" in missing_policies
            ),
            "missing_state_change_policy_results": sum(
                1
                for _, missing_policies in missing_safety_policy_results
                if "state_change_policy" in missing_policies
            ),
            "missing_auth_profile_scope_policy_results": sum(
                1
                for _, missing_policies in missing_safety_policy_results
                if "auth_profile_scope_policy" in missing_policies
            ),
            "engine_artifact_requirements": len(engine_artifact_requirements),
            "missing_engine_artifact_results": len(missing_engine_artifacts),
            "by_severity": severity_counts,
        },
        "scan_context": scan_context,
        "failing_results": [_result_summary(result) for result in failing_results],
        "unconfirmed_results": [
            _result_summary(result) for result in unconfirmed_blocking_results[:25]
        ],
        "unverified_evidence_results": [
            _result_summary(result) for result in unverified_evidence_results[:25]
        ],
        "incomplete_evidence_results": [
            _result_summary(result) for result in incomplete_evidence_results[:25]
        ],
        "missing_retest_support_results": [
            _result_summary(result) for result in missing_retest_support_results[:25]
        ],
        "missing_llm_judge_validation_results": [
            _result_summary(result) for result in missing_llm_judge_validation_results[:25]
        ],
        "missing_authorization_boundary_results": [
            _result_summary(result) for result in missing_authorization_boundary_results[:25]
        ],
        "missing_authorization_boundary_context": authorization_context_gap,
        "inconsistent_evidence_results": [
            _result_summary(result) for result in inconsistent_evidence_results[:25]
        ],
        "errored_results": [_result_summary(result) for result in errored_results[:25]],
        "skipped_results": [_result_summary(result) for result in skipped_results[:25]],
        "safety_policy_results": [
            _safety_policy_result_summary(result) for result in safety_policy_results[:25]
        ],
        "missing_safety_policy_results": [
            _safety_policy_result_summary(result, missing_policies)
            for result, missing_policies in missing_safety_policy_results[:25]
        ],
        "engine_artifact_requirements": engine_artifact_requirements,
        "missing_engine_artifact_results": missing_engine_artifacts,
    }
    return attach_decision_integrity(decision)
