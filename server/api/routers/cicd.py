"""CI/CD integration, release gates, and machine-readable security artifacts."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import AuthProfile, CICDTrigger, PentestArtifact, PentestProfile, TestResult, TestRun, Vulnerability
from server.modules.auth.audit import log_action
from server.modules.auth.rbac import Permission, RBAC, can_trigger_cicd
from server.modules.cicd.policy_packs import available_policy_packs, resolve_policy_pack
from server.modules.cicd.quality_gate import attach_decision_integrity, evaluate_quality_gate, parse_fail_on
from server.modules.pentest.auth_preflight import auth_profile_has_runtime_material
from server.modules.pentest.auth_scope import AuthScopeError, auth_scope_policy_for_error, validate_auth_profile_scope
from server.modules.pentest.target_policy import target_guard_policy_for_error, validate_pentest_target
from server.modules.persistence.database import get_db
from server.modules.quotas.tenant_quota import QuotaStatus, check_cicd_gate_quota
from server.modules.test_executor.reporting import build_junit, build_report_artifact_manifest, build_sarif
from server.modules.utils.redactor import Redactor
from server.modules.validation.input_validator import InputValidator, ValidationError
from server.modules.vulnerability_detector.lifecycle import (
    confirmation_status_from_evidence,
    latest_ticket_sync,
    vulnerability_sla_status,
)

router = APIRouter(tags=["CI/CD Integration"])
logger = logging.getLogger(__name__)

_STRICT_GATE_FAIL_ON = {"CRITICAL", "HIGH"}
_TICKET_REQUIRED_STOPPED_STATUSES = {
    "CLOSED",
    "RESOLVED",
    "FALSE_POSITIVE",
    "FALSE-POSITIVE",
    "ACCEPTED_RISK",
}
_FAILED_TICKET_SYNC_STATUSES = {"ERROR", "FAILED", "SYNC_FAILED", "ERRORED"}
_TICKET_SYNC_MAX_AGE_SECONDS = 24 * 60 * 60
_SELECTION_COVERAGE_TARGETS = ("authorization", "business_logic", "llm_api")
_SELECTION_COVERAGE_REQUIRED_FIELDS = ("status", "signals")
_SELECTION_COVERAGE_ACTIVE_FAMILY_TARGETS = {"business_logic", "llm_api"}
_SELECTION_COVERAGE_AUTHORIZATION_REQUIRED_FIELDS = ("identity_context", "readiness")
_SELECTION_COVERAGE_AUTHORIZATION_IDENTITY_FIELDS = (
    "role_count",
    "multi_identity_ready",
    "privileged_role_present",
    "low_privilege_role_present",
    "privilege_boundary_pair_count",
)
_SELECTION_COVERAGE_AUTHORIZATION_READINESS_FIELDS = (
    "auth_context_ready",
    "private_identifier_context_ready",
    "role_context_ready",
    "bola_replay_testable",
    "bfla_replay_testable",
)
_SELECTION_COVERAGE_AUTHORIZATION_REPLAY_READY_FIELDS = (
    "bola_replay_testable",
    "bfla_replay_testable",
)


def _message_exception(status_code: int, message: object) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"message": message})


def _validate_uuid_or_400(value: str, field_name: str) -> str:
    try:
        return InputValidator.validate_uuid(value, field_name)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _parse_evidence(value: object) -> object:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


def _safe_webhook_payload(payload: object) -> dict:
    redacted = Redactor.redact_json(payload)
    return redacted if isinstance(redacted, dict) else {}


def _resolve_webhook_account_id(x_account_id: Optional[str]) -> int:
    """Resolve the tenant account for an inbound CI webhook.

    Multi-tenant deployments should send ``X-Account-Id`` on every webhook.
    When absent, fall back to ``DEFAULT_ACCOUNT_ID`` and warn so operators
    know CI triggers are being attributed to the shared default tenant.
    """
    if x_account_id:
        try:
            return int(x_account_id)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="X-Account-Id must be an integer account id")
    default_id = int(getattr(settings, "DEFAULT_ACCOUNT_ID", 1000000))
    logger.warning(
        "cicd_webhook_default_account: no X-Account-Id header; attributing "
        "trigger to DEFAULT_ACCOUNT_ID=%s. Configure per-tenant webhook "
        "secrets and send X-Account-Id for multi-tenant CI.",
        default_id,
    )
    return default_id


async def _load_run(
    db: AsyncSession,
    *,
    run_id: str,
    account_id: int,
) -> TestRun:
    result = await db.execute(
        select(TestRun).where(TestRun.id == run_id, TestRun.account_id == account_id)
    )
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return run


async def _load_results(
    db: AsyncSession,
    *,
    run_id: str,
    account_id: int,
) -> list[TestResult]:
    result = await db.execute(
        select(TestResult)
        .join(TestRun, and_(TestResult.run_id == TestRun.id, TestRun.account_id == account_id))
        .where(TestResult.run_id == run_id)
    )
    return list(result.scalars().all())


async def _load_execution_artifacts(
    db: AsyncSession,
    *,
    run_id: str,
    account_id: int,
) -> list[PentestArtifact]:
    result = await db.execute(
        select(PentestArtifact).where(
            PentestArtifact.run_id == run_id,
            PentestArtifact.account_id == account_id,
        )
    )
    return list(result.scalars().all())


def _execution_artifact_payloads(artifacts: list[PentestArtifact]) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for artifact in artifacts:
        payload = artifact.content_json if isinstance(artifact.content_json, dict) else {}
        artifact_payload: dict[str, object] = dict(payload)
        artifact_payload.setdefault("artifact_type", artifact.artifact_type)
        artifact_payload.setdefault("engine", str(artifact.artifact_type or "").removesuffix("_execution"))
        payloads.append(artifact_payload)
    return payloads


async def _load_run_for_gate(
    db: AsyncSession,
    *,
    account_id: int,
    run_id: str,
) -> tuple[TestRun, list[TestResult], dict[str, object]]:
    run = await _load_run(db, run_id=run_id, account_id=account_id)
    results = await _load_results(db, run_id=run_id, account_id=account_id)
    auth_context = await _run_auth_context(db, account_id=account_id, run=run, results=results)
    return run, results, auth_context


async def _run_auth_context(
    db: AsyncSession,
    *,
    account_id: int,
    run: TestRun,
    results: list[TestResult],
) -> dict[str, object]:
    replay_context = _authorization_replay_auth_context(results)
    if replay_context["authenticated"]:
        return replay_context
    if not run.pentest_profile_id:
        return replay_context

    result = await db.execute(
        select(PentestProfile).where(
            PentestProfile.id == run.pentest_profile_id,
            PentestProfile.account_id == account_id,
        )
    )
    profile = result.scalar_one_or_none()
    if profile is None:
        return {
            "authenticated": False,
            "pentest_profile_id": run.pentest_profile_id,
            "auth_profile_id": None,
            "reason": "pentest_profile_missing",
        }

    auth_profile = None
    if profile.auth_profile_id:
        auth_result = await db.execute(
            select(AuthProfile).where(
                AuthProfile.id == profile.auth_profile_id,
                AuthProfile.account_id == account_id,
                AuthProfile.is_active.is_(True),
            )
        )
        auth_profile = auth_result.scalar_one_or_none()

    authenticated = bool(auth_profile and auth_profile_has_runtime_material(auth_profile))
    return {
        "authenticated": authenticated,
        "pentest_profile_id": profile.id,
        "auth_profile_id": profile.auth_profile_id if authenticated else None,
        "reason": "auth_profile_ready" if authenticated else "auth_profile_missing_runtime_credentials",
    }


def _authorization_replay_auth_context(results: list[TestResult]) -> dict[str, object]:
    identity_pairs: set[tuple[str, str]] = set()
    vulnerable_identity_pairs: set[tuple[str, str]] = set()
    boundary_kinds: set[str] = set()
    compared_boundary_fields: set[str] = set()
    changed_boundary_fields: set[str] = set()
    unchanged_boundary_fields: set[str] = set()
    issue_types: set[str] = set()
    results_with_identity_boundary = 0

    for result in results:
        evidence = _parse_evidence(result.evidence)
        if not isinstance(evidence, dict) or evidence.get("engine") != "authorization_replay":
            continue
        identity_pair = evidence.get("identity_pair")
        replay_request = evidence.get("replay_request")
        victim = identity_pair.get("victim") if isinstance(identity_pair, dict) else {}
        attacker = identity_pair.get("attacker") if isinstance(identity_pair, dict) else {}
        headers = replay_request.get("headers") if isinstance(replay_request, dict) else {}
        if not (
            isinstance(victim, dict)
            and isinstance(attacker, dict)
            and (attacker.get("id") or attacker.get("role"))
            and isinstance(headers, dict)
        ):
            continue

        identity_pair_key = (
            Redactor.redact_text(str(victim.get("id") or victim.get("role") or "unknown")),
            Redactor.redact_text(str(attacker.get("id") or attacker.get("role") or "unknown")),
        )
        identity_pairs.add(identity_pair_key)
        if result.is_vulnerable:
            vulnerable_identity_pairs.add(identity_pair_key)

        matched_rule = evidence.get("matched_rule") if isinstance(evidence.get("matched_rule"), dict) else {}
        issue_type = evidence.get("issue_type") or matched_rule.get("issue_type")
        if issue_type:
            issue_types.add(Redactor.redact_text(str(issue_type)))
        classification = evidence.get("authorization_issue_classification")
        classification_issue_types = (
            classification.get("issue_types")
            if isinstance(classification, dict)
            else None
        )
        if isinstance(classification_issue_types, list):
            for classified_issue_type in classification_issue_types:
                if classified_issue_type:
                    issue_types.add(Redactor.redact_text(str(classified_issue_type)))

        identity_boundary = matched_rule.get("identity_boundary") if isinstance(matched_rule, dict) else None
        boundary_coverage = evidence.get("authorization_boundary_coverage")
        boundary_metadata = (
            boundary_coverage
            if isinstance(boundary_coverage, dict)
            else identity_boundary
            if isinstance(identity_boundary, dict)
            else {}
        )
        if isinstance(identity_boundary, dict) or isinstance(boundary_coverage, dict):
            results_with_identity_boundary += 1
            boundary_kinds.update(_authorization_boundary_kinds(boundary_metadata, identity_boundary))
            compared_boundary_fields.update(_authorization_boundary_field_names(boundary_metadata.get("compared_fields")))
            compared_boundary_fields.update(
                _authorization_boundary_field_names(boundary_metadata.get("compared_boundary_fields"))
            )
            changed_boundary_fields.update(_authorization_boundary_field_names(boundary_metadata.get("changed_fields")))
            changed_boundary_fields.update(
                _authorization_boundary_field_names(boundary_metadata.get("changed_boundary_fields"))
            )
            unchanged_boundary_fields.update(_authorization_boundary_field_names(boundary_metadata.get("unchanged_fields")))
            unchanged_boundary_fields.update(
                _authorization_boundary_field_names(boundary_metadata.get("unchanged_boundary_fields"))
            )

    if identity_pairs:
        return {
            "authenticated": True,
            "pentest_profile_id": None,
            "auth_profile_id": None,
            "reason": "authorization_replay_test_accounts",
            "authorization_replay": {
                "identity_pair_count": len(identity_pairs),
                "vulnerable_identity_pair_count": len(vulnerable_identity_pairs),
                "results_with_identity_boundary": results_with_identity_boundary,
                "compared_boundary_field_count": len(compared_boundary_fields),
                "changed_boundary_field_count": len(changed_boundary_fields),
                "unchanged_boundary_field_count": len(unchanged_boundary_fields),
                "boundary_kinds": sorted(boundary_kinds),
                "compared_boundary_fields": sorted(compared_boundary_fields),
                "changed_boundary_fields": sorted(changed_boundary_fields),
                "unchanged_boundary_fields": sorted(unchanged_boundary_fields),
                "issue_types": sorted(issue_types),
            },
        }

    return {
        "authenticated": False,
        "pentest_profile_id": None,
        "auth_profile_id": None,
        "reason": "missing_pentest_profile",
    }


def _authorization_boundary_kinds(
    boundary_metadata: dict[str, object],
    identity_boundary: object,
) -> set[str]:
    allowed = {"cross_tenant", "cross_account", "cross_role", "cross_scope", "cross_permission"}
    kinds: set[str] = set()
    raw_kinds = boundary_metadata.get("boundary_kinds")
    if isinstance(raw_kinds, list):
        for boundary_kind in raw_kinds:
            normalized = str(boundary_kind or "").strip().lower()
            if normalized in allowed:
                kinds.add(normalized)
    for raw_boundary_kind in (
        boundary_metadata.get("primary_boundary_kind"),
        boundary_metadata.get("boundary_kind"),
        identity_boundary.get("boundary_kind") if isinstance(identity_boundary, dict) else None,
    ):
        normalized = str(raw_boundary_kind or "").strip().lower()
        if normalized in allowed:
            kinds.add(normalized)
    return kinds


def _authorization_boundary_field_names(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    fields: set[str] = set()
    for item in value:
        normalized = str(item or "").strip().lower()
        if normalized and normalized.startswith("x-") and len(normalized) <= 100:
            fields.add(Redactor.redact_text(normalized))
    return fields


def _gate_auth_context_metadata(auth_context: dict[str, object]) -> dict[str, object] | None:
    replay = auth_context.get("authorization_replay")
    return {"authorization_replay": replay} if isinstance(replay, dict) else None


def _strict_gate_policy() -> dict[str, object]:
    return {
        "fail_on_severities": sorted(_STRICT_GATE_FAIL_ON),
        "fail_on_errors": True,
        "fail_on_no_execution": True,
        "fail_on_unauthenticated": True,
        "require_evidence_integrity": True,
        "require_evidence_completeness": True,
        "require_safety_policies": True,
        "require_retest_support": True,
        "require_llm_judge_validation": False,
        "require_authorization_boundary_coverage": True,
        "require_engine_artifact_accountability": True,
        "require_confirmatory_retests": True,
        "require_confirmed_findings": False,
        "require_ticketed_blocking_vulnerabilities": True,
    }


def _resolve_gate_policy(
    *,
    request: Request,
    policy_pack: str,
    fail_on: str,
    fail_on_errors: bool,
    fail_on_no_execution: bool,
    fail_on_unauthenticated: bool,
    require_evidence_integrity: bool,
    require_evidence_completeness: bool,
    require_safety_policies: bool,
    require_retest_support: bool,
    require_llm_judge_validation: bool,
    require_authorization_boundary_coverage: bool,
    require_engine_artifact_accountability: bool,
    require_confirmatory_retests: bool,
    require_confirmed_findings: bool,
    require_ticketed_blocking_vulnerabilities: bool,
) -> dict[str, object]:
    try:
        effective = resolve_policy_pack(policy_pack)
    except ValueError as exc:
        raise _message_exception(
            400,
            {
                "message": str(exc),
                "reason": "unknown_policy_pack",
                "valid_policy_packs": available_policy_packs(),
            },
        ) from exc

    query_params = set(request.query_params.keys())
    if "fail_on" in query_params:
        effective["fail_on"] = fail_on
    for key, value in {
        "fail_on_errors": fail_on_errors,
        "fail_on_no_execution": fail_on_no_execution,
        "fail_on_unauthenticated": fail_on_unauthenticated,
        "require_evidence_integrity": require_evidence_integrity,
        "require_evidence_completeness": require_evidence_completeness,
        "require_safety_policies": require_safety_policies,
        "require_retest_support": require_retest_support,
        "require_llm_judge_validation": require_llm_judge_validation,
        "require_authorization_boundary_coverage": require_authorization_boundary_coverage,
        "require_engine_artifact_accountability": require_engine_artifact_accountability,
        "require_confirmatory_retests": require_confirmatory_retests,
        "require_confirmed_findings": require_confirmed_findings,
        "require_ticketed_blocking_vulnerabilities": require_ticketed_blocking_vulnerabilities,
    }.items():
        if key in query_params:
            effective[key] = value
    effective.setdefault("require_llm_judge_validation", False)
    effective.setdefault("require_authorization_boundary_coverage", False)
    effective.setdefault("require_engine_artifact_accountability", True)
    effective.setdefault("require_ticketed_blocking_vulnerabilities", True)
    return effective


def _gate_policy_override_reasons(
    *,
    fail_on: str,
    fail_on_errors: bool,
    fail_on_no_execution: bool,
    fail_on_unauthenticated: bool,
    require_evidence_integrity: bool,
    require_evidence_completeness: bool,
    require_safety_policies: bool,
    require_retest_support: bool,
    require_llm_judge_validation: bool,
    require_authorization_boundary_coverage: bool,
    require_engine_artifact_accountability: bool,
    require_confirmatory_retests: bool,
    require_confirmed_findings: bool,
    require_ticketed_blocking_vulnerabilities: bool,
) -> list[dict[str, object]]:
    reasons: list[dict[str, object]] = []
    fail_on_severities = parse_fail_on(fail_on)
    missing_severities = sorted(_STRICT_GATE_FAIL_ON - fail_on_severities)
    if missing_severities:
        reasons.append({
            "field": "fail_on",
            "reason": "missing_required_blocking_severities",
            "missing": missing_severities,
            "received": sorted(fail_on_severities),
        })
    if not fail_on_errors:
        reasons.append({"field": "fail_on_errors", "reason": "scan_errors_would_not_fail_gate"})
    if not fail_on_no_execution:
        reasons.append({"field": "fail_on_no_execution", "reason": "empty_or_fully_skipped_runs_would_pass"})
    if not fail_on_unauthenticated:
        reasons.append({"field": "fail_on_unauthenticated", "reason": "unauthenticated_runs_would_pass"})
    if not require_evidence_integrity:
        reasons.append({"field": "require_evidence_integrity", "reason": "tampered_or_missing_evidence_hashes_would_pass"})
    if not require_evidence_completeness:
        reasons.append({"field": "require_evidence_completeness", "reason": "incomplete_finding_evidence_would_pass"})
    if not require_safety_policies:
        reasons.append({"field": "require_safety_policies", "reason": "missing_safety_policy_evidence_would_pass"})
    if not require_retest_support:
        reasons.append({"field": "require_retest_support", "reason": "findings_without_retest_support_would_pass"})
    if not require_llm_judge_validation and _strict_gate_policy().get("require_llm_judge_validation"):
        reasons.append({"field": "require_llm_judge_validation", "reason": "llm_results_without_judge_would_pass"})
    if not require_authorization_boundary_coverage:
        reasons.append({
            "field": "require_authorization_boundary_coverage",
            "reason": "authorization_replay_without_boundary_coverage_would_pass",
        })
    if not require_engine_artifact_accountability:
        reasons.append({
            "field": "require_engine_artifact_accountability",
            "reason": "missing_or_unverified_engine_execution_artifacts_would_pass",
        })
    if not require_confirmatory_retests:
        reasons.append({"field": "require_confirmatory_retests", "reason": "unconfirmed_blocking_findings_would_pass"})
    if require_confirmed_findings:
        reasons.append({"field": "require_confirmed_findings", "reason": "unconfirmed_blocking_findings_would_pass"})
    if not require_ticketed_blocking_vulnerabilities:
        reasons.append({
            "field": "require_ticketed_blocking_vulnerabilities",
            "reason": "known_blocking_findings_without_tickets_would_pass",
        })
    return reasons


def _enforce_gate_policy(
    *,
    payload: dict,
    allow_policy_overrides: bool,
    override_reasons: list[dict[str, object]],
) -> dict[str, object]:
    enforcement = {
        "strict_policy": _strict_gate_policy(),
        "override_reasons": override_reasons,
        "overrides_allowed": bool(allow_policy_overrides and override_reasons),
        "mode": "strict" if not override_reasons else "advisory_override",
    }
    if not override_reasons:
        return enforcement
    if not allow_policy_overrides:
        raise _message_exception(
            400,
            {
                "message": "CI/CD gate policy weakening is blocked by default.",
                "reason": "gate_policy_override_blocked",
                "override_reasons": override_reasons,
                "strict_policy": _strict_gate_policy(),
            },
        )
    if Permission.CICD_TRIGGER not in payload.get("_permissions", set()):
        raise _message_exception(
            403,
            {
                "message": "CI/CD gate policy overrides require trigger permission.",
                "reason": "gate_policy_override_permission_required",
                "override_reasons": override_reasons,
            },
        )
    return enforcement


def _engine_accountability_required_artifacts(report_artifacts: dict[str, object]) -> list[dict[str, object]]:
    accountability = report_artifacts.get("engine_accountability")
    if not isinstance(accountability, dict):
        return []
    required_artifacts = accountability.get("required_artifacts")
    if not isinstance(required_artifacts, list):
        return []
    return [item for item in required_artifacts if isinstance(item, dict)]


def _engine_accountability_continuous_artifacts(report_artifacts: dict[str, object]) -> list[dict[str, object]]:
    accountability = report_artifacts.get("engine_accountability")
    if not isinstance(accountability, dict):
        return []
    continuous_artifacts = accountability.get("continuous_artifacts")
    if not isinstance(continuous_artifacts, list):
        return []
    return [item for item in continuous_artifacts if isinstance(item, dict)]


def _engine_accountability_selection_accountability(report_artifacts: dict[str, object]) -> dict[str, object]:
    accountability = report_artifacts.get("engine_accountability")
    if not isinstance(accountability, dict):
        return {}
    selection = accountability.get("selection_accountability")
    return selection if isinstance(selection, dict) else {}


def _selection_coverage_accountability_gaps(selection_details: list[object]) -> list[dict[str, object]]:
    gaps: list[dict[str, object]] = []
    for raw_detail in selection_details:
        if not isinstance(raw_detail, dict) or raw_detail.get("status") != "trusted":
            continue
        coverage_targets = raw_detail.get("coverage_targets")
        target_names = [
            str(target)
            for target in coverage_targets
            if str(target) in _SELECTION_COVERAGE_TARGETS
        ] if isinstance(coverage_targets, list) else []
        if not target_names:
            continue

        details = raw_detail.get("coverage_target_details")
        if not isinstance(details, dict):
            gaps.append(
                _selection_coverage_gap(
                    raw_detail,
                    target=None,
                    reason="missing_coverage_target_details",
                    missing_fields=["coverage_target_details"],
                )
            )
            continue

        for target in target_names:
            target_detail = details.get(target)
            if not isinstance(target_detail, dict):
                gaps.append(
                    _selection_coverage_gap(
                        raw_detail,
                        target=target,
                        reason="missing_coverage_target_detail",
                        missing_fields=["coverage_target_details"],
                    )
                )
                continue
            missing_fields = _selection_coverage_target_missing_fields(target, target_detail)
            if missing_fields:
                gaps.append(
                    _selection_coverage_gap(
                        raw_detail,
                        target=target,
                        reason="missing_coverage_target_fields",
                        missing_fields=missing_fields,
                    )
                )
                continue
            readiness_fields = _selection_coverage_target_not_ready_fields(target, target_detail)
            if readiness_fields:
                gaps.append(
                    _selection_coverage_gap(
                        raw_detail,
                        target=target,
                        reason="coverage_target_not_ready",
                        missing_fields=readiness_fields,
                    )
                )
    return gaps


def _selection_coverage_target_missing_fields(target: str, target_detail: dict[str, object]) -> list[str]:
    missing = [
        field
        for field in _SELECTION_COVERAGE_REQUIRED_FIELDS
        if field not in target_detail
    ]
    if "signals" in target_detail and not isinstance(target_detail.get("signals"), list):
        missing.append("signals")
    if (
        target in _SELECTION_COVERAGE_ACTIVE_FAMILY_TARGETS
        and target_detail.get("template_requested") is True
    ):
        active_families = target_detail.get("active_test_families")
        if not isinstance(active_families, dict) or not active_families:
            missing.append("active_test_families")
    if target == "authorization" and target_detail.get("template_requested") is True:
        for field in _SELECTION_COVERAGE_AUTHORIZATION_REQUIRED_FIELDS:
            if not isinstance(target_detail.get(field), dict) or not target_detail.get(field):
                missing.append(field)
        identity_context = target_detail.get("identity_context")
        if isinstance(identity_context, dict):
            for field in _SELECTION_COVERAGE_AUTHORIZATION_IDENTITY_FIELDS:
                if field not in identity_context:
                    missing.append(f"identity_context.{field}")
        readiness = target_detail.get("readiness")
        if isinstance(readiness, dict):
            for field in _SELECTION_COVERAGE_AUTHORIZATION_READINESS_FIELDS:
                if field not in readiness:
                    missing.append(f"readiness.{field}")
    return sorted(set(missing))


def _selection_coverage_target_not_ready_fields(target: str, target_detail: dict[str, object]) -> list[str]:
    if target_detail.get("template_requested") is not True:
        return []
    if not _selection_coverage_target_claims_available(target_detail):
        return []
    if target == "authorization":
        return _selection_coverage_authorization_not_ready_fields(target_detail)
    if target not in _SELECTION_COVERAGE_ACTIVE_FAMILY_TARGETS:
        return []
    active_families = target_detail.get("active_test_families")
    if not isinstance(active_families, dict):
        return []
    if any(
        isinstance(family, dict) and family.get("ready") is True
        for family in active_families.values()
    ):
        return []
    return ["active_test_families.ready"]


def _selection_coverage_authorization_not_ready_fields(target_detail: dict[str, object]) -> list[str]:
    readiness = target_detail.get("readiness")
    if not isinstance(readiness, dict):
        return []
    if any(
        readiness.get(field) is True
        for field in _SELECTION_COVERAGE_AUTHORIZATION_REPLAY_READY_FIELDS
    ):
        return []
    return sorted(
        f"readiness.{field}"
        for field in _SELECTION_COVERAGE_AUTHORIZATION_REPLAY_READY_FIELDS
    )


def _selection_coverage_target_claims_available(target_detail: dict[str, object]) -> bool:
    status = str(target_detail.get("status") or "").strip().lower()
    return status in {"available", "ready"} or target_detail.get("template_covered") is True


def _selection_coverage_gap(
    detail: dict[str, object],
    *,
    target: str | None,
    reason: str,
    missing_fields: list[str],
) -> dict[str, object]:
    gap = {
        "engine": Redactor.redact_text(str(detail.get("engine") or "")),
        "artifact_type": Redactor.redact_text(str(detail.get("artifact_type") or "")),
        "reason": reason,
        "missing_fields": missing_fields,
    }
    if target is not None:
        gap["target"] = target
    return gap


def _apply_engine_artifact_accountability_gate(
    decision: dict[str, object],
    report_artifacts: dict[str, object],
    *,
    required: bool,
) -> dict[str, object]:
    policy = decision.get("policy")
    if isinstance(policy, dict):
        policy["require_engine_artifact_accountability"] = required

    required_artifacts = _engine_accountability_required_artifacts(report_artifacts)
    missing_artifacts = [
        artifact
        for artifact in required_artifacts
        if artifact.get("status") == "missing" or artifact.get("present") is False
    ]
    unverified_artifacts = [
        artifact
        for artifact in required_artifacts
        if artifact.get("status") == "unverified" or (
            artifact.get("present") is True and artifact.get("verified") is not True
        )
    ]
    duplicate_artifacts = [
        artifact
        for artifact in required_artifacts
        if artifact.get("status") == "duplicate_artifact"
    ]
    incomplete_worker_isolation_artifacts = [
        artifact
        for artifact in required_artifacts
        if artifact.get("status") == "worker_isolation_incomplete"
    ]
    content_governance_failed_artifacts = [
        artifact
        for artifact in required_artifacts
        if artifact.get("status") == "artifact_content_governance_failed"
    ]
    continuous_artifacts = _engine_accountability_continuous_artifacts(report_artifacts)
    missing_continuous_artifacts = [
        artifact
        for artifact in continuous_artifacts
        if artifact.get("status") == "missing" or artifact.get("present") is False
    ]
    unverified_continuous_artifacts = [
        artifact
        for artifact in continuous_artifacts
        if artifact.get("status") == "unverified" or (
            artifact.get("present") is True and artifact.get("verified") is not True
        )
    ]
    duplicate_continuous_artifacts = [
        artifact
        for artifact in continuous_artifacts
        if artifact.get("status") == "duplicate_artifact"
    ]
    incomplete_continuous_worker_isolation_artifacts = [
        artifact
        for artifact in continuous_artifacts
        if artifact.get("status") == "worker_isolation_incomplete"
    ]
    content_governance_failed_continuous_artifacts = [
        artifact
        for artifact in continuous_artifacts
        if artifact.get("status") == "artifact_content_governance_failed"
    ]

    counts = decision.get("counts")
    if isinstance(counts, dict):
        counts["missing_engine_execution_artifacts"] = len(missing_artifacts)
        counts["unverified_engine_execution_artifacts"] = len(unverified_artifacts)
        counts["duplicate_engine_execution_artifacts"] = len(duplicate_artifacts)
        counts["incomplete_worker_isolation_engine_artifacts"] = len(
            incomplete_worker_isolation_artifacts
        )
        counts["content_governance_failed_engine_artifacts"] = len(
            content_governance_failed_artifacts
        )
        counts["missing_continuous_engine_artifacts"] = len(missing_continuous_artifacts)
        counts["unverified_continuous_engine_artifacts"] = len(unverified_continuous_artifacts)
        counts["duplicate_continuous_engine_artifacts"] = len(duplicate_continuous_artifacts)
        counts["incomplete_worker_isolation_continuous_artifacts"] = len(
            incomplete_continuous_worker_isolation_artifacts
        )
        counts["content_governance_failed_continuous_artifacts"] = len(
            content_governance_failed_continuous_artifacts
        )

    decision["missing_engine_execution_artifacts"] = missing_artifacts[:25]
    decision["unverified_engine_execution_artifacts"] = unverified_artifacts[:25]
    decision["duplicate_engine_execution_artifacts"] = duplicate_artifacts[:25]
    decision["incomplete_worker_isolation_engine_artifacts"] = (
        incomplete_worker_isolation_artifacts[:25]
    )
    decision["content_governance_failed_engine_artifacts"] = (
        content_governance_failed_artifacts[:25]
    )
    decision["missing_continuous_engine_artifacts"] = missing_continuous_artifacts[:25]
    decision["unverified_continuous_engine_artifacts"] = unverified_continuous_artifacts[:25]
    decision["duplicate_continuous_engine_artifacts"] = duplicate_continuous_artifacts[:25]
    decision["incomplete_worker_isolation_continuous_artifacts"] = (
        incomplete_continuous_worker_isolation_artifacts[:25]
    )
    decision["content_governance_failed_continuous_artifacts"] = (
        content_governance_failed_continuous_artifacts[:25]
    )

    selection_accountability = _engine_accountability_selection_accountability(report_artifacts)
    selection_details = selection_accountability.get("engine_details")
    if not isinstance(selection_details, list):
        selection_details = []
    missing_selection = [
        detail
        for detail in selection_details
        if isinstance(detail, dict)
        and detail.get("status") == "missing_selection_accountability"
    ]
    unverified_selection = [
        detail
        for detail in selection_details
        if isinstance(detail, dict)
        and detail.get("status") == "unverified_artifact"
    ]
    coverage_gaps = _selection_coverage_accountability_gaps(selection_details)
    if isinstance(counts, dict):
        counts["missing_selection_accountability"] = len(missing_selection)
        counts["unverified_selection_accountability"] = len(unverified_selection)
        counts["selection_coverage_accountability_gaps"] = len(coverage_gaps)
    decision["missing_selection_accountability"] = missing_selection[:25]
    decision["unverified_selection_accountability"] = unverified_selection[:25]
    decision["selection_coverage_accountability_gaps"] = coverage_gaps[:25]

    if not required:
        return decision

    accountability = report_artifacts.get("engine_accountability")
    if not isinstance(accountability, dict) or accountability.get("required") is not True:
        return decision
    if (
        decision.get("status") == "PASSED"
        and (
            content_governance_failed_artifacts
            or content_governance_failed_continuous_artifacts
        )
    ):
        decision["status"] = "FAILED"
        decision["passed"] = False
        decision["reason"] = "artifact_content_governance_failed"
        decision["exit_code"] = 1
    if (
        decision.get("status") == "PASSED"
        and (
            incomplete_worker_isolation_artifacts
            or incomplete_continuous_worker_isolation_artifacts
        )
    ):
        decision["status"] = "FAILED"
        decision["passed"] = False
        decision["reason"] = "incomplete_worker_isolation_artifacts"
        decision["exit_code"] = 1
    if (
        decision.get("status") == "PASSED"
        and (duplicate_artifacts or duplicate_continuous_artifacts)
    ):
        decision["status"] = "FAILED"
        decision["passed"] = False
        decision["reason"] = "duplicate_engine_execution_artifacts"
        decision["exit_code"] = 1
    if accountability.get("complete") is not True and decision.get("status") == "PASSED":
        decision["status"] = "FAILED"
        decision["passed"] = False
        decision["reason"] = "incomplete_engine_artifact_accountability"
        decision["exit_code"] = 1
    if (
        decision.get("status") == "PASSED"
        and selection_accountability.get("scan_plan_context_present") is True
        and selection_accountability.get("selection_accountability_complete") is not True
    ):
        decision["status"] = "FAILED"
        decision["passed"] = False
        decision["reason"] = "incomplete_selection_accountability"
        decision["exit_code"] = 1
    if (
        decision.get("status") == "PASSED"
        and selection_accountability.get("scan_plan_context_present") is True
        and coverage_gaps
    ):
        decision["status"] = "FAILED"
        decision["passed"] = False
        decision["reason"] = "incomplete_selection_coverage_accountability"
        decision["exit_code"] = 1
    return decision


def _run_scope_ids(run: TestRun, results: list[TestResult]) -> tuple[set[str], set[str]]:
    endpoint_ids = {
        str(value)
        for value in (getattr(run, "endpoint_ids", None) or [])
        if value
    }
    template_ids = {
        str(value)
        for value in (getattr(run, "template_ids", None) or [])
        if value
    }
    for result in results:
        if result.endpoint_id:
            endpoint_ids.add(str(result.endpoint_id))
        if result.template_id:
            template_ids.add(str(result.template_id))
    return endpoint_ids, template_ids


async def _load_scoped_blocking_vulnerabilities(
    db: AsyncSession,
    *,
    account_id: int,
    run: TestRun,
    results: list[TestResult],
    fail_on: str,
) -> list[Vulnerability]:
    fail_on_severities = parse_fail_on(fail_on)
    if not fail_on_severities:
        return []

    endpoint_ids, template_ids = _run_scope_ids(run, results)
    if not endpoint_ids and not template_ids:
        return []

    filters = [
        Vulnerability.account_id == account_id,
        Vulnerability.severity.in_(sorted(fail_on_severities)),
        Vulnerability.false_positive.is_(False),
        Vulnerability.status.notin_(sorted(_TICKET_REQUIRED_STOPPED_STATUSES)),
    ]
    if endpoint_ids:
        filters.append(Vulnerability.endpoint_id.in_(sorted(endpoint_ids)))
    elif template_ids:
        filters.append(Vulnerability.template_id.in_(sorted(template_ids)))

    result = await db.execute(select(Vulnerability).where(*filters))
    return list(result.scalars().all())


def _blocking_vulnerability_summary(vulnerability: Vulnerability) -> dict[str, object]:
    sla = vulnerability_sla_status(vulnerability)
    ticket_url = str(getattr(vulnerability, "ticket_url", "") or "").strip()
    sync = latest_ticket_sync(getattr(vulnerability, "evidence", None))
    sync_health = _ticket_sync_health(sync)
    summary = {
        "vulnerability_id": vulnerability.id,
        "endpoint_id": vulnerability.endpoint_id,
        "template_id": vulnerability.template_id,
        "severity": str(vulnerability.severity or "UNKNOWN").upper(),
        "status": vulnerability.status,
        "confidence": vulnerability.confidence,
        "type": vulnerability.type,
        "method": vulnerability.method,
        "url": Redactor.redact_url(vulnerability.url) if vulnerability.url else None,
        "ticket_url_present": bool(ticket_url),
        "ticket_url": Redactor.redact_url(ticket_url) if ticket_url else None,
        "sla_status": sla.get("status"),
        "sla_due_at": sla.get("due_at"),
        "sla_breached": sla.get("breached") is True,
        "confirmation_status": confirmation_status_from_evidence(vulnerability.evidence),
    }
    if isinstance(sync, dict):
        summary.update(
            {
                "ticket_sync_present": True,
                "ticket_sync_reason": sync.get("reason"),
                "ticket_sync_external_status": sync.get("external_status"),
                "ticket_sync_synced_at": sync.get("synced_at"),
                "ticket_sync_health": sync_health["status"],
                "ticket_sync_health_reason": sync_health["reason"],
                "latest_ticket_sync": sync,
            }
        )
        for key in ("ticket_sync_age_seconds", "ticket_sync_max_age_seconds"):
            if key in sync_health:
                summary[key] = sync_health[key]
    return {key: value for key, value in summary.items() if value is not None}


def _ticket_sync_health(sync: object) -> dict[str, object]:
    if not isinstance(sync, dict):
        return {"status": "unknown", "reason": "missing_ticket_sync"}

    sync_status = str(sync.get("sync_status") or sync.get("status") or "").strip().upper()
    if sync_status in _FAILED_TICKET_SYNC_STATUSES:
        return {"status": "unhealthy", "reason": "ticket_sync_failed"}

    reason = str(sync.get("reason") or "").strip()
    if reason == "ticket_open":
        return {"status": "unhealthy", "reason": "ticket_not_in_remediation"}
    if reason == "ticket_status_unmapped":
        return {"status": "unhealthy", "reason": "ticket_status_unmapped"}

    retest_decision = sync.get("retest_decision")
    if isinstance(retest_decision, dict) and retest_decision.get("status") == "not_queued":
        return {"status": "unhealthy", "reason": "ticket_retest_not_queued"}

    closure_gate = sync.get("closure_gate")
    if (
        reason == "ticket_resolved_requires_confirmatory_retest"
        and isinstance(closure_gate, dict)
        and closure_gate.get("ready_for_closure") is not True
    ):
        return {"status": "unhealthy", "reason": "ticket_resolved_without_confirmatory_retest"}

    synced_at = _parse_ticket_sync_timestamp(sync.get("synced_at"))
    if synced_at is not None:
        now = datetime.datetime.now(datetime.timezone.utc)
        age_seconds = max(0, int((now - synced_at).total_seconds()))
        if age_seconds > _TICKET_SYNC_MAX_AGE_SECONDS:
            return {
                "status": "unhealthy",
                "reason": "stale_ticket_sync",
                "ticket_sync_age_seconds": age_seconds,
                "ticket_sync_max_age_seconds": _TICKET_SYNC_MAX_AGE_SECONDS,
            }

    return {"status": "healthy", "reason": "ticket_sync_current"}


def _parse_ticket_sync_timestamp(value: object) -> datetime.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        parsed = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def _apply_lifecycle_ticketing_gate(
    decision: dict[str, object],
    vulnerabilities: list[Vulnerability],
    *,
    required: bool,
) -> dict[str, object]:
    policy = decision.get("policy")
    if isinstance(policy, dict):
        policy["require_ticketed_blocking_vulnerabilities"] = required

    summaries = [_blocking_vulnerability_summary(vulnerability) for vulnerability in vulnerabilities]
    unticketed = [summary for summary in summaries if summary.get("ticket_url_present") is not True]
    unhealthy_ticket_syncs = [
        summary
        for summary in summaries
        if summary.get("ticket_url_present") is True and summary.get("ticket_sync_health") == "unhealthy"
    ]
    overdue = [
        summary
        for summary in summaries
        if summary.get("sla_status") == "OVERDUE" or summary.get("sla_breached") is True
    ]

    counts = decision.get("counts")
    if isinstance(counts, dict):
        counts["scoped_blocking_vulnerabilities"] = len(summaries)
        counts["ticketed_blocking_vulnerabilities"] = len(summaries) - len(unticketed)
        counts["unticketed_blocking_vulnerabilities"] = len(unticketed)
        counts["unhealthy_ticket_sync_blocking_vulnerabilities"] = len(unhealthy_ticket_syncs)
        counts["overdue_blocking_vulnerabilities"] = len(overdue)

    decision["lifecycle_ticketing"] = {
        "required": required,
        "scoped_blocking_vulnerability_count": len(summaries),
        "ticketed_blocking_vulnerability_count": len(summaries) - len(unticketed),
        "unticketed_blocking_vulnerability_count": len(unticketed),
        "unhealthy_ticket_sync_blocking_vulnerability_count": len(unhealthy_ticket_syncs),
        "overdue_blocking_vulnerability_count": len(overdue),
        "ticketing_complete": not unticketed and not unhealthy_ticket_syncs,
        "blocking_vulnerabilities": summaries[:25],
    }
    decision["unticketed_blocking_vulnerabilities"] = unticketed[:25]
    decision["unhealthy_ticket_sync_blocking_vulnerabilities"] = unhealthy_ticket_syncs[:25]
    decision["overdue_blocking_vulnerabilities"] = overdue[:25]

    if required and unticketed and decision.get("status") == "PASSED":
        decision["status"] = "FAILED"
        decision["passed"] = False
        decision["reason"] = "unticketed_blocking_vulnerabilities"
        decision["exit_code"] = 1
    elif required and unhealthy_ticket_syncs and decision.get("status") == "PASSED":
        decision["status"] = "FAILED"
        decision["passed"] = False
        decision["reason"] = "unhealthy_ticket_sync_blocking_vulnerabilities"
        decision["exit_code"] = 1

    return decision


def _decision_quota_payload(quota: QuotaStatus) -> dict[str, object]:
    return {"remaining": quota.remaining, "reset_at": quota.reset_at}


async def _enforce_gate_quota(account_id: int) -> QuotaStatus:
    quota = await check_cicd_gate_quota(account_id)
    if quota.allowed:
        return quota
    raise _message_exception(
        429,
        {
            "message": "CI/CD gate quota exceeded.",
            "reason": "cicd_gate_quota_exceeded",
            "quota": _decision_quota_payload(quota),
        },
    )


async def _audit_gate_decision(
    db: AsyncSession,
    *,
    payload: dict,
    run: TestRun,
    decision: dict[str, object],
    policy_pack: str,
    trigger_id: str | None = None,
) -> None:
    integrity = decision.get("decision_integrity") if isinstance(decision.get("decision_integrity"), dict) else {}
    await log_action(
        db,
        action="CICD_GATE_EVALUATED",
        resource_type="cicd_gate",
        resource_id=run.id,
        user_id=str(payload.get("user_id") or payload.get("sub") or "") or None,
        account_id=run.account_id,
        details={
            "status": decision.get("status"),
            "passed": decision.get("passed"),
            "reason": decision.get("reason"),
            "exit_code": decision.get("exit_code"),
            "trigger_id": trigger_id,
            "policy_pack": policy_pack,
            "policy": decision.get("policy"),
            "policy_enforcement": decision.get("policy_enforcement"),
            "counts": decision.get("counts"),
            "report_artifacts": decision.get("report_artifacts"),
            "decision_hash": integrity.get("decision_hash"),
            "hash_algorithm": integrity.get("hash_algorithm"),
            "signature_algorithm": integrity.get("signature_algorithm"),
            "decision_signature": integrity.get("decision_signature"),
        },
    )


async def _evaluate_gate_response(
    *,
    request: Request,
    db: AsyncSession,
    payload: dict,
    run: TestRun,
    results: list[TestResult],
    auth_context: dict[str, object],
    policy_pack: str,
    fail_on: str,
    fail_on_errors: bool,
    fail_on_no_execution: bool,
    fail_on_unauthenticated: bool,
    require_evidence_integrity: bool,
    require_evidence_completeness: bool,
    require_safety_policies: bool,
    require_retest_support: bool,
    require_llm_judge_validation: bool,
    require_authorization_boundary_coverage: bool,
    require_engine_artifact_accountability: bool,
    require_confirmatory_retests: bool,
    require_confirmed_findings: bool,
    require_ticketed_blocking_vulnerabilities: bool,
    allow_policy_overrides: bool,
    trigger_id: str | None = None,
) -> dict[str, object]:
    quota = await _enforce_gate_quota(run.account_id)
    gate_policy = _resolve_gate_policy(
        request=request,
        policy_pack=policy_pack,
        fail_on=fail_on,
        fail_on_errors=fail_on_errors,
        fail_on_no_execution=fail_on_no_execution,
        fail_on_unauthenticated=fail_on_unauthenticated,
        require_evidence_integrity=require_evidence_integrity,
        require_evidence_completeness=require_evidence_completeness,
        require_safety_policies=require_safety_policies,
        require_retest_support=require_retest_support,
        require_llm_judge_validation=require_llm_judge_validation,
        require_authorization_boundary_coverage=require_authorization_boundary_coverage,
        require_engine_artifact_accountability=require_engine_artifact_accountability,
        require_confirmatory_retests=require_confirmatory_retests,
        require_confirmed_findings=require_confirmed_findings,
        require_ticketed_blocking_vulnerabilities=require_ticketed_blocking_vulnerabilities,
    )
    override_reasons = _gate_policy_override_reasons(
        fail_on=str(gate_policy["fail_on"]),
        fail_on_errors=bool(gate_policy["fail_on_errors"]),
        fail_on_no_execution=bool(gate_policy["fail_on_no_execution"]),
        fail_on_unauthenticated=bool(gate_policy["fail_on_unauthenticated"]),
        require_evidence_integrity=bool(gate_policy["require_evidence_integrity"]),
        require_evidence_completeness=bool(gate_policy["require_evidence_completeness"]),
        require_safety_policies=bool(gate_policy["require_safety_policies"]),
        require_retest_support=bool(gate_policy["require_retest_support"]),
        require_llm_judge_validation=bool(gate_policy["require_llm_judge_validation"]),
        require_authorization_boundary_coverage=bool(gate_policy["require_authorization_boundary_coverage"]),
        require_engine_artifact_accountability=bool(gate_policy["require_engine_artifact_accountability"]),
        require_confirmatory_retests=bool(gate_policy["require_confirmatory_retests"]),
        require_confirmed_findings=bool(gate_policy["require_confirmed_findings"]),
        require_ticketed_blocking_vulnerabilities=bool(gate_policy["require_ticketed_blocking_vulnerabilities"]),
    )
    enforcement = _enforce_gate_policy(
        payload=payload,
        allow_policy_overrides=allow_policy_overrides,
        override_reasons=override_reasons,
    )
    execution_artifacts = await _load_execution_artifacts(db, run_id=run.id, account_id=run.account_id)
    decision = evaluate_quality_gate(
        run,
        results,
        fail_on=str(gate_policy["fail_on"]),
        fail_on_errors=bool(gate_policy["fail_on_errors"]),
        fail_on_no_execution=bool(gate_policy["fail_on_no_execution"]),
        fail_on_unauthenticated=bool(gate_policy["fail_on_unauthenticated"]),
        require_evidence_integrity=bool(gate_policy["require_evidence_integrity"]),
        require_evidence_completeness=bool(gate_policy["require_evidence_completeness"]),
        require_safety_policies=bool(gate_policy["require_safety_policies"]),
        require_retest_support=bool(gate_policy["require_retest_support"]),
        require_llm_judge_validation=bool(gate_policy["require_llm_judge_validation"]),
        require_authorization_boundary_coverage=bool(gate_policy["require_authorization_boundary_coverage"]),
        require_engine_artifacts=bool(gate_policy["require_engine_artifact_accountability"]),
        require_confirmatory_retests=bool(gate_policy["require_confirmatory_retests"]),
        require_confirmed_findings=bool(gate_policy["require_confirmed_findings"]),
        execution_artifacts=_execution_artifact_payloads(execution_artifacts),
        authenticated_context=bool(auth_context["authenticated"]),
        auth_profile_id=auth_context.get("auth_profile_id"),
        auth_context_reason=auth_context.get("reason"),
        auth_context_metadata=_gate_auth_context_metadata(auth_context),
    )
    if trigger_id:
        decision["trigger_id"] = trigger_id
    decision["policy"]["policy_pack"] = gate_policy["name"]
    decision["quota"] = _decision_quota_payload(quota)
    decision["policy_enforcement"] = enforcement
    decision["report_artifacts"] = build_report_artifact_manifest(
        run,
        results,
        execution_artifacts=execution_artifacts,
    )
    decision = _apply_engine_artifact_accountability_gate(
        decision,
        decision["report_artifacts"],
        required=bool(gate_policy["require_engine_artifact_accountability"]),
    )
    scoped_blocking_vulnerabilities = await _load_scoped_blocking_vulnerabilities(
        db,
        account_id=run.account_id,
        run=run,
        results=results,
        fail_on=str(gate_policy["fail_on"]),
    )
    decision = _apply_lifecycle_ticketing_gate(
        decision,
        scoped_blocking_vulnerabilities,
        required=bool(gate_policy["require_ticketed_blocking_vulnerabilities"]),
    )
    decision = attach_decision_integrity(decision)
    await _audit_gate_decision(
        db,
        payload=payload,
        run=run,
        decision=decision,
        policy_pack=str(gate_policy["name"]),
        trigger_id=trigger_id,
    )
    await db.commit()
    return decision


async def _manual_trigger_auth_context(
    db: AsyncSession,
    *,
    account_id: int,
    pentest_profile_id: str | None,
    target_url: str,
    allow_unauthenticated: bool,
) -> tuple[PentestProfile | None, AuthProfile | None, dict[str, object]]:
    if not pentest_profile_id:
        context = {
            "authenticated": False,
            "pentest_profile_id": None,
            "auth_profile_id": None,
            "reason": "missing_pentest_profile",
        }
        if allow_unauthenticated:
            return None, None, context
        raise _message_exception(400, {"reason": "auth_profile_required", "auth_context": context})

    result = await db.execute(
        select(PentestProfile).where(
            PentestProfile.id == pentest_profile_id,
            PentestProfile.account_id == account_id,
        )
    )
    profile = result.scalar_one_or_none()
    if profile is None:
        raise _message_exception(400, {"reason": "pentest_profile_not_found"})

    auth_profile = None
    if profile.auth_profile_id:
        auth_result = await db.execute(
            select(AuthProfile).where(
                AuthProfile.id == profile.auth_profile_id,
                AuthProfile.account_id == account_id,
                AuthProfile.is_active.is_(True),
            )
        )
        auth_profile = auth_result.scalar_one_or_none()

    if auth_profile is None or not auth_profile_has_runtime_material(auth_profile):
        context = {
            "authenticated": False,
            "pentest_profile_id": profile.id,
            "auth_profile_id": profile.auth_profile_id,
            "reason": "auth_profile_missing_runtime_credentials",
        }
        if allow_unauthenticated:
            return profile, auth_profile, context
        raise _message_exception(400, {"reason": "auth_profile_required", "auth_context": context})

    try:
        validate_auth_profile_scope(auth_profile, target_url)
    except AuthScopeError as exc:
        raise _message_exception(
            400,
            {
                "reason": "auth_profile_scope_blocked",
                "auth_profile_scope_policy": auth_scope_policy_for_error(
                    exc,
                    auth_profile=auth_profile,
                    target_url=target_url,
                    base_url=target_url,
                ),
            },
        ) from exc

    return profile, auth_profile, {
        "authenticated": True,
        "pentest_profile_id": profile.id,
        "auth_profile_id": auth_profile.id,
        "reason": "auth_profile_ready",
    }


@router.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None),
    x_account_id: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    body = await request.body()
    secret = str(getattr(settings, "GITHUB_WEBHOOK_SECRET", "") or "")
    if not secret:
        raise _message_exception(503, "GitHub webhook secret is not configured")
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(x_hub_signature_256 or "", expected):
        raise HTTPException(401, "Invalid webhook signature")

    account_id = _resolve_webhook_account_id(x_account_id)
    payload = await request.json()
    trigger = CICDTrigger(
        id=str(uuid.uuid4()),
        account_id=account_id,
        source="github",
        commit_sha=payload.get("after", "") or payload.get("pull_request", {}).get("head", {}).get("sha", ""),
        branch=str(payload.get("ref", "")).replace("refs/heads/", ""),
        repo=payload.get("repository", {}).get("full_name", ""),
        status="QUEUED",
        webhook_payload=_safe_webhook_payload(payload),
    )
    db.add(trigger)
    await db.commit()
    return {"trigger_id": trigger.id, "status": "QUEUED", "event": x_github_event}


@router.post("/webhook/gitlab")
async def gitlab_webhook(
    request: Request,
    x_gitlab_token: Optional[str] = Header(None),
    x_gitlab_event: Optional[str] = Header(None),
    x_account_id: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    secret = str(getattr(settings, "GITLAB_WEBHOOK_SECRET", "") or "")
    if secret and x_gitlab_token != secret:
        raise HTTPException(401, "Invalid GitLab token")
    account_id = _resolve_webhook_account_id(x_account_id)
    payload = await request.json()
    trigger = CICDTrigger(
        id=str(uuid.uuid4()),
        account_id=account_id,
        source="gitlab",
        commit_sha=payload.get("checkout_sha", ""),
        branch=str(payload.get("ref", "")).replace("refs/heads/", ""),
        repo=payload.get("project", {}).get("path_with_namespace", ""),
        status="QUEUED",
        webhook_payload=_safe_webhook_payload(payload),
    )
    db.add(trigger)
    await db.commit()
    return {"trigger_id": trigger.id, "status": "QUEUED", "event": x_gitlab_event}


@router.post("/trigger")
async def manual_trigger(
    target_url: str = Body(...),
    template_ids: list = Body(default=[]),
    collection_id: Optional[str] = Body(None),
    branch: str = Body("main"),
    source: str = Body("manual"),
    commit_sha: str = Body(""),
    pentest_profile_id: Optional[str] = Body(None),
    allow_unauthenticated: bool = Body(False),
    payload: dict = Depends(can_trigger_cicd),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    try:
        validate_pentest_target(target_url)
    except Exception as exc:
        from server.modules.test_executor.target_guard import TargetGuardError

        if isinstance(exc, TargetGuardError):
            raise _message_exception(
                400,
                {
                    "reason": "target_guard_blocked",
                    "target_guard_policy": target_guard_policy_for_error(
                        exc,
                        fallback_url=target_url,
                        fallback_base_url=target_url,
                    ),
                },
            ) from exc
        raise

    profile, auth_profile, auth_context = await _manual_trigger_auth_context(
        db,
        account_id=account_id,
        pentest_profile_id=pentest_profile_id,
        target_url=target_url,
        allow_unauthenticated=allow_unauthenticated,
    )
    trigger_payload = _safe_webhook_payload(
        {
            "target_url": target_url,
            "template_ids": template_ids,
            "collection_id": collection_id,
            "pentest_profile_id": profile.id if profile is not None else pentest_profile_id,
            "auth_profile_id": auth_profile.id if auth_profile is not None else None,
            "auth_context": auth_context,
            "allow_unauthenticated": allow_unauthenticated,
        }
    )
    trigger = CICDTrigger(
        id=str(uuid.uuid4()),
        account_id=account_id,
        source=source,
        commit_sha=commit_sha,
        branch=branch,
        status="QUEUED",
        webhook_payload=trigger_payload,
    )
    db.add(trigger)
    await db.commit()
    return {"trigger_id": trigger.id, "status": "QUEUED", "auth_context": auth_context}


@router.get("/triggers")
async def list_triggers(
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    source: Optional[str] = Query(None),
    limit: int = Query(50),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    q = select(CICDTrigger).where(CICDTrigger.account_id == account_id)
    if source:
        q = q.where(CICDTrigger.source == source)
    result = await db.execute(q.order_by(CICDTrigger.created_at.desc()).limit(limit))
    triggers = result.scalars().all()
    return {
        "total": len(triggers),
        "triggers": [
            {
                "id": t.id,
                "source": t.source,
                "repo": t.repo,
                "branch": t.branch,
                "commit_sha": t.commit_sha,
                "status": t.status,
                "test_run_id": t.test_run_id,
                "created_at": t.created_at,
            }
            for t in triggers
        ],
    }


@router.get("/gate/{run_id}")
async def evaluate_run_gate(
    request: Request,
    run_id: str,
    policy_pack: str = Query("strict", description="Named CI/CD policy pack"),
    fail_on: str = Query("CRITICAL,HIGH"),
    fail_on_errors: bool = Query(True),
    fail_on_no_execution: bool = Query(True),
    fail_on_unauthenticated: bool = Query(True),
    require_evidence_integrity: bool = Query(True),
    require_evidence_completeness: bool = Query(True),
    require_safety_policies: bool = Query(True),
    require_retest_support: bool = Query(True),
    require_llm_judge_validation: bool = Query(False),
    require_authorization_boundary_coverage: bool = Query(True),
    require_engine_artifact_accountability: bool = Query(True),
    require_confirmatory_retests: bool = Query(True),
    require_confirmed_findings: bool = Query(False),
    require_ticketed_blocking_vulnerabilities: bool = Query(True),
    allow_policy_overrides: bool = Query(False),
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    run, results, auth_context = await _load_run_for_gate(db, account_id=account_id, run_id=run_id)
    return await _evaluate_gate_response(
        request=request,
        db=db,
        payload=payload,
        run=run,
        results=results,
        auth_context=auth_context,
        policy_pack=policy_pack,
        fail_on=fail_on,
        fail_on_errors=fail_on_errors,
        fail_on_no_execution=fail_on_no_execution,
        fail_on_unauthenticated=fail_on_unauthenticated,
        require_evidence_integrity=require_evidence_integrity,
        require_evidence_completeness=require_evidence_completeness,
        require_safety_policies=require_safety_policies,
        require_retest_support=require_retest_support,
        require_llm_judge_validation=require_llm_judge_validation,
        require_authorization_boundary_coverage=require_authorization_boundary_coverage,
        require_engine_artifact_accountability=require_engine_artifact_accountability,
        require_confirmatory_retests=require_confirmatory_retests,
        require_confirmed_findings=require_confirmed_findings,
        require_ticketed_blocking_vulnerabilities=require_ticketed_blocking_vulnerabilities,
        allow_policy_overrides=allow_policy_overrides,
    )


@router.get("/gate/{run_id}/sarif")
async def export_run_gate_sarif(
    run_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    run, results, _ = await _load_run_for_gate(db, account_id=account_id, run_id=run_id)
    await _enforce_gate_quota(account_id)
    return build_sarif(run, results)


@router.get("/gate/{run_id}/junit", response_class=Response)
async def export_run_gate_junit(
    run_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    run, results, _ = await _load_run_for_gate(db, account_id=account_id, run_id=run_id)
    await _enforce_gate_quota(account_id)
    return PlainTextResponse(content=build_junit(run, results), media_type="application/xml")


@router.get("/triggers/{trigger_id}/gate")
async def evaluate_trigger_gate(
    request: Request,
    trigger_id: str,
    policy_pack: str = Query("strict"),
    fail_on: str = Query("CRITICAL,HIGH"),
    fail_on_errors: bool = Query(True),
    fail_on_no_execution: bool = Query(True),
    fail_on_unauthenticated: bool = Query(True),
    require_evidence_integrity: bool = Query(True),
    require_evidence_completeness: bool = Query(True),
    require_safety_policies: bool = Query(True),
    require_retest_support: bool = Query(True),
    require_llm_judge_validation: bool = Query(False),
    require_authorization_boundary_coverage: bool = Query(True),
    require_engine_artifact_accountability: bool = Query(True),
    require_confirmatory_retests: bool = Query(True),
    require_confirmed_findings: bool = Query(False),
    require_ticketed_blocking_vulnerabilities: bool = Query(True),
    allow_policy_overrides: bool = Query(False),
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(CICDTrigger).where(
            CICDTrigger.id == _validate_uuid_or_400(trigger_id, "trigger_id"),
            CICDTrigger.account_id == account_id,
        )
    )
    trigger = result.scalar_one_or_none()
    if trigger is None:
        raise HTTPException(status_code=404, detail="Trigger not found")
    if not trigger.test_run_id:
        return {
            "status": "PENDING",
            "passed": False,
            "reason": "trigger_not_linked_to_test_run",
            "exit_code": 2,
            "trigger_id": trigger.id,
            "run_id": None,
        }
    run, results, auth_context = await _load_run_for_gate(db, account_id=account_id, run_id=trigger.test_run_id)
    return await _evaluate_gate_response(
        request=request,
        db=db,
        payload=payload,
        run=run,
        results=results,
        auth_context=auth_context,
        policy_pack=policy_pack,
        fail_on=fail_on,
        fail_on_errors=fail_on_errors,
        fail_on_no_execution=fail_on_no_execution,
        fail_on_unauthenticated=fail_on_unauthenticated,
        require_evidence_integrity=require_evidence_integrity,
        require_evidence_completeness=require_evidence_completeness,
        require_safety_policies=require_safety_policies,
        require_retest_support=require_retest_support,
        require_llm_judge_validation=require_llm_judge_validation,
        require_authorization_boundary_coverage=require_authorization_boundary_coverage,
        require_engine_artifact_accountability=require_engine_artifact_accountability,
        require_confirmatory_retests=require_confirmatory_retests,
        require_confirmed_findings=require_confirmed_findings,
        require_ticketed_blocking_vulnerabilities=require_ticketed_blocking_vulnerabilities,
        allow_policy_overrides=allow_policy_overrides,
        trigger_id=trigger.id,
    )


@router.get("/triggers/{trigger_id}")
async def get_trigger(
    trigger_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(CICDTrigger).where(
            CICDTrigger.id == _validate_uuid_or_400(trigger_id, "trigger_id"),
            CICDTrigger.account_id == account_id,
        )
    )
    trigger = result.scalar_one_or_none()
    if not trigger:
        raise HTTPException(status_code=404, detail="Trigger not found")
    return {
        "id": trigger.id,
        "source": trigger.source,
        "repo": trigger.repo,
        "branch": trigger.branch,
        "commit_sha": trigger.commit_sha,
        "status": trigger.status,
        "test_run_id": trigger.test_run_id,
        "created_at": trigger.created_at,
    }


@router.get("/badge/{account_id}", response_class=Response)
async def security_badge(account_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(CICDTrigger)
        .where(CICDTrigger.account_id == account_id)
        .order_by(CICDTrigger.created_at.desc())
        .limit(1)
    )
    trigger = result.scalar_one_or_none()
    status = trigger.status if trigger else "unknown"
    fill = "#4c1" if status == "PASSED" else "#e05d44" if status == "FAILED" else "#9f9f9f"
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="130" height="20">'
        f'<rect width="130" height="20" rx="3" fill="#555"/>'
        f'<rect x="75" width="55" height="20" rx="3" fill="{fill}"/>'
        f'<text x="37" y="14" fill="#fff" font-size="11" font-family="sans-serif">API Security</text>'
        f'<text x="102" y="14" fill="#fff" font-size="11" font-family="sans-serif" text-anchor="middle">{status}</text>'
        f"</svg>"
    )
    return Response(content=svg, media_type="image/svg+xml")


@router.get("/{run_id}/gate")
async def legacy_ci_gate_decision(
    run_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    run, results, auth_context = await _load_run_for_gate(db, account_id=account_id, run_id=run_id)
    boundary_decision = evaluate_quality_gate(
        run,
        results,
        fail_on="none",
        fail_on_errors=False,
        fail_on_no_execution=False,
        fail_on_unauthenticated=False,
        require_evidence_integrity=False,
        require_evidence_completeness=False,
        require_safety_policies=False,
        require_retest_support=False,
        require_confirmatory_retests=False,
        require_authorization_boundary_coverage=True,
        require_engine_artifacts=False,
        authenticated_context=bool(auth_context["authenticated"]),
        auth_profile_id=auth_context.get("auth_profile_id"),
        auth_context_reason=auth_context.get("reason"),
        auth_context_metadata=_gate_auth_context_metadata(auth_context),
    )
    missing_boundary_results = boundary_decision.get("missing_authorization_boundary_results")
    if not isinstance(missing_boundary_results, list):
        missing_boundary_results = []
    blocked_reasons = [
        f"missing_authorization_boundary_coverage: template={result.get('template_id')}"
        for result in missing_boundary_results
        if isinstance(result, dict)
    ]
    execution_artifacts = await _load_execution_artifacts(db, run_id=run.id, account_id=run.account_id)
    report_artifacts = build_report_artifact_manifest(
        run,
        results,
        gate_base_path="/api/cicd",
        execution_artifacts=execution_artifacts,
    )
    engine_accountability = report_artifacts.get("engine_accountability")
    if not isinstance(engine_accountability, dict):
        engine_accountability = {}
    for artifact in _engine_accountability_required_artifacts(report_artifacts):
        engine = artifact.get("engine")
        artifact_type = artifact.get("artifact_type")
        if artifact.get("status") == "missing" or artifact.get("present") is False:
            blocked_reasons.append(
                f"missing_engine_execution_artifact: engine={engine} artifact_type={artifact_type}"
            )
        elif artifact.get("status") == "duplicate_artifact":
            blocked_reasons.append(
                f"duplicate_engine_execution_artifact: engine={engine} artifact_type={artifact_type}"
            )
        elif artifact.get("status") == "worker_isolation_incomplete":
            blocked_reasons.append(
                f"incomplete_worker_isolation_artifact: engine={engine} artifact_type={artifact_type}"
            )
        elif artifact.get("status") == "artifact_content_governance_failed":
            blocked_reasons.append(
                f"artifact_content_governance_failed: engine={engine} artifact_type={artifact_type}"
            )
        elif artifact.get("status") == "unverified" or (
            artifact.get("present") is True and artifact.get("verified") is not True
        ):
            blocked_reasons.append(
                f"unverified_engine_execution_artifact: engine={engine} artifact_type={artifact_type}"
            )
    for result in results:
        if not result.is_vulnerable:
            continue
        severity = str(result.severity or "").upper()
        if severity in _STRICT_GATE_FAIL_ON:
            blocked_reasons.append(
                f"vulnerable_finding: template={result.template_id} severity={severity}"
            )
    vulnerable_count = sum(1 for result in results if result.is_vulnerable)
    return {
        "run_id": run.id,
        "run_status": run.status,
        "gate_passed": not blocked_reasons,
        "blocked": bool(blocked_reasons),
        "blocked_reasons": blocked_reasons,
        "vulnerable_count": vulnerable_count,
        "total_results": len(results),
        "authorization_boundary_coverage": {
            "required": True,
            "missing_result_count": len(missing_boundary_results),
            "missing_results": missing_boundary_results,
        },
        "engine_accountability": engine_accountability,
    }


@router.get("/{run_id}/sarif")
async def ci_sarif_export(
    run_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    run = await _load_run(db, run_id=run_id, account_id=account_id)
    results = await _load_results(db, run_id=run_id, account_id=account_id)
    return build_sarif(run, results)


@router.get("/{run_id}/junit")
async def ci_junit_export(
    run_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    run = await _load_run(db, run_id=run_id, account_id=account_id)
    results = await _load_results(db, run_id=run_id, account_id=account_id)
    return PlainTextResponse(content=build_junit(run, results), media_type="application/xml")


@router.get("/{run_id}/artifacts")
async def ci_artifact_manifest(
    run_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    run = await _load_run(db, run_id=run_id, account_id=account_id)
    results = await _load_results(db, run_id=run_id, account_id=account_id)
    execution_artifacts = await _load_execution_artifacts(db, run_id=run_id, account_id=account_id)
    return build_report_artifact_manifest(
        run,
        results,
        gate_base_path="/api/cicd",
        execution_artifacts=execution_artifacts,
    )


@router.get("/{run_id}/regressions")
async def ci_regression_check(
    run_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.CICD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    run = await _load_run(db, run_id=run_id, account_id=account_id)
    results = await _load_results(db, run_id=run_id, account_id=account_id)
    vulnerable_pairs = {
        (result.template_id, result.endpoint_id)
        for result in results
        if result.is_vulnerable and result.template_id and result.endpoint_id
    }
    reopened = []
    for template_id, endpoint_id in vulnerable_pairs:
        vuln_result = await db.execute(
            select(Vulnerability).where(
                Vulnerability.account_id == account_id,
                Vulnerability.template_id == template_id,
                Vulnerability.endpoint_id == endpoint_id,
                Vulnerability.status.in_(["CLOSED", "RESOLVED", "FALSE_POSITIVE"]),
            )
        )
        for vuln in vuln_result.scalars().all():
            sla = vulnerability_sla_status(vuln)
            reopened.append(
                {
                    "vulnerability_id": vuln.id,
                    "template_id": vuln.template_id,
                    "endpoint_id": vuln.endpoint_id,
                    "severity": vuln.severity,
                    "previous_status": vuln.status,
                    "sla_status": sla.get("status"),
                    "sla_due_at": sla.get("due_at"),
                    "url": Redactor.redact_url(vuln.url) if vuln.url else None,
                    "method": vuln.method,
                }
            )
    return {
        "run_id": run.id,
        "reopened_count": len(reopened),
        "reopened_findings": reopened,
        "has_regressions": bool(reopened),
    }
