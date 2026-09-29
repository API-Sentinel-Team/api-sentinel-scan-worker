import uuid
import datetime
import json
import logging
from fastapi import APIRouter, Depends, BackgroundTasks, Query, HTTPException, Request, Body
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy import select, update, and_
from server.config import settings
from server.modules.persistence.database import get_db, AsyncSessionLocal
from server.modules.auth.rbac import RBAC, Permission, can_run_tests
from server.modules.validation.input_validator import InputValidator, ValidationError
from server.modules.test_executor.wordlist_manager import WordlistManager
from server.modules.test_executor.execution_engine import ExecutionEngine
from server.modules.test_executor.kill_switch import KILL_SWITCH_REASON, kill_switch_enabled
from server.modules.test_executor.selection_filter import SelectionFilterEngine
from server.modules.test_executor.scan_plan import (
    build_readable_scan_plan,
    finalize_scan_plan_hash,
    normalize_test_intensity,
    verify_scan_plan_integrity,
)
from server.modules.test_executor.target_guard import TargetGuard, blocked_endpoint_targets, endpoint_target_url
from server.modules.test_executor.result_aggregator import ResultAggregator
from server.modules.test_executor.reporting import build_sarif, build_junit
from server.modules.test_executor.evidence import build_active_scan_evidence
from server.modules.test_executor.scan_worker import heartbeat_claimed_run, normalize_worker_id
from server.models.core import APIEndpoint, OpenAPISpec, TestRun, TestResult, TestAccount, Vulnerability
from server.api.websocket.manager import ws_manager
from server.api.websocket.event_types import WSEventType
from server.api.rate_limiter import limiter
from server.modules.pentest.auth_preflight import (
    ActiveScanAuthError,
    PentestProfileNotFound,
    active_scan_auth_required,
    active_scan_auth_audit_context,
    load_profile_and_auth_for_active_scan,
)
from server.modules.pentest.auth_scope import blocked_auth_profile_targets
from server.modules.pentest.engine_plan import (
    ENGINE_EXECUTION_ORDER,
    build_engine_plan,
    engine_outcome_summaries,
    engine_status_counts,
)
from server.modules.pentest.execution_artifacts import persist_execution_artifact
from server.modules.pentest.profiles import PentestProfileService
from server.modules.pentest.schemathesis_runner import SchemathesisRunner
from server.modules.nuclei.runner import NucleiRunner
from server.modules.identity.roles_context import RolesContextBuilder
from server.modules.identity.eligibility import eligible_test_accounts
from server.modules.utils.redactor import Redactor
from server.modules.vulnerability_detector.lifecycle import (
    is_vulnerability_retest_trigger_source,
    isoformat,
    latest_remediation_retest_integrity,
    retest_outcome_digest,
    utc_now,
)
from server.modules.vulnerability_detector.store import create_or_merge_vulnerability
from server.modules.agentic.finding_persistence import build_agentic_vulnerability_data
from server.modules.auth.audit import log_action
from server.modules.zap.runner import ZapRunner
from server.modules.business_logic.active_tests import (
    ACTIVE_BUSINESS_LOGIC_TEMPLATE_ID,
    build_active_business_logic_templates,
)
from server.modules.business_logic.graph_builder import get_latest_graph

router = APIRouter()
logger = logging.getLogger(__name__)
_pentest_profiles = PentestProfileService()
_CONFIRMATORY_RETEST_SEVERITIES = {"HIGH", "CRITICAL"}
_CANCEL_REQUESTED_STATUSES = {"CANCEL_REQUESTED", "CANCELED"}
_TERMINAL_RUN_STATUSES = {"COMPLETED", "FAILED", "CANCELED"}
_NON_EXECUTED_SKIP_REASONS = {
    "auth_profile_scope_guard",
    "auth_resolution_failed",
    "request_budget",
    "state_change_guard",
    "target_guard",
}
_SAFETY_POLICY_KEYS = (
    "auth_profile_scope_policy",
    "state_change_policy",
    "target_guard_policy",
)
_SCAN_PLAN_COVERAGE_TARGETS = ("authorization", "business_logic", "llm_api")
_SCAN_PLAN_COVERAGE_STATUSES = {"available", "discovered", "gap", "not_requested", "partial", "ready"}
_SCAN_PLAN_COVERAGE_SIGNALS = {
    "auth_context",
    "body_key",
    "path_hint",
    "private_identifier",
    "role_context",
    "state_changing_method",
    "tool_context",
    "workflow_path",
}
_SCAN_PLAN_COVERAGE_READINESS_KEYS = {
    "auth_context_ready",
    "bfla_replay_testable",
    "bola_replay_testable",
    "private_identifier_context_ready",
    "prompt_context_ready",
    "role_context_ready",
    "state_change_context_ready",
    "tool_abuse_testable",
    "tool_context_ready",
    "workflow_abuse_testable",
    "workflow_context_ready",
}
_ACTIVE_TEST_FAMILIES = (
    "coupon_abuse",
    "otp_spam",
    "workflow_bypass",
    "resource_exhaustion",
    "prompt_injection",
    "rag_exfiltration",
    "indirect_prompt_injection",
    "dangerous_tool_invocation",
    "privilege_escalating_tool_invocation",
    "tool_chain_injection",
)
_ACTIVE_TEST_FAMILY_STATUSES = {"ready", "missing_template", "missing_endpoint_context"}
_ACTIVE_TEST_FAMILY_SIGNALS = {
    "body_key",
    "bulk",
    "captcha",
    "cart",
    "checkout",
    "coupon",
    "discount",
    "export",
    "invoice",
    "mfa",
    "order",
    "otp",
    "path_hint",
    "payment",
    "promo",
    "referral",
    "retrieval_context",
    "search",
    "subscription",
    "tool_invocation_context",
    "tool_output_context",
    "untrusted_context",
    "upload",
    "verification",
}


def _test_result_evidence_text(
    test_result: dict,
    endpoint: dict,
    *,
    is_vulnerable: bool,
    non_executed_skip: bool,
) -> str:
    if (is_vulnerable or test_result.get("confirmation")) and not non_executed_skip:
        evidence = build_active_scan_evidence(test_result, endpoint)
        return json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
    if non_executed_skip and _has_safety_policy_metadata(test_result):
        evidence = build_active_scan_evidence(test_result, endpoint)
        return json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
    evidence = test_result.get("evidence", "")
    if isinstance(evidence, (dict, list)):
        return json.dumps(Redactor.redact_json(evidence), sort_keys=True, separators=(",", ":"), default=str)
    return str(evidence or "")


def _has_safety_policy_metadata(test_result: dict) -> bool:
    return any(isinstance(test_result.get(key), dict) for key in _SAFETY_POLICY_KEYS)


def _request_ip(request: Request | None) -> str | None:
    client = getattr(request, "client", None)
    return getattr(client, "host", None) if client else None


async def _audit_scan_event(
    db: AsyncSession,
    *,
    action: str,
    account_id: int,
    run_id: str,
    user_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    await log_action(
        db=db,
        account_id=account_id,
        action=action,
        user_id=user_id,
        resource_type="test_run",
        resource_id=run_id,
        details=details or {},
        ip_address=ip_address,
    )


async def _record_vulnerability_retest_outcome(
    db: AsyncSession,
    *,
    run_id: str,
    account_id: int,
    status: str,
    outcome: str,
    details: dict | None = None,
) -> None:
    run = (
        await db.execute(
            select(TestRun).where(and_(TestRun.id == run_id, TestRun.account_id == account_id))
        )
    ).scalar_one_or_none()
    if (
        run is None
        or not is_vulnerability_retest_trigger_source(run.trigger_source)
        or not run.source_vulnerability_id
    ):
        return

    vulnerability = (
        await db.execute(
            select(Vulnerability).where(
                and_(
                    Vulnerability.id == run.source_vulnerability_id,
                    Vulnerability.account_id == account_id,
                )
            )
        )
    ).scalar_one_or_none()
    if vulnerability is None:
        return

    now = utc_now()
    safe_details = Redactor.redact_json(details or {})
    previous_status = vulnerability.status
    retest = {
        "run_id": run_id,
        "status": status,
        "outcome": outcome,
        "completed_at": isoformat(now),
        "executed": int(safe_details.get("executed") or 0),
        "vulnerable": int(safe_details.get("vulnerable") or 0),
        "errors": int(safe_details.get("errors") or 0),
        "skipped": int(safe_details.get("skipped") or 0),
    }
    if safe_details.get("reason"):
        retest["reason"] = safe_details["reason"]
    retest["hash_algorithm"] = "sha256"
    retest["retest_hash"] = retest_outcome_digest(retest)

    evidence = dict(vulnerability.evidence or {})
    previous_retests = evidence.get("remediation_retests")
    if not isinstance(previous_retests, list):
        previous_retests = []
    evidence["remediation_retests"] = (previous_retests + [retest])[-10:]
    evidence["latest_remediation_retest"] = retest
    vulnerability.evidence = evidence

    if not vulnerability.false_positive and (vulnerability.status or "").upper() != "ACCEPTED_RISK":
        if outcome == "CLEAN":
            vulnerability.status = "CLOSED"
        elif outcome == "STILL_VULNERABLE":
            vulnerability.status = "OPEN"
            vulnerability.last_seen_at = now

    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_RETEST_COMPLETED",
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details={
            "run_id": run_id,
            "status": status,
            "outcome": outcome,
            "previous_status": previous_status,
            "new_status": vulnerability.status,
            "executed": retest["executed"],
            "vulnerable": retest["vulnerable"],
            "errors": retest["errors"],
            "skipped": retest["skipped"],
            "reason": retest.get("reason"),
            "hash_algorithm": retest["hash_algorithm"],
            "retest_hash": retest["retest_hash"],
            "retest_integrity": latest_remediation_retest_integrity(evidence),
        },
    )


async def _fail_scan_before_execution(
    db: AsyncSession,
    *,
    run_id: str,
    account_id: int,
    reason: str,
    template_ids: list[str],
    endpoint_ids: list[str],
    details: dict | None = None,
    worker_id: str | None = None,
) -> bool:
    failure_details = {
        "reason": reason,
        "template_count": len(template_ids),
        "endpoint_count": len(endpoint_ids),
        "processed": 0,
        "executed": 0,
        "vulnerable": 0,
        "errors": 1,
    }
    failure_details.update(details or {})
    update_filters = [TestRun.id == run_id, TestRun.account_id == account_id]
    if worker_id:
        update_filters.extend(
            [
                TestRun.worker_id == worker_id,
                TestRun.status.in_(["DISPATCHED", "RUNNING"]),
            ]
        )
    update_result = await db.execute(
        update(TestRun).where(and_(*update_filters)).values(
            status="FAILED",
            completed_at=datetime.datetime.now(datetime.timezone.utc),
            error_count=1,
            dispatch_lease_expires_at=None,
        )
    )
    if update_result.rowcount != 1:
        await db.rollback()
        return False
    await _record_vulnerability_retest_outcome(
        db,
        run_id=run_id,
        account_id=account_id,
        status="FAILED",
        outcome="FAILED",
        details={
            **failure_details,
            "previous_status": None,
        },
    )
    await _audit_scan_event(
        db,
        action="SCAN_RUN_FAILED",
        account_id=account_id,
        run_id=run_id,
        details=failure_details,
    )
    await db.commit()
    await ws_manager.broadcast({
        "type": WSEventType.SCAN_COMPLETED,
        "data": {
            "run_id": run_id,
            "status": "FAILED",
            "total": 0,
            "processed": 0,
            "skipped": 0,
            "vulnerable": 0,
            "errors": 1,
        }
    })
    return True


async def _worker_claim_is_current(
    db: AsyncSession,
    *,
    run_id: str,
    account_id: int,
    worker_id: str | None,
) -> bool:
    if not worker_id:
        return True
    result = await db.execute(
        select(TestRun.id).where(
            TestRun.id == run_id,
            TestRun.account_id == account_id,
            TestRun.worker_id == worker_id,
            TestRun.status.in_(["DISPATCHED", "RUNNING"]),
        )
    )
    return result.scalar_one_or_none() is not None


async def _rollback_if_worker_claim_lost(
    db: AsyncSession,
    *,
    run_id: str,
    account_id: int,
    worker_id: str | None,
) -> bool:
    if await _worker_claim_is_current(
        db,
        run_id=run_id,
        account_id=account_id,
        worker_id=worker_id,
    ):
        return False
    await db.rollback()
    return True


def _planned_test_count(template_ids: list[str], endpoint_ids: list[str]) -> int:
    return len(template_ids) * len(endpoint_ids)


def _validate_scan_budget(template_ids: list[str], endpoint_ids: list[str]) -> None:
    planned_count = _planned_test_count(template_ids, endpoint_ids)
    max_budget = max(1, int(settings.PENTEST_MAX_TESTS_PER_RUN))
    if planned_count > max_budget:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Scan plan has {planned_count} template/endpoint combinations; "
                f"maximum budget is {max_budget}. Narrow the selection or adjust PENTEST_MAX_TESTS_PER_RUN."
            ),
        )


def _templates_for_scan_plan(templates: list[dict], template_ids: list[str]) -> list[dict]:
    by_id = {str(template.get("id")): template for template in templates if isinstance(template, dict)}
    return [by_id.get(str(template_id)) or {"id": str(template_id), "info": {}} for template_id in template_ids]


def _scan_plan_generated_templates(scan_plan: dict | None) -> list[dict]:
    if not isinstance(scan_plan, dict):
        return []
    generated = scan_plan.get("generated_templates")
    if not isinstance(generated, list):
        return []
    return [template for template in generated if isinstance(template, dict) and template.get("id")]


def _runtime_templates_for_run(base_templates: list[dict], template_ids: list[str], scan_plan: dict | None) -> list[dict]:
    template_map = {
        str(template.get("id")): template
        for template in [*base_templates, *_scan_plan_generated_templates(scan_plan)]
        if isinstance(template, dict) and template.get("id")
    }
    return [template_map[str(template_id)] for template_id in template_ids if str(template_id) in template_map]


async def _expand_active_business_logic_templates(
    db: AsyncSession,
    *,
    account_id: int,
    template_ids: list[str],
    endpoints: list[APIEndpoint],
    base_templates: list[dict],
    test_intensity: str | None,
) -> tuple[list[str], list[dict], list[dict]]:
    if ACTIVE_BUSINESS_LOGIC_TEMPLATE_ID not in {str(template_id) for template_id in template_ids}:
        return template_ids, base_templates, []

    base_ids = [str(template_id) for template_id in template_ids if str(template_id) != ACTIVE_BUSINESS_LOGIC_TEMPLATE_ID]
    graph = await get_latest_graph(db, account_id)
    generated_templates = build_active_business_logic_templates(
        endpoints,
        graph=graph,
        test_intensity=test_intensity,
    )
    generated_ids = [str(template["id"]) for template in generated_templates]
    return [*base_ids, *generated_ids], [*base_templates, *generated_templates], generated_templates


def _endpoint_scan_plan_context(endpoint: APIEndpoint, *, account_id: int) -> dict:
    return {
        "id": endpoint.id,
        "method": endpoint.method,
        "url": f"{endpoint.protocol or 'http'}://{endpoint.host}{endpoint.path}",
        "path": endpoint.path,
        "host": endpoint.host or "",
        "protocol": endpoint.protocol or "http",
        "last_response_body": endpoint.last_response_body,
        "last_request_body": endpoint.last_request_body,
        "last_query_string": endpoint.last_query_string,
        "last_response_code": endpoint.last_response_code,
        "last_response_headers": endpoint.last_response_headers or {},
        "auth_types_found": endpoint.auth_types_found or [],
        "private_variable_count": endpoint.private_variable_count or 0,
        "account_id": account_id,
    }


def _scan_engine_runtime_availability() -> dict[str, bool]:
    return {
        "schemathesis": SchemathesisRunner.is_available(),
        "nuclei": NucleiRunner.is_available(),
        "zap": ZapRunner.is_available(),
    }


async def _account_has_openapi_spec(db: AsyncSession, *, account_id: int) -> bool:
    result = await db.execute(
        select(OpenAPISpec.id)
        .where(OpenAPISpec.account_id == account_id)
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


def _build_scan_plan_for_run(
    *,
    templates: list[dict],
    template_ids: list[str],
    endpoints: list[APIEndpoint],
    account_id: int,
    test_intensity: str | None,
    profile: object | None,
    roles_context: dict | None = None,
    auth_profile: object | None = None,
    has_openapi_spec: bool = False,
    engine_runtime_availability: dict[str, bool] | None = None,
    generated_templates: list[dict] | None = None,
    test_accounts_count: int = 0,
    external_engine_scope: dict | None = None,
) -> dict:
    scan_plan = build_readable_scan_plan(
        templates=_templates_for_scan_plan(templates, template_ids),
        endpoints=[
            _endpoint_scan_plan_context(endpoint, account_id=account_id)
            for endpoint in endpoints
        ],
        roles_context=roles_context,
        test_intensity=test_intensity,
        profile=profile,
    )
    runtime_availability = engine_runtime_availability or _scan_engine_runtime_availability()
    scan_plan["engine_plan"] = build_engine_plan(
        profile=profile,
        auth_profile=auth_profile,
        has_openapi_spec=has_openapi_spec,
        schemathesis_available=bool(runtime_availability.get("schemathesis")),
        nuclei_available=bool(runtime_availability.get("nuclei")),
        zap_available=bool(runtime_availability.get("zap")),
        require_authenticated_active_scan=active_scan_auth_required(),
        test_accounts_count=test_accounts_count,
    )
    authorization = scan_plan.get("coverage_targets", {}).get("authorization", {})
    authorization_readiness = authorization.get("readiness", {}) if isinstance(authorization, dict) else {}
    replay_ready = bool(
        test_accounts_count >= 2
        and (
            authorization_readiness.get("bola_replay_testable")
            or authorization_readiness.get("bfla_replay_testable")
        )
    )
    replay_endpoint_ids = [
        str(endpoint.id)
        for endpoint in endpoints
        if str(endpoint.id)
        and bool(endpoint.auth_types_found)
        and (
            int(endpoint.private_variable_count or 0) > 0
            or "{" in str(endpoint.path or "")
            or str(endpoint.method or "").upper() in {"POST", "PUT", "PATCH", "DELETE"}
        )
    ]
    for entry in scan_plan["engine_plan"]:
        if entry.get("engine") == "authorization_replay" and entry.get("status") == "ready":
            if not replay_ready or not replay_endpoint_ids:
                entry.update(status="blocked", reason="no_authorization_replay_targets")
    scan_plan["authorization_replay"] = {
        "endpoint_ids": replay_endpoint_ids,
        "selection_reason": "authenticated_private_identifier_or_state_change_surface",
        "ready": replay_ready and bool(replay_endpoint_ids),
    }
    if external_engine_scope:
        scan_plan["external_engine_scope"] = external_engine_scope
    else:
        for entry in scan_plan["engine_plan"]:
            if entry["engine"] in {"schemathesis", "nuclei", "zap"} and entry["status"] == "ready":
                entry.update(status="blocked", reason="external_engine_scope_required")
    if generated_templates:
        safe_generated = Redactor.redact_json(generated_templates)
        scan_plan["generated_templates"] = safe_generated if isinstance(safe_generated, list) else []
    return finalize_scan_plan_hash(scan_plan)


def _scan_plan_engine_audit_summary(scan_plan: dict) -> dict:
    raw_engine_plan = _scan_plan_engine_plan(scan_plan)
    if not raw_engine_plan:
        return {}

    engine_plan = Redactor.redact_json(raw_engine_plan)
    if not isinstance(engine_plan, list):
        return {}
    entries = {
        str(item.get("engine")): item
        for item in engine_plan
        if isinstance(item, dict) and str(item.get("engine")) in ENGINE_EXECUTION_ORDER
    }
    ready_active_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if engine != "passive" and entries.get(engine, {}).get("status") == "ready"
    ]
    blocked_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if entries.get(engine, {}).get("status") == "blocked"
    ]
    disabled_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if entries.get(engine, {}).get("status") == "disabled"
    ]
    continuous_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if entries.get(engine, {}).get("status") in {"available", "continuous"}
    ]
    required_artifacts = [
        {
            "engine": engine,
            "artifact_type": str(entries[engine].get("artifact_type")),
        }
        for engine in ready_active_engines
        if entries.get(engine, {}).get("artifact_type")
    ]
    return {
        "engine_status_counts": engine_status_counts(engine_plan),
        "ready_active_engines": ready_active_engines,
        "blocked_engines": blocked_engines,
        "disabled_engines": disabled_engines,
        "continuous_engines": continuous_engines,
        "required_artifacts": required_artifacts,
        "engine_outcomes": engine_outcome_summaries(engine_plan),
    }


def _scan_plan_engine_plan(scan_plan: dict | None) -> list[dict]:
    if not isinstance(scan_plan, dict):
        return []
    raw_engine_plan = scan_plan.get("engine_plan")
    if not isinstance(raw_engine_plan, list):
        return []
    return [
        dict(item)
        for item in raw_engine_plan
        if isinstance(item, dict) and str(item.get("engine")) in ENGINE_EXECUTION_ORDER
    ]


def _execution_artifact_engine_plan(scan_plan: dict | None) -> list[dict]:
    engine_plan = _scan_plan_engine_plan(scan_plan)
    if engine_plan:
        return engine_plan
    return [{"engine": "templates", "status": "ready", "reason": "template_execution_completed"}]


def _scan_plan_audit_summary(scan_plan: dict | None) -> dict:
    if not isinstance(scan_plan, dict):
        return {}
    selection = scan_plan.get("selection") if isinstance(scan_plan.get("selection"), dict) else {}
    context = scan_plan.get("context") if isinstance(scan_plan.get("context"), dict) else {}
    summary = {
        "schema_version": scan_plan.get("schema_version"),
        "hash_algorithm": scan_plan.get("hash_algorithm"),
        "scan_plan_hash": scan_plan.get("scan_plan_hash"),
        "test_intensity": scan_plan.get("test_intensity"),
        "selected_pair_count": selection.get("selected_pair_count", 0),
        "skipped_pair_count": selection.get("skipped_pair_count", 0),
        "requested_pair_count": selection.get("template_endpoint_pair_count", 0),
        "context_status": context.get("status"),
        "selection_starved": bool(selection.get("selection_starved")),
        "skip_reason_counts": selection.get("skip_reason_counts", {}),
    }
    coverage_targets = _scan_plan_coverage_targets_summary(scan_plan.get("coverage_targets"))
    if coverage_targets:
        summary["coverage_targets"] = coverage_targets
    summary.update(_scan_plan_engine_audit_summary(scan_plan))
    integrity = _scan_plan_integrity_summary(scan_plan)
    if integrity:
        summary["scan_plan_integrity"] = integrity
    return summary


def _scan_plan_integrity_summary(scan_plan: dict | None) -> dict | None:
    if not isinstance(scan_plan, dict):
        return None
    if not (scan_plan.get("scan_plan_hash") or scan_plan.get("hash_algorithm")):
        return None
    integrity = verify_scan_plan_integrity(scan_plan)
    return {
        "verified": bool(integrity.get("verified")),
        "status": str(integrity.get("status") or "MISMATCH"),
        "hash_algorithm": integrity.get("hash_algorithm"),
        "expected_hash": integrity.get("expected_hash"),
        "actual_hash": integrity.get("actual_hash"),
    }


def _scan_plan_integrity_failure(scan_plan: dict | None) -> dict | None:
    summary = _scan_plan_integrity_summary(scan_plan)
    if not summary or summary["verified"]:
        return None
    return summary


def _scan_plan_coverage_targets_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    summary: dict[str, object] = {}
    for target in _SCAN_PLAN_COVERAGE_TARGETS:
        raw_target = value.get(target)
        if not isinstance(raw_target, dict):
            continue
        status = str(raw_target.get("status") or "not_requested")
        if status not in _SCAN_PLAN_COVERAGE_STATUSES:
            status = "gap"
        signals = [
            signal
            for signal in sorted(str(item) for item in (raw_target.get("signals") or []))
            if signal in _SCAN_PLAN_COVERAGE_SIGNALS
        ]
        target_summary: dict[str, object] = {
            "template_requested": bool(raw_target.get("template_requested")),
            "template_covered": bool(raw_target.get("template_covered")),
            "endpoint_signal_count": _safe_nonnegative_int(raw_target.get("endpoint_signal_count")),
            "status": status,
            "signals": signals,
        }
        identity_context = _scan_plan_identity_context_summary(raw_target.get("identity_context"))
        if identity_context:
            target_summary["identity_context"] = identity_context
        readiness = _scan_plan_readiness_summary(raw_target.get("readiness"))
        if readiness:
            target_summary["readiness"] = readiness
        active_families = _scan_plan_active_test_families_summary(
            raw_target.get("active_test_families")
        )
        if active_families:
            target_summary["active_test_families"] = active_families
        summary[target] = target_summary
    return summary


def _scan_plan_active_test_families_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    summary: dict[str, object] = {}
    for family in _ACTIVE_TEST_FAMILIES:
        raw_family = value.get(family)
        if not isinstance(raw_family, dict):
            continue
        status = str(raw_family.get("status") or "")
        if status not in _ACTIVE_TEST_FAMILY_STATUSES:
            status = (
                "ready"
                if bool(raw_family.get("ready"))
                else "missing_template"
                if _safe_nonnegative_int(raw_family.get("template_count")) == 0
                else "missing_endpoint_context"
            )
        signals = [
            signal
            for signal in sorted(str(item) for item in (raw_family.get("signals") or []))
            if signal in _ACTIVE_TEST_FAMILY_SIGNALS
        ]
        summary[family] = {
            "template_count": _safe_nonnegative_int(raw_family.get("template_count")),
            "endpoint_signal_count": _safe_nonnegative_int(raw_family.get("endpoint_signal_count")),
            "ready": bool(raw_family.get("ready")),
            "status": status,
            "signals": signals,
        }
    return summary


def _scan_plan_identity_context_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {
        "role_count": _safe_nonnegative_int(value.get("role_count")),
        "multi_identity_ready": bool(value.get("multi_identity_ready")),
        "privileged_role_present": bool(value.get("privileged_role_present")),
        "low_privilege_role_present": bool(value.get("low_privilege_role_present")),
        "privilege_boundary_pair_count": _safe_nonnegative_int(value.get("privilege_boundary_pair_count")),
    }


def _scan_plan_readiness_summary(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    return {
        key: bool(value.get(key))
        for key in sorted(_SCAN_PLAN_COVERAGE_READINESS_KEYS)
        if key in value
    }


def _safe_nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _validate_scan_endpoint_targets(endpoints: list[APIEndpoint]) -> None:
    blocked = blocked_endpoint_targets(endpoints, guard=TargetGuard.from_settings())
    if blocked:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Pentest target guard blocked one or more selected endpoints",
                "blocked_endpoints": blocked,
            },
        )


def _validate_scan_auth_scope(endpoints: list[APIEndpoint], auth_profile: object | None) -> None:
    blocked = blocked_auth_profile_targets(auth_profile, endpoints)
    if blocked:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Auth profile scope blocked one or more selected endpoints",
                "reason": "auth_profile_scope_blocked",
                "blocked_endpoints": blocked,
            },
        )


def _scan_execution_mode() -> str:
    mode = (settings.PENTEST_SCAN_EXECUTION_MODE or "background").strip().lower()
    if mode not in {"background", "queued"}:
        raise HTTPException(
            status_code=500,
            detail="PENTEST_SCAN_EXECUTION_MODE must be one of: background, queued",
        )
    return mode


async def _load_scan_profile_for_execution(
    db: AsyncSession,
    *,
    account_id: int,
    pentest_profile_id: str | None = None,
):
    try:
        profile, auth_profile = await load_profile_and_auth_for_active_scan(
            db,
            account_id=account_id,
            pentest_profile_id=pentest_profile_id,
            profiles=_pentest_profiles,
        )
    except PentestProfileNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ActiveScanAuthError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc
    return profile, auth_profile


def _requires_confirmatory_retest(test_result: dict) -> bool:
    severity = (test_result.get("severity") or "").upper()
    return bool(test_result.get("is_vulnerable")) and severity in _CONFIRMATORY_RETEST_SEVERITIES


def _is_non_executed_skip(test_result: dict) -> bool:
    return str(test_result.get("skip_reason") or "") in _NON_EXECUTED_SKIP_REASONS


def _confirmation_payload(confirmation_result: dict, *, confirmed: bool) -> dict:
    return {
        "required": True,
        "confirmed": confirmed,
        "template_id": confirmation_result.get("template_id"),
        "severity": confirmation_result.get("severity"),
        "sent_request": confirmation_result.get("sent_request"),
        "received_response": confirmation_result.get("received_response"),
        "results": confirmation_result.get("results", []),
        "error": confirmation_result.get("error"),
    }


async def _confirm_test_result(
    *,
    engine: ExecutionEngine,
    endpoint: dict,
    template: dict,
    selection_context: dict,
) -> dict:
    try:
        confirmation = await engine.execute_test(
            endpoint,
            template,
            selection_context=selection_context,
        )
        return Redactor.redact_scan_result(confirmation)
    except Exception as exc:
        return {
            "template_id": template.get("id"),
            "severity": template.get("info", {}).get("severity"),
            "is_vulnerable": False,
            "results": [],
            "error": Redactor.redact_text(str(exc)),
        }


async def _run_agentic_scan_pass(
    *,
    engine: ExecutionEngine,
    endpoints: list,
    templates: list,
    account_id: int,
    pentest_profile,
    prior_findings: list | None = None,
    test_accounts: list | None = None,
) -> dict:
    """Run the agentic proposer-confirmer loop over the scanned endpoints.

    Thin adapter from ORM endpoints to the agentic ``run_agentic_scan_async``
    entry point, reusing the live engine + real safety guards. Gated upstream by
    AGENTIC_LLM_ENABLED; here we just translate inputs.
    """
    from server.modules.agentic.orchestration import run_agentic_scan_async

    endpoint_dicts = [
        {
            "id": str(ep.id),
            "method": ep.method,
            "path": ep.path,
            "host": ep.host or "",
            "protocol": ep.protocol or "http",
            "auth_types_found": ep.auth_types_found or [],
            "private_variable_count": ep.private_variable_count or 0,
            "account_id": account_id,
        }
        for ep in endpoints
    ]
    return await run_agentic_scan_async(
        engine=engine,
        endpoints=endpoint_dicts,
        templates=templates,
        prior_findings=prior_findings,
        test_accounts=test_accounts,
        allow_state_change=pentest_profile.allow_state_change,
        allow_destructive_methods=pentest_profile.allow_destructive_methods,
    )


async def _scan_cancel_requested(db: AsyncSession, run_id: str) -> bool:
    status = await db.scalar(select(TestRun.status).where(TestRun.id == run_id))
    return (status or "").upper() in _CANCEL_REQUESTED_STATUSES


async def _scan_should_stop(db: AsyncSession, run_id: str) -> tuple[bool, str | None]:
    if kill_switch_enabled():
        return True, KILL_SWITCH_REASON
    if await _scan_cancel_requested(db, run_id):
        return True, "cancel_requested"
    return False, None


def _serialize_run(run: TestRun) -> dict:
    return {
        "id": run.id,
        "status": run.status,
        "total_tests": run.total_tests,
        "vulnerable_count": run.vulnerable_count,
        "error_count": run.error_count,
        "pentest_profile_id": run.pentest_profile_id,
        "trigger_source": run.trigger_source,
        "source_vulnerability_id": run.source_vulnerability_id,
        "source_schedule_id": run.source_schedule_id,
        "test_intensity": getattr(run, "test_intensity", "standard"),
        "scan_plan": getattr(run, "scan_plan", None),
        "worker_id": run.worker_id,
        "dispatch_lease_expires_at": _serialize_datetime(run.dispatch_lease_expires_at),
        "worker_heartbeat_at": _serialize_datetime(run.worker_heartbeat_at),
        "claim_count": run.claim_count,
        "started_at": _serialize_datetime(run.started_at),
        "completed_at": _serialize_datetime(run.completed_at),
        "created_at": _serialize_datetime(run.created_at),
    }


def _serialize_datetime(value: datetime.datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=datetime.timezone.utc)
    else:
        value = value.astimezone(datetime.timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _safe_result_text(value: str | None) -> str | None:
    if value is None:
        return None
    return Redactor.redact_text(str(value))


def _serialize_result(result: TestResult) -> dict:
    return {
        "endpoint_id": result.endpoint_id,
        "template_id": result.template_id,
        "is_vulnerable": result.is_vulnerable,
        "severity": result.severity,
        "evidence": _safe_result_text(result.evidence),
        "error": _safe_result_text(result.error),
        "skip_reason": result.skip_reason,
    }


async def _load_scoped_run_results(db: AsyncSession, run: TestRun) -> list[TestResult]:
    stmt = select(TestResult).where(TestResult.run_id == run.id)
    endpoint_scope = [str(endpoint_id) for endpoint_id in (run.endpoint_ids or []) if endpoint_id]
    if endpoint_scope:
        stmt = stmt.where(TestResult.endpoint_id.in_(endpoint_scope))
    result = await db.execute(stmt)
    return result.scalars().all()


async def _run_security_tasks(
    run_id: str,
    template_ids: list[str],
    endpoint_ids: list[str],
    account_id: int,
    pentest_profile_id: str | None = None,
    db_bind=None,
    worker_id: str | None = None,
    worker_isolation: dict | None = None,
    worker_isolation_context: dict | None = None,
):
    """Background task: execute templates against endpoints, persist results."""
    worker_id = normalize_worker_id(worker_id)
    wm = WordlistManager.get_instance()
    total = 0
    processed_count = 0
    skipped_count = 0
    vuln_count = 0
    err_count = 0
    canceled = False
    cancel_reason = None
    # Confirmed deterministic findings, fed to the agentic pass as prior_findings
    # so its strategist can chain from real leaks (e.g. a leaked id -> BOLA).
    deterministic_findings: list[dict] = []

    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    async with session_factory() as db:
        aggregator = ResultAggregator(db=db)
        run_context = (
            await db.execute(select(TestRun).where(TestRun.id == run_id))
        ).scalar_one_or_none()
        run_audit_context = {
            "trigger_source": getattr(run_context, "trigger_source", None),
            "source_vulnerability_id": getattr(run_context, "source_vulnerability_id", None),
            "source_schedule_id": getattr(run_context, "source_schedule_id", None),
            "worker_id": worker_id or getattr(run_context, "worker_id", None),
        }
        if await _rollback_if_worker_claim_lost(
            db,
            run_id=run_id,
            account_id=account_id,
            worker_id=worker_id,
        ):
            return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
        should_stop, stop_reason = await _scan_should_stop(db, run_id)
        if should_stop:
            if await _rollback_if_worker_claim_lost(
                db,
                run_id=run_id,
                account_id=account_id,
                worker_id=worker_id,
            ):
                return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
            cancel_update_filters = [TestRun.id == run_id, TestRun.account_id == account_id]
            if worker_id:
                cancel_update_filters.extend(
                    [
                        TestRun.worker_id == worker_id,
                        TestRun.status.in_(["DISPATCHED", "RUNNING"]),
                    ]
                )
            cancel_update_result = await db.execute(
                update(TestRun).where(and_(*cancel_update_filters)).values(
                    status="CANCELED",
                    completed_at=datetime.datetime.now(datetime.timezone.utc),
                    dispatch_lease_expires_at=None,
                )
            )
            if cancel_update_result.rowcount != 1:
                await db.rollback()
                return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
            await _record_vulnerability_retest_outcome(
                db,
                run_id=run_id,
                account_id=account_id,
                status="CANCELED",
                outcome="CANCELED",
                details={
                    "reason": stop_reason or "cancel_requested_before_start",
                    "processed": 0,
                    "executed": 0,
                    "vulnerable": 0,
                    "errors": 0,
                    "skipped": 0,
                },
            )
            await _audit_scan_event(
                db,
                action="SCAN_RUN_CANCELED",
                account_id=account_id,
                run_id=run_id,
                details={
                    "reason": stop_reason or "cancel_requested_before_start",
                    "template_count": len(template_ids),
                    "endpoint_count": len(endpoint_ids),
                    "processed": 0,
                    "executed": 0,
                    "vulnerable": 0,
                    "errors": 0,
                    **run_audit_context,
                },
            )
            await db.commit()
            await ws_manager.broadcast({
                "type": WSEventType.SCAN_COMPLETED,
                "data": {
                    "run_id": run_id,
                    "status": "CANCELED",
                    "total": 0,
                    "processed": 0,
                    "skipped": 0,
                    "vulnerable": 0,
                    "errors": 0,
                }
            })
            return {"status": "canceled", "reason": stop_reason or "cancel_requested_before_start", "run_id": run_id}

        planned_count = _planned_test_count(template_ids, endpoint_ids)
        max_budget = max(1, int(settings.PENTEST_MAX_TESTS_PER_RUN))
        if planned_count > max_budget:
            if await _rollback_if_worker_claim_lost(
                db,
                run_id=run_id,
                account_id=account_id,
                worker_id=worker_id,
            ):
                return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
            failed = await _fail_scan_before_execution(
                db,
                run_id=run_id,
                account_id=account_id,
                reason="scan_budget_exceeded",
                template_ids=template_ids,
                endpoint_ids=endpoint_ids,
                worker_id=worker_id,
                details={
                    "planned_tests": planned_count,
                    "max_tests_per_run": max_budget,
                    **run_audit_context,
                },
            )
            return {"status": "failed" if failed else "aborted", "reason": "scan_budget_exceeded" if failed else "worker_claim_lost", "run_id": run_id}

        result = await db.execute(
            select(APIEndpoint).where(
                and_(APIEndpoint.id.in_(endpoint_ids), APIEndpoint.account_id == account_id)
            )
        )
        endpoints = result.scalars().all()

        requested_endpoint_ids = {str(endpoint_id) for endpoint_id in endpoint_ids}
        found_endpoint_ids = {str(endpoint.id) for endpoint in endpoints}
        unavailable_endpoint_ids = sorted(requested_endpoint_ids - found_endpoint_ids)
        if unavailable_endpoint_ids:
            if await _rollback_if_worker_claim_lost(
                db,
                run_id=run_id,
                account_id=account_id,
                worker_id=worker_id,
            ):
                return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
            failed = await _fail_scan_before_execution(
                db,
                run_id=run_id,
                account_id=account_id,
                reason="endpoint_scope_invalid",
                template_ids=template_ids,
                endpoint_ids=endpoint_ids,
                worker_id=worker_id,
                details={
                    "unavailable_endpoint_ids": unavailable_endpoint_ids[:25],
                    **run_audit_context,
                },
            )
            return {"status": "failed" if failed else "aborted", "reason": "endpoint_scope_invalid" if failed else "worker_claim_lost", "run_id": run_id}

        blocked_targets = blocked_endpoint_targets(endpoints, guard=TargetGuard.from_settings())
        if blocked_targets:
            if await _rollback_if_worker_claim_lost(
                db,
                run_id=run_id,
                account_id=account_id,
                worker_id=worker_id,
            ):
                return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
            failed = await _fail_scan_before_execution(
                db,
                run_id=run_id,
                account_id=account_id,
                reason="target_guard_blocked",
                template_ids=template_ids,
                endpoint_ids=endpoint_ids,
                worker_id=worker_id,
                details={
                    "blocked_endpoints": blocked_targets,
                    **run_audit_context,
                },
            )
            return {"status": "failed" if failed else "aborted", "reason": "target_guard_blocked" if failed else "worker_claim_lost", "run_id": run_id}

        try:
            preflight_profile, preflight_auth_profile = await load_profile_and_auth_for_active_scan(
                db,
                account_id=account_id,
                pentest_profile_id=pentest_profile_id,
                profiles=_pentest_profiles,
            )
        except (PentestProfileNotFound, ActiveScanAuthError) as exc:
            if await _rollback_if_worker_claim_lost(
                db,
                run_id=run_id,
                account_id=account_id,
                worker_id=worker_id,
            ):
                return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
            reason = getattr(exc, "reason", "pentest_profile_invalid")
            failed = await _fail_scan_before_execution(
                db,
                run_id=run_id,
                account_id=account_id,
                reason=reason,
                template_ids=template_ids,
                endpoint_ids=endpoint_ids,
                worker_id=worker_id,
                details={
                    "message": Redactor.redact_text(str(exc)),
                    **run_audit_context,
                },
            )
            return {"status": "failed" if failed else "aborted", "reason": reason if failed else "worker_claim_lost", "run_id": run_id}

        if preflight_profile is None:
            pentest_profile = await _pentest_profiles.load_profile(
                db,
                account_id=account_id,
                pentest_profile_id=pentest_profile_id,
            )
            auth_profile = await _pentest_profiles.load_auth_profile(
                db,
                account_id=account_id,
                auth_profile_id=pentest_profile.auth_profile_id,
            )
        else:
            pentest_profile = preflight_profile
            auth_profile = preflight_auth_profile

        blocked_auth_targets = blocked_auth_profile_targets(auth_profile, endpoints)
        if blocked_auth_targets:
            if await _rollback_if_worker_claim_lost(
                db,
                run_id=run_id,
                account_id=account_id,
                worker_id=worker_id,
            ):
                return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
            failed = await _fail_scan_before_execution(
                db,
                run_id=run_id,
                account_id=account_id,
                reason="auth_profile_scope_blocked",
                template_ids=template_ids,
                endpoint_ids=endpoint_ids,
                worker_id=worker_id,
                details={
                    "blocked_endpoints": blocked_auth_targets,
                    **run_audit_context,
                },
            )
            return {"status": "failed" if failed else "aborted", "reason": "auth_profile_scope_blocked" if failed else "worker_claim_lost", "run_id": run_id}

        test_accounts_result = await db.execute(
            select(TestAccount).where(TestAccount.account_id == account_id)
        )
        # Retain the identity list so the agentic pass can run authenticated
        # multi-identity BOLA/BFLA replay (needs >=2 identities), not just build
        # the roles_context summary.
        test_accounts = eligible_test_accounts(test_accounts_result.scalars().all())
        roles_context = RolesContextBuilder().build(test_accounts)
        try:
            effective_test_intensity = normalize_test_intensity(
                getattr(run_context, "test_intensity", None),
                profile=pentest_profile,
            )
        except ValueError as exc:
            if await _rollback_if_worker_claim_lost(
                db,
                run_id=run_id,
                account_id=account_id,
                worker_id=worker_id,
            ):
                return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
            failed = await _fail_scan_before_execution(
                db,
                run_id=run_id,
                account_id=account_id,
                reason="invalid_test_intensity",
                template_ids=template_ids,
                endpoint_ids=endpoint_ids,
                worker_id=worker_id,
                details={
                    "message": str(exc),
                    **run_audit_context,
                },
            )
            return {
                "status": "failed" if failed else "aborted",
                "reason": "invalid_test_intensity" if failed else "worker_claim_lost",
                "run_id": run_id,
            }
        scan_plan = getattr(run_context, "scan_plan", None)
        if not isinstance(scan_plan, dict):
            has_openapi_spec = await _account_has_openapi_spec(db, account_id=account_id)
            scan_plan = _build_scan_plan_for_run(
                templates=wm.templates,
                template_ids=template_ids,
                endpoints=endpoints,
                account_id=account_id,
                test_intensity=effective_test_intensity,
                profile=pentest_profile,
                roles_context=roles_context,
                auth_profile=auth_profile,
                has_openapi_spec=has_openapi_spec,
            )
        scan_plan_integrity_failure = _scan_plan_integrity_failure(scan_plan)
        if scan_plan_integrity_failure:
            if await _rollback_if_worker_claim_lost(
                db,
                run_id=run_id,
                account_id=account_id,
                worker_id=worker_id,
            ):
                return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
            failed = await _fail_scan_before_execution(
                db,
                run_id=run_id,
                account_id=account_id,
                reason="scan_plan_integrity_mismatch",
                template_ids=template_ids,
                endpoint_ids=endpoint_ids,
                worker_id=worker_id,
                details={
                    "scan_plan_integrity": scan_plan_integrity_failure,
                    "scan_plan": _scan_plan_audit_summary(scan_plan),
                    **run_audit_context,
                },
            )
            return {
                "status": "failed" if failed else "aborted",
                "reason": "scan_plan_integrity_mismatch" if failed else "worker_claim_lost",
                "run_id": run_id,
            }
        runtime_templates = _runtime_templates_for_run(wm.templates, template_ids, scan_plan)
        runtime_template_map = {
            str(template.get("id")): template
            for template in runtime_templates
            if isinstance(template, dict) and template.get("id")
        }

        # Mark run as RUNNING only after all pre-execution governance gates pass.
        run_started_at = datetime.datetime.now(datetime.timezone.utc)
        run_update = {
            "status": "RUNNING",
            "started_at": run_started_at,
            "test_intensity": effective_test_intensity,
            "scan_plan": scan_plan,
        }
        if worker_id:
            run_update.update(
                {
                    "worker_id": worker_id,
                    "worker_heartbeat_at": run_started_at,
                    "dispatch_lease_expires_at": run_started_at
                    + datetime.timedelta(seconds=max(1, int(settings.PENTEST_SCAN_DISPATCH_LEASE_SECONDS))),
                }
            )
        run_update_filters = [TestRun.id == run_id, TestRun.account_id == account_id]
        if worker_id:
            run_update_filters.extend(
                [
                    TestRun.worker_id == worker_id,
                    TestRun.status.in_(["DISPATCHED", "RUNNING"]),
                ]
            )
        run_update_result = await db.execute(
            update(TestRun).where(and_(*run_update_filters)).values(**run_update)
        )
        if run_update_result.rowcount != 1:
            await db.rollback()
            return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
        await _audit_scan_event(
            db,
            action="SCAN_RUN_STARTED",
            account_id=account_id,
            run_id=run_id,
            details={
                "template_count": len(template_ids),
                "endpoint_count": len(endpoint_ids),
                "planned_tests": _planned_test_count(template_ids, endpoint_ids),
                "pentest_profile_id": pentest_profile_id,
                "test_intensity": effective_test_intensity,
                "scan_plan": _scan_plan_audit_summary(scan_plan),
                **run_audit_context,
            },
        )
        await db.commit()

        await ws_manager.broadcast({
            "type": WSEventType.SCAN_STARTED,
            "data": {"run_id": run_id, "total": len(template_ids) * len(endpoint_ids)}
        })

        engine_kwargs = {
            "concurrency": pentest_profile.max_concurrency,
            "test_id": run_id,
            "timeout_seconds": pentest_profile.request_timeout_seconds,
            "db": db,
            "auth_profile": auth_profile,
            "follow_redirects": pentest_profile.follow_redirects,
            "allow_state_change": pentest_profile.allow_state_change,
            "allow_destructive_methods": pentest_profile.allow_destructive_methods,
            "attacker_role": pentest_profile.attacker_role,
        }
        if worker_isolation_context is not None:
            engine_kwargs["worker_isolation_context"] = worker_isolation_context
        engine = ExecutionEngine(**engine_kwargs)
        selector = SelectionFilterEngine()

        for t_id in template_ids:
            template = runtime_template_map.get(str(t_id))
            if not template:
                continue
            for ep in endpoints:
                should_stop, stop_reason = await _scan_should_stop(db, run_id)
                if should_stop:
                    canceled = True
                    cancel_reason = stop_reason
                    break

                if worker_id:
                    heartbeat_ok = await heartbeat_claimed_run(
                        run_id,
                        worker_id,
                        db_bind=db_bind,
                        account_id=account_id,
                    )
                    if not heartbeat_ok:
                        await db.rollback()
                        return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}

                processed_count += 1
                ep_dict = {
                    "id": ep.id,
                    "method": ep.method,
                    "url": f"{ep.protocol or 'http'}://{ep.host}{ep.path}",
                    "path": ep.path,
                    "host": ep.host or "",
                    "protocol": ep.protocol or "http",
                    "last_response_body": ep.last_response_body,
                    "last_request_body": ep.last_request_body,
                    "last_query_string": ep.last_query_string,
                    "last_response_code": ep.last_response_code,
                    "last_response_headers": ep.last_response_headers or {},
                    "auth_types_found": ep.auth_types_found or [],
                    "private_variable_count": ep.private_variable_count or 0,
                    "account_id": account_id,
                }
                selection_decision = selector.evaluate(
                    template,
                    ep_dict,
                    roles_context=roles_context,
                )
                selection_context = selection_decision.extracted
                if not selection_decision.should_run:
                    skipped_count += 1
                    db.add(
                        TestResult(
                            run_id=run_id,
                            endpoint_id=ep.id,
                            template_id=t_id,
                            is_vulnerable=False,
                            severity=template.get("info", {}).get("severity"),
                            evidence=json.dumps(
                                {
                                    "selection_filter": {
                                        "reason": selection_decision.reason or "selection_filter_mismatch",
                                    }
                                },
                                sort_keys=True,
                            ),
                            skip_reason="selection_filter",
                        )
                    )
                    await ws_manager.broadcast({
                        "type": WSEventType.SCAN_PROGRESS,
                        "data": {
                            "run_id": run_id,
                            "current": processed_count,
                            "executed": total,
                            "skipped": skipped_count,
                            "vulnerable": vuln_count,
                            "errors": err_count
                        }
                    })
                    continue

                try:
                    test_result = await engine.execute_test(
                        ep_dict,
                        template,
                        selection_context=selection_context,
                    )
                    test_result = Redactor.redact_scan_result(test_result)
                    if _requires_confirmatory_retest(test_result):
                        original_evidence = test_result.get("evidence")
                        confirmation = await _confirm_test_result(
                            engine=engine,
                            endpoint=ep_dict,
                            template=template,
                            selection_context=selection_context,
                        )
                        confirmed = bool(confirmation.get("is_vulnerable"))
                        if original_evidence not in (None, ""):
                            test_result["original_evidence"] = original_evidence
                        test_result["confirmation"] = _confirmation_payload(
                            confirmation,
                            confirmed=confirmed,
                        )
                        if confirmed:
                            test_result["evidence"] = "confirmatory_retest=passed"
                        else:
                            test_result["is_vulnerable"] = False
                            test_result["skip_reason"] = "confirmatory_retest_failed"
                            test_result["evidence"] = "confirmatory_retest=failed"

                    is_vuln = test_result.get("is_vulnerable", False)
                    non_executed_skip = _is_non_executed_skip(test_result)
                    if non_executed_skip:
                        skipped_count += 1
                    else:
                        total += 1
                    if is_vuln and not non_executed_skip:
                        vuln_count += 1
                        await aggregator.add_vulnerability(test_result, ep_dict)
                        deterministic_findings.append(
                            {
                                "type": test_result.get("type") or test_result.get("template_id"),
                                "endpoint_id": str(ep.id),
                                "severity": test_result.get("severity"),
                                "exposed_fields": test_result.get("exposed_fields") or [],
                            }
                        )

                    # Persist individual result
                    tr = TestResult(
                        run_id=run_id,
                        endpoint_id=ep.id,
                        template_id=t_id,
                        is_vulnerable=is_vuln,
                        severity=test_result.get("severity"),
                        sent_request=test_result.get("sent_request"),
                        received_response=test_result.get("received_response"),
                        evidence=_test_result_evidence_text(
                            test_result,
                            ep_dict,
                            is_vulnerable=is_vuln,
                            non_executed_skip=non_executed_skip,
                        ),
                        skip_reason=test_result.get("skip_reason"),
                    )
                    db.add(tr)
                except Exception as exc:
                    err_count += 1
                    tr = TestResult(
                        run_id=run_id, endpoint_id=ep.id, template_id=t_id,
                        is_vulnerable=False, error=Redactor.redact_text(str(exc))
                    )
                    db.add(tr)
 
                # Broadcast progress for each test combination
                await ws_manager.broadcast({
                    "type": WSEventType.SCAN_PROGRESS,
                    "data": {
                        "run_id": run_id,
                        "current": processed_count,
                        "executed": total,
                        "skipped": skipped_count,
                        "vulnerable": vuln_count,
                        "errors": err_count
                    }
                })
            if canceled:
                break

        # ── Agentic pass ─────────────────────────────────────────────────────
        # Runs AFTER the deterministic template scan, reusing the same engine,
        # endpoints, and safety guards. The deterministic sub-passes (multi-step
        # attack chains + targeted detectors: sensitive exposure, SQLi, mass
        # assignment, business abuse) run unconditionally — they need no LLM
        # and each is behind the same TargetGuard/StateChangeGuard as the rest
        # of the engine. The LLM proposer-confirmer loop runs only when
        # AGENTIC_LLM_ENABLED is true (handled inside run_agentic_scan_async).
        # All three finding categories (chain, detector, LLM-confirmed) are
        # promoted to persisted Vulnerability rows (not just a per-run
        # TestResult) so they reach the dashboard, compliance reports, and
        # every export the same way a template finding does. Fully wrapped so
        # it can never fail a scan.
        if not canceled:
            try:
                agentic_result = await _run_agentic_scan_pass(
                    engine=engine,
                    endpoints=endpoints,
                    templates=runtime_templates,
                    account_id=account_id,
                    pentest_profile=pentest_profile,
                    prior_findings=deterministic_findings,
                    test_accounts=test_accounts,
                )
                endpoint_by_id = {str(ep.id): ep for ep in endpoints}

                async def _persist_agentic_finding(finding: dict, *, source: str) -> None:
                    nonlocal total, vuln_count
                    ep = endpoint_by_id.get(str(finding.get("endpoint_id")))
                    if ep is None:
                        return
                    ep_dict = {
                        "id": ep.id,
                        "method": ep.method,
                        "url": f"{ep.protocol or 'http'}://{ep.host}{ep.path}",
                        "path": ep.path,
                    }
                    vulnerability_data = build_agentic_vulnerability_data(
                        finding=finding,
                        endpoint=ep_dict,
                        account_id=account_id,
                        source=source,
                    )
                    vuln, created, fingerprint = await create_or_merge_vulnerability(db, vulnerability_data)
                    if created:
                        await ws_manager.broadcast({
                            "type": WSEventType.VULNERABILITY_FOUND,
                            "data": {
                                "id": vuln.id,
                                "template_id": vuln.template_id,
                                "severity": vuln.severity,
                                "url": vuln.url,
                                "method": vuln.method,
                                "fingerprint": fingerprint,
                                "timestamp": vuln.created_at.isoformat() if vuln.created_at else None,
                            },
                        })
                    total += 1
                    vuln_count += 1
                    db.add(
                        TestResult(
                            run_id=run_id,
                            endpoint_id=ep.id,
                            template_id=vulnerability_data["template_id"],
                            is_vulnerable=True,
                            severity=finding.get("severity"),
                            evidence=json.dumps(
                                {
                                    "engine": f"agentic_{source}",
                                    "type": finding.get("type"),
                                    "confidence": finding.get("confidence"),
                                    "rationale": finding.get("rationale"),
                                },
                                sort_keys=True,
                            ),
                            skip_reason=None,
                        )
                    )

                for finding in agentic_result.get("chain_findings", []) or []:
                    await _persist_agentic_finding(finding, source="chain")
                for finding in agentic_result.get("detector_findings", []) or []:
                    await _persist_agentic_finding(finding, source="detector")
                agentic_findings = agentic_result.get("outcome", {}).get("confirmed_findings", [])
                for finding in agentic_findings:
                    await _persist_agentic_finding(finding, source="agentic")
            except Exception as exc:  # never let the agentic pass break a scan
                logger.warning("agentic_pass_failed run_id=%s error=%s", run_id, str(exc))

        # Stamp last_tested on the scanned endpoints so continuous-discovery does
        # not re-queue them, and so the inventory reflects test coverage. Only on
        # a completed (non-canceled) run.
        if not canceled and endpoints:
            scanned_endpoint_ids = [ep.id for ep in endpoints]
            await db.execute(
                update(APIEndpoint)
                .where(
                    APIEndpoint.account_id == account_id,
                    APIEndpoint.id.in_(scanned_endpoint_ids),
                )
                .values(last_tested=datetime.datetime.now(datetime.timezone.utc))
            )

        final_update_filters = [TestRun.id == run_id, TestRun.account_id == account_id]
        if worker_id:
            final_update_filters.extend(
                [
                    TestRun.worker_id == worker_id,
                    TestRun.status == "RUNNING",
                ]
            )
        final_update_result = await db.execute(
            update(TestRun).where(and_(*final_update_filters)).values(
                status="CANCELED" if canceled else "COMPLETED",
                completed_at=datetime.datetime.now(datetime.timezone.utc),
                total_tests=total,
                vulnerable_count=vuln_count,
                error_count=err_count,
                dispatch_lease_expires_at=None,
            )
        )
        if final_update_result.rowcount != 1:
            await db.rollback()
            return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
        final_status = "CANCELED" if canceled else "COMPLETED"
        if canceled:
            retest_outcome = "CANCELED"
        elif err_count > 0:
            retest_outcome = "FAILED"
        elif total == 0:
            retest_outcome = "NO_EXECUTION"
        elif vuln_count > 0:
            retest_outcome = "STILL_VULNERABLE"
        else:
            retest_outcome = "CLEAN"
        await _record_vulnerability_retest_outcome(
            db,
            run_id=run_id,
            account_id=account_id,
            status=final_status,
            outcome=retest_outcome,
            details={
                "processed": processed_count,
                "executed": total,
                "skipped": skipped_count,
                "vulnerable": vuln_count,
                "errors": err_count,
                "reason": cancel_reason,
            },
        )
        await persist_execution_artifact(
            db,
            account_id=account_id,
            engine="templates",
            target_url=endpoint_target_url(endpoints[0]),
            profile_id=pentest_profile_id,
            execution={
                "status": final_status,
                "processed": processed_count,
                "executed": total,
                "skipped": skipped_count,
                "vulnerable": vuln_count,
                "errors": err_count,
                "reason": cancel_reason,
                "trigger_source": getattr(run_context, "trigger_source", None),
                "source_vulnerability_id": getattr(run_context, "source_vulnerability_id", None),
                "source_schedule_id": getattr(run_context, "source_schedule_id", None),
                "worker_id": worker_id,
                "claim_count": getattr(run_context, "claim_count", None),
                "test_intensity": effective_test_intensity,
                "scan_plan": _scan_plan_audit_summary(scan_plan),
                "worker_isolation_enforcement": getattr(
                    engine,
                    "worker_isolation_enforcement",
                    {"present": False, "engine": "templates"},
                ),
            },
            engine_plan=_execution_artifact_engine_plan(scan_plan),
            findings={
                "created_count": vuln_count,
                "vulnerable_count": vuln_count,
                "template_count": len(template_ids),
                "endpoint_count": len(endpoint_ids),
            },
            auth_context=run_audit_context,
            run_id=run_id,
            worker_isolation=worker_isolation,
        )
        await _audit_scan_event(
            db,
            action="SCAN_RUN_CANCELED" if canceled else "SCAN_RUN_COMPLETED",
            account_id=account_id,
            run_id=run_id,
            details={
                "processed": processed_count,
                "executed": total,
                "skipped": skipped_count,
                "vulnerable": vuln_count,
                "errors": err_count,
                "reason": cancel_reason,
                "test_intensity": effective_test_intensity,
                "scan_plan": _scan_plan_audit_summary(scan_plan),
                **run_audit_context,
            },
        )
        await db.commit()

        await ws_manager.broadcast({
            "type": WSEventType.SCAN_COMPLETED,
            "data": {
                "run_id": run_id,
                "status": "CANCELED" if canceled else "COMPLETED",
                "total": total,
                "processed": processed_count,
                "skipped": skipped_count,
                "vulnerable": vuln_count,
                "errors": err_count
            }
        })
        return {
            "status": final_status.lower(),
            "reason": cancel_reason,
            "run_id": run_id,
            "processed": processed_count,
            "executed": total,
            "skipped": skipped_count,
            "vulnerable": vuln_count,
            "errors": err_count,
            "test_intensity": effective_test_intensity,
            "scan_plan": _scan_plan_audit_summary(scan_plan),
        }


@router.get("/templates")
@limiter.limit("30/minute")
async def list_templates(
    request: Request,
    category: str = Query(None),
    severity: str = Query(None),
    search: str = Query(None),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ))
):
    try:
        # Validate string parameters
        validated_category = None
        if category:
            validated_category = InputValidator.validate_string(
                category, "category", max_length=100, allow_empty=False
            ).upper()

        validated_severity = None
        if severity:
            validated_severity = InputValidator.validate_string(
                severity, "severity", max_length=20, allow_empty=False
            ).upper()

        validated_search = None
        if search:
            validated_search = InputValidator.validate_string(
                search, "search", max_length=256, allow_empty=False
            )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    wm = WordlistManager.get_instance()
    templates = wm.templates

    if validated_category:
        templates = [t for t in templates if t.get("info", {}).get("category", {}).get("name", "").upper() == validated_category]
    if validated_severity:
        templates = [t for t in templates if t.get("info", {}).get("severity", "").upper() == validated_severity]
    if validated_search:
        term = validated_search.lower()
        templates = [t for t in templates if term in (t.get("info", {}).get("name") or "").lower()]

    return {
        "count": len(templates),
        "templates": [
            {
                "id": t["id"],
                "name": t.get("info", {}).get("name"),
                "severity": t.get("info", {}).get("severity"),
                "category": t.get("info", {}).get("category", {}).get("name"),
                "description": t.get("info", {}).get("description"),
            }
            for t in templates
        ],
    }


@router.get("/templates/{template_id}")
async def get_template(
    template_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
):
    try:
        # Validate template_id (alphanumeric with hyphens and underscores)
        validated_template_id = InputValidator.validate_string(
            template_id, "template_id", max_length=256, allow_empty=False
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    wm = WordlistManager.get_instance()
    template = next((t for t in wm.templates if t["id"] == validated_template_id), None)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template


@router.post("/run")
@limiter.limit("10/minute")
async def run_scan(
    request: Request,
    template_ids: list[str],
    endpoint_ids: list[str],
    background_tasks: BackgroundTasks,
    pentest_profile_id: str | None = Body(default=None),
    test_intensity: str | None = Body(default=None),
    external_engine_scope: dict | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(can_run_tests),
):
    try:
        # Validate lists are not empty and within size limits
        InputValidator.validate_collection_size(template_ids, "template_ids", max_size=1000)
        InputValidator.validate_collection_size(endpoint_ids, "endpoint_ids", max_size=1000)
        # Validate each template_id is a valid string
        for t_id in template_ids:
            InputValidator.validate_string(t_id, "template_id", max_length=256, allow_empty=False)
        # Validate each endpoint_id is a valid UUID
        for e_id in endpoint_ids:
            InputValidator.validate_uuid(e_id, "endpoint_id")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload["account_id"]
    if kill_switch_enabled():
        raise HTTPException(status_code=503, detail=KILL_SWITCH_REASON)
    _validate_scan_budget(template_ids, endpoint_ids)

    # Verify all endpoint_ids belong to this account
    result = await db.execute(
        select(APIEndpoint).where(
            and_(APIEndpoint.id.in_(endpoint_ids), APIEndpoint.account_id == account_id)
        )
    )
    endpoints = result.scalars().all()
    valid_ids = [str(endpoint.id) for endpoint in endpoints]
    if len(valid_ids) < len(endpoint_ids):
        raise HTTPException(status_code=403, detail="Some endpoints do not belong to your account")
    _validate_scan_endpoint_targets(endpoints)

    pentest_profile, auth_profile = await _load_scan_profile_for_execution(
        db,
        account_id=account_id,
        pentest_profile_id=pentest_profile_id,
    )
    _validate_scan_auth_scope(endpoints, auth_profile)
    effective_pentest_profile_id = pentest_profile.id if pentest_profile is not None else pentest_profile_id
    try:
        effective_test_intensity = normalize_test_intensity(test_intensity, profile=pentest_profile)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    wm = WordlistManager.get_instance()
    effective_template_ids, scan_templates, generated_templates = await _expand_active_business_logic_templates(
        db,
        account_id=account_id,
        template_ids=template_ids,
        endpoints=endpoints,
        base_templates=wm.templates,
        test_intensity=effective_test_intensity,
    )
    _validate_scan_budget(effective_template_ids, endpoint_ids)
    test_accounts_result = await db.execute(
        select(TestAccount).where(TestAccount.account_id == account_id)
    )
    test_accounts_list = eligible_test_accounts(test_accounts_result.scalars().all())
    roles_context = RolesContextBuilder().build(test_accounts_list)
    has_openapi_spec = await _account_has_openapi_spec(db, account_id=account_id)
    engine_runtime_availability = _scan_engine_runtime_availability()
    if external_engine_scope is not None and not isinstance(external_engine_scope, dict):
        external_engine_scope = None
    if external_engine_scope:
        from server.modules.test_executor.scan_worker import _scoped_worker_spec, worker_spec_digest
        from server.modules.pentest.target_policy import validate_pentest_target
        from server.modules.pentest.auth_scope import validate_auth_profile_scope
        target_url = external_engine_scope.get("target_url")
        spec_id = external_engine_scope.get("openapi_spec_id")
        if not isinstance(target_url, str) or not isinstance(spec_id, str):
            raise HTTPException(status_code=400, detail="External engines require target_url and openapi_spec_id")
        spec = (await db.execute(select(OpenAPISpec).where(
            OpenAPISpec.id == spec_id, OpenAPISpec.account_id == account_id,
        ))).scalar_one_or_none()
        if spec is None:
            raise HTTPException(status_code=404, detail="OpenAPI spec not found")
        try:
            validate_pentest_target(target_url)
            validate_auth_profile_scope(auth_profile, target_url)
            _scoped_worker_spec(spec.spec_json, endpoints, target_url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=Redactor.redact_text(str(exc))) from exc
        if _scan_execution_mode() != "queued":
            raise HTTPException(status_code=400, detail="External engine plans require queued execution")
        external_engine_scope = {"target_url": target_url, "openapi_spec_id": spec_id, "openapi_spec_sha256": worker_spec_digest(spec.spec_json)}
    scan_plan = _build_scan_plan_for_run(
        templates=scan_templates,
        template_ids=effective_template_ids,
        endpoints=endpoints,
        account_id=account_id,
        test_intensity=effective_test_intensity,
        profile=pentest_profile,
        roles_context=roles_context,
        auth_profile=auth_profile,
        has_openapi_spec=has_openapi_spec,
        engine_runtime_availability=engine_runtime_availability,
        generated_templates=generated_templates,
        test_accounts_count=len(test_accounts_list),
        external_engine_scope=external_engine_scope,
    )

    run_id = str(uuid.uuid4())
    run = TestRun(
        id=run_id,
        account_id=account_id,
        status="PENDING",
        template_ids=effective_template_ids,
        endpoint_ids=endpoint_ids,
        pentest_profile_id=effective_pentest_profile_id,
        trigger_source="manual",
        test_intensity=effective_test_intensity,
        scan_plan=scan_plan,
    )
    execution_mode = _scan_execution_mode()
    db.add(run)
    await _audit_scan_event(
        db,
        action="SCAN_RUN_QUEUED",
        account_id=account_id,
        run_id=run_id,
        user_id=payload.get("user_id"),
        details={
            "template_count": len(effective_template_ids),
            "generated_business_logic_template_count": len(generated_templates),
            "endpoint_count": len(endpoint_ids),
            "planned_tests": _planned_test_count(effective_template_ids, endpoint_ids),
            "pentest_profile_id": effective_pentest_profile_id,
            **active_scan_auth_audit_context(pentest_profile, auth_profile),
            "execution_mode": execution_mode,
            "trigger_source": run.trigger_source,
            "test_intensity": effective_test_intensity,
            "scan_plan": _scan_plan_audit_summary(scan_plan),
        },
        ip_address=_request_ip(request),
    )
    await db.commit()
    if execution_mode == "background":
        background_tasks.add_task(
            _run_security_tasks,
            run_id,
            effective_template_ids,
            endpoint_ids,
            account_id,
            effective_pentest_profile_id,
            db.bind,
        )
    return {
        "status": "scan_started" if execution_mode == "background" else "scan_queued",
        "run_id": run_id,
        "templates": len(effective_template_ids),
        "endpoints": len(endpoint_ids),
        "pentest_profile_id": effective_pentest_profile_id,
        "execution_mode": execution_mode,
        "trigger_source": run.trigger_source,
        "test_intensity": effective_test_intensity,
        "scan_plan": scan_plan,
    }


@router.get("/runs")
async def list_runs(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ))
):
    try:
        # Validate limit parameter
        validated_limit = InputValidator.validate_integer(limit, "limit", min_value=1, max_value=1000)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload["account_id"]
    result = await db.execute(
        select(TestRun).where(TestRun.account_id == account_id)
        .order_by(TestRun.created_at.desc()).limit(validated_limit)
    )
    runs = result.scalars().all()
    return {
        "total": len(runs),
        "runs": [
            _serialize_run(r)
            for r in runs
        ],
    }


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ))
):
    try:
        # Validate run_id UUID format
        validated_run_id = InputValidator.validate_uuid(run_id, "run_id")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload["account_id"]
    result = await db.execute(
        select(TestRun).where(and_(TestRun.id == validated_run_id, TestRun.account_id == account_id))
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    results = await _load_scoped_run_results(db, run)

    return {
        **_serialize_run(run),
        "results": [_serialize_result(r) for r in results],
    }


@router.post("/runs/{run_id}/cancel")
async def cancel_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(can_run_tests),
):
    try:
        validated_run_id = InputValidator.validate_uuid(run_id, "run_id")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload["account_id"]
    result = await db.execute(
        select(TestRun).where(and_(TestRun.id == validated_run_id, TestRun.account_id == account_id))
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    current_status = (run.status or "").upper()
    if current_status in _TERMINAL_RUN_STATUSES:
        return {
            "status": "not_cancelled",
            "run_id": run.id,
            "run_status": run.status,
        }

    previous_status = current_status
    run.status = "CANCEL_REQUESTED"
    await _audit_scan_event(
        db,
        action="SCAN_CANCEL_REQUESTED",
        account_id=account_id,
        run_id=run.id,
        user_id=payload.get("user_id"),
        details={"previous_status": previous_status},
    )
    await db.commit()
    return {
        "status": "cancel_requested",
        "run_id": run.id,
        "run_status": "CANCEL_REQUESTED",
    }


@router.get("/runs/{run_id}/findings")
@limiter.limit("30/minute")
async def get_run_findings(
    request: Request,
    run_id: str,
    format: str = Query("sarif"),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
):
    try:
        # Validate run_id UUID format
        validated_run_id = InputValidator.validate_uuid(run_id, "run_id")
        # Validate format parameter
        validated_format = InputValidator.validate_string(format, "format", max_length=20, allow_empty=False)
        if validated_format.lower() not in ("sarif", "junit"):
            raise ValidationError("format: Must be one of sarif, junit")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload["account_id"]
    result = await db.execute(
        select(TestRun).where(and_(TestRun.id == validated_run_id, TestRun.account_id == account_id))
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    results = await _load_scoped_run_results(db, run)

    fmt = validated_format.lower()
    if fmt == "sarif":
        sarif = build_sarif(run, results)
        return JSONResponse(content=sarif, media_type="application/sarif+json")
    if fmt == "junit":
        xml = build_junit(run, results)
        return PlainTextResponse(content=xml, media_type="application/xml")
    return {"error": "unsupported format", "supported": ["sarif", "junit"]}
