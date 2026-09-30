"""Scan run execution: runs planned templates against endpoints and persists results.

Owned by api-sentinel-scan-worker. ``run_security_tasks`` is invoked for a run the
worker has claimed from the queue; nothing outside the worker sends scan traffic.
"""
from __future__ import annotations

import datetime
import json
import logging

from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.config import settings
from sentinel_core.models.core import APIEndpoint, TestAccount, TestResult, TestRun, Vulnerability
from sentinel_worker.modules.agentic.finding_persistence import build_agentic_vulnerability_data
from sentinel_core.modules.auth.audit import log_action
from sentinel_core.modules.events import EventType, publish_dashboard_event
from sentinel_core.modules.identity.eligibility import eligible_test_accounts
from sentinel_core.modules.identity.roles_context import RolesContextBuilder
from sentinel_core.modules.pentest.auth_preflight import (
    ActiveScanAuthError,
    PentestProfileNotFound,
    load_profile_and_auth_for_active_scan,
)
from sentinel_core.modules.pentest.auth_scope import blocked_auth_profile_targets
from sentinel_core.modules.pentest.execution_artifacts import persist_execution_artifact
from sentinel_core.modules.pentest.profiles import PentestProfileService
from sentinel_core.modules.persistence.database import AsyncSessionLocal
from sentinel_core.modules.test_executor.evidence import build_active_scan_evidence
from sentinel_worker.modules.test_executor.execution_engine import ExecutionEngine
from sentinel_core.modules.test_executor.kill_switch import KILL_SWITCH_REASON, kill_switch_enabled
from sentinel_worker.modules.test_executor.result_aggregator import ResultAggregator
from sentinel_core.modules.test_executor.scan_plan import normalize_test_intensity
from sentinel_core.modules.test_executor.scan_planning import (
    account_has_openapi_spec,
    audit_scan_event,
    build_scan_plan_for_run,
    execution_artifact_engine_plan,
    planned_test_count,
    runtime_templates_for_run,
    scan_plan_audit_summary,
    scan_plan_integrity_failure,
)
from sentinel_worker.modules.test_executor.scan_worker import (
    WORKER_HELD_STATUSES,
    heartbeat_claimed_run,
    normalize_worker_id,
)
from sentinel_core.modules.test_executor.selection_filter import SelectionFilterEngine
from sentinel_core.modules.test_executor.target_guard import TargetGuard, blocked_endpoint_targets, endpoint_target_url
from sentinel_core.modules.test_executor.wordlist_manager import WordlistManager
from sentinel_core.modules.utils.redactor import Redactor
from sentinel_core.modules.vulnerability_detector.lifecycle import (
    is_vulnerability_retest_trigger_source,
    isoformat,
    latest_remediation_retest_integrity,
    retest_outcome_digest,
    utc_now,
)
from sentinel_core.modules.vulnerability_detector.store import create_or_merge_vulnerability

logger = logging.getLogger(__name__)

_pentest_profiles = PentestProfileService()


_CONFIRMATORY_RETEST_SEVERITIES = {"HIGH", "CRITICAL"}


_CANCEL_REQUESTED_STATUSES = {"CANCEL_REQUESTED", "CANCELED"}


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
                TestRun.status.in_(WORKER_HELD_STATUSES),
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
    await audit_scan_event(
        db,
        action="SCAN_RUN_FAILED",
        account_id=account_id,
        run_id=run_id,
        details=failure_details,
    )
    await db.commit()
    await publish_dashboard_event({
        "type": EventType.SCAN_COMPLETED,
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
            TestRun.status.in_(WORKER_HELD_STATUSES),
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
    from sentinel_worker.modules.agentic.orchestration import run_agentic_scan_async

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


async def run_security_tasks(
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
                        TestRun.status.in_(WORKER_HELD_STATUSES),
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
            await audit_scan_event(
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
            await publish_dashboard_event({
                "type": EventType.SCAN_COMPLETED,
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

        planned_count = planned_test_count(template_ids, endpoint_ids)
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
            has_openapi_spec = await account_has_openapi_spec(db, account_id=account_id)
            scan_plan = build_scan_plan_for_run(
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
        integrity_failure = scan_plan_integrity_failure(scan_plan)
        if integrity_failure:
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
                    "scan_plan_integrity": integrity_failure,
                    "scan_plan": scan_plan_audit_summary(scan_plan),
                    **run_audit_context,
                },
            )
            return {
                "status": "failed" if failed else "aborted",
                "reason": "scan_plan_integrity_mismatch" if failed else "worker_claim_lost",
                "run_id": run_id,
            }
        runtime_templates = runtime_templates_for_run(wm.templates, template_ids, scan_plan)
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
                    TestRun.status.in_(WORKER_HELD_STATUSES),
                ]
            )
        run_update_result = await db.execute(
            update(TestRun).where(and_(*run_update_filters)).values(**run_update)
        )
        if run_update_result.rowcount != 1:
            await db.rollback()
            return {"status": "aborted", "reason": "worker_claim_lost", "run_id": run_id}
        await audit_scan_event(
            db,
            action="SCAN_RUN_STARTED",
            account_id=account_id,
            run_id=run_id,
            details={
                "template_count": len(template_ids),
                "endpoint_count": len(endpoint_ids),
                "planned_tests": planned_test_count(template_ids, endpoint_ids),
                "pentest_profile_id": pentest_profile_id,
                "test_intensity": effective_test_intensity,
                "scan_plan": scan_plan_audit_summary(scan_plan),
                **run_audit_context,
            },
        )
        await db.commit()

        await publish_dashboard_event({
            "type": EventType.SCAN_STARTED,
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
                    await publish_dashboard_event({
                        "type": EventType.SCAN_PROGRESS,
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
                await publish_dashboard_event({
                    "type": EventType.SCAN_PROGRESS,
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
                        await publish_dashboard_event({
                            "type": EventType.VULNERABILITY_FOUND,
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
                    TestRun.status.in_(WORKER_HELD_STATUSES),
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
                "scan_plan": scan_plan_audit_summary(scan_plan),
                "worker_isolation_enforcement": getattr(
                    engine,
                    "worker_isolation_enforcement",
                    {"present": False, "engine": "templates"},
                ),
            },
            engine_plan=execution_artifact_engine_plan(scan_plan),
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
        await audit_scan_event(
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
                "scan_plan": scan_plan_audit_summary(scan_plan),
                **run_audit_context,
            },
        )
        await db.commit()

        await publish_dashboard_event({
            "type": EventType.SCAN_COMPLETED,
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
            "scan_plan": scan_plan_audit_summary(scan_plan),
        }
