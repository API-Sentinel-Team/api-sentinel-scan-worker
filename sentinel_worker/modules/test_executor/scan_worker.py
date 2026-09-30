from __future__ import annotations

import argparse
import asyncio
import copy
import contextlib
import datetime
import json
import os
import socket
import uuid
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlunparse, urlsplit

import httpx
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.config import settings
from sentinel_core.models.core import (
    APIEndpoint,
    AuditLog,
    OpenAPISpec,
    PentestArtifact,
    SampleData,
    TestAccount,
    TestResult,
    TestRun,
    Vulnerability,
)
from sentinel_worker.modules.identity.authorization_replay import (
    auth_headers_for_account,
    authorization_identity_label,
    authorization_identity_summary,
    build_authorization_replay_evidence,
    build_replay_request,
    classify_authorization_issue,
    evaluate_authorization_replay,
    infer_victim_account,
)
from sentinel_core.modules.identity.eligibility import eligible_test_accounts
from sentinel_core.modules.identity.role_keys import authorization_role_key
from sentinel_core.modules.persistence.database import AsyncSessionLocal
from sentinel_core.modules.pentest.auth_preflight import (
    ActiveScanAuthError,
    PentestProfileNotFound,
    active_scan_auth_audit_context,
    load_profile_and_auth_for_active_scan,
)
from sentinel_core.modules.pentest.engine_plan import (
    ENGINE_EXECUTION_ORDER,
    SUCCESSFUL_ENGINE_EXECUTION_STATUSES,
    build_auth_readiness,
    engine_execution_succeeded,
    engine_outcome_summaries,
)
from sentinel_core.modules.pentest.execution_artifacts import (
    persist_execution_artifact,
    verify_execution_artifact_payload,
)
from sentinel_core.modules.pentest.nuclei_secret_file import NucleiSecretFileBuilder
from sentinel_core.modules.pentest.profiles import PentestProfileService
from sentinel_worker.modules.pentest.schemathesis_runner import SchemathesisRunner
from sentinel_worker.modules.nuclei.runner import NucleiRunner
from sentinel_core.modules.nuclei.findings import persist_nuclei_findings
from sentinel_core.modules.schemathesis.findings import persist_schemathesis_junit
from sentinel_core.modules.zap.findings import persist_zap_report
from sentinel_worker.modules.zap.runner import ZapRunner
from sentinel_core.modules.pentest.target_policy import target_guard_policy_for_error, validate_pentest_target
from sentinel_core.modules.pentest.worker_isolation import (
    cleanup_worker_isolation_session,
    create_worker_isolation_session,
    worker_isolation_enforcement_metadata,
)
from sentinel_core.modules.test_executor.kill_switch import (
    KILL_SWITCH_REASON,
    PentestKillSwitchError,
    ensure_pentest_not_killed,
    kill_switch_enabled,
)
from sentinel_core.modules.test_executor.scan_plan import verify_scan_plan_integrity
from sentinel_core.modules.test_executor.scan_queue import (
    _ENGINE_EXECUTION_ARTIFACT_TYPES,
    _EXTERNAL_ENGINE_ARTIFACT_TYPES,
    _engine_accountability_policy,
    _lease_seconds,
    _max_claims,
    scoped_worker_spec,
    _utc_now,
    _worker_governance_policy,
    normalize_worker_id,
    worker_spec_digest,
)
from sentinel_core.modules.test_executor.state_change_guard import (
    StateChangeBlocked,
    StateChangeGuard,
    state_change_policy_for_request,
)
from sentinel_core.modules.test_executor.target_guard import TargetGuard, TargetGuardError, endpoint_target_url
from sentinel_core.modules.test_executor.worker_validation import validate_worker_staging_scan_acceptance
from sentinel_core.modules.utils.redactor import Redactor
from sentinel_core.modules.vulnerability_detector.lifecycle import (
    is_vulnerability_retest_trigger_source,
    isoformat,
    latest_remediation_retest_integrity,
    retest_outcome_digest,
)
from sentinel_core.modules.vulnerability_detector.store import create_or_merge_vulnerability

_EXTERNAL_ENGINE_ARTIFACT_TYPES_BY_ENGINE = {"schemathesis", "nuclei", "zap"}
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
_BUSINESS_ABUSE_FAMILIES = ("coupon_abuse", "otp_spam", "workflow_bypass", "resource_exhaustion")
_LLM_ACTIVE_FAMILIES = (
    "prompt_injection",
    "rag_exfiltration",
    "indirect_prompt_injection",
    "dangerous_tool_invocation",
    "privilege_escalating_tool_invocation",
    "tool_chain_injection",
)
_ACTIVE_TEST_FAMILIES = _BUSINESS_ABUSE_FAMILIES + _LLM_ACTIVE_FAMILIES
_BUSINESS_ABUSE_FAMILY_STATUSES = {"ready", "missing_template", "missing_endpoint_context"}
_ACTIVE_TEST_FAMILY_SIGNALS = {
    "bulk",
    "body_key",
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
    "upload",
    "untrusted_context",
    "verification",
}
_AUTHORIZATION_REPLAY_ENGINE = "authorization_replay"
# LIFE-1: retests of external-engine findings are queued with this sentinel template id
# and an engine-only scan plan. The worker routes them to the dedicated executor below;
# the templates phase is skipped and no template lookup ever happens.
_EXTERNAL_ENGINE_RETEST_TEMPLATE_ID = "EXTERNAL_ENGINE_RETEST"
_AUTHORIZATION_REPLAY_TEMPLATE_ID = "AUTHORIZATION_REPLAY_MATRIX"


# A run stays this worker's while it is dispatched, running, or has a cancel the worker has not yet
# acknowledged. Treating CANCEL_REQUESTED as "lost" made a user cancel look like a lost claim: the worker
# stopped, rolled back, and left the run in CANCEL_REQUESTED forever.
WORKER_HELD_STATUSES = ("DISPATCHED", "RUNNING", "CANCEL_REQUESTED")
_TERMINAL_RUN_STATUSES = {"COMPLETED", "FAILED", "CANCELED"}


class ScanCancelRequestedError(RuntimeError):
    """Raised when an operator cancel is observed during queued external execution.

    Distinct from claim loss: a cancel is an intentional terminal transition, so the
    worker finalizes the run as CANCELED rather than aborting without a terminal write.
    """


def _worker_engine_capabilities() -> dict[str, object]:
    """Probe the executing worker's real engine binaries (ISO-1 advertisement).

    The API host's ``runtime_available`` in the engine plan is evaluated where the
    plan was built, not where engines execute; this probe is the authoritative
    per-run record of what this worker could actually run.
    """
    advertised_at = isoformat(_utc_now())
    engines = {
        "schemathesis": {"available": SchemathesisRunner.is_available()},
        "nuclei": {"available": NucleiRunner.is_available()},
        "zap": {"available": ZapRunner.is_available()},
    }
    advertised_at = isoformat(_utc_now())
    digest = sha256(
        json.dumps(
            {"advertised_at": advertised_at, "engines": engines},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "advertised_at": advertised_at,
        "probed_at": advertised_at,
        "engines": engines,
        "digest": digest,
    }


@dataclass(frozen=True)
class ClaimedScanRun:
    run_id: str
    template_ids: list[str]
    endpoint_ids: list[str]
    account_id: int
    test_intensity: str | None = None
    scan_plan: dict[str, object] | None = None
    pentest_profile_id: str | None = None
    trigger_source: str | None = None
    source_vulnerability_id: str | None = None
    source_schedule_id: str | None = None
    auth_context: dict[str, object] | None = None
    engine_accountability: dict[str, object] | None = None
    worker_id: str | None = None
    lease_expires_at: datetime.datetime | None = None
    claim_count: int = 0


def _scan_plan_claim_summary(scan_plan: dict | None) -> dict[str, object]:
    if not isinstance(scan_plan, dict):
        return {}
    selection = scan_plan.get("selection") if isinstance(scan_plan.get("selection"), dict) else {}
    context = scan_plan.get("context") if isinstance(scan_plan.get("context"), dict) else {}
    summary = {
        "schema_version": scan_plan.get("schema_version"),
        "hash_algorithm": scan_plan.get("hash_algorithm"),
        "scan_plan_hash": scan_plan.get("scan_plan_hash"),
        "scan_plan_integrity": _scan_plan_integrity_summary(scan_plan),
        "test_intensity": scan_plan.get("test_intensity"),
        "selected_pair_count": int(selection.get("selected_pair_count") or 0),
        "skipped_pair_count": int(selection.get("skipped_pair_count") or 0),
        "requested_pair_count": int(selection.get("template_endpoint_pair_count") or 0),
        "context_status": context.get("status"),
        "selection_starved": bool(selection.get("selection_starved")),
    }
    coverage_targets = _scan_plan_coverage_targets_summary(scan_plan.get("coverage_targets"))
    if coverage_targets:
        summary["coverage_targets"] = coverage_targets
    return summary


def _claimed_scan_plan_handoff(scan_plan: dict | None) -> dict[str, object] | None:
    if not isinstance(scan_plan, dict):
        return None
    safe_plan = dict(scan_plan)
    safe_plan["scan_plan_integrity"] = _scan_plan_integrity_summary(scan_plan)
    return safe_plan


def _scan_plan_integrity_summary(scan_plan: dict[str, object]) -> dict[str, object]:
    integrity = verify_scan_plan_integrity(scan_plan)
    return {
        "verified": bool(integrity.get("verified")),
        "status": str(integrity.get("status") or "MISMATCH"),
        "hash_algorithm": integrity.get("hash_algorithm"),
        "expected_hash": integrity.get("expected_hash"),
        "actual_hash": integrity.get("actual_hash"),
    }


def _claim_scan_plan_with_integrity(scan_plan: dict | None) -> dict[str, object] | None:
    if not isinstance(scan_plan, dict):
        return scan_plan
    claimed_scan_plan = copy.deepcopy(scan_plan)
    claimed_scan_plan["scan_plan_integrity"] = _scan_plan_integrity_summary(claimed_scan_plan)
    return claimed_scan_plan


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
        if status not in _BUSINESS_ABUSE_FAMILY_STATUSES:
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


def _scan_plan_readiness_summary(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    return {
        key: bool(value.get(key))
        for key in sorted(_SCAN_PLAN_COVERAGE_READINESS_KEYS)
        if key in value
    }


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


def _safe_nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _scan_plan_engine_plan(scan_plan: dict | None) -> list[dict[str, object]]:
    if not isinstance(scan_plan, dict):
        return []
    engine_plan = scan_plan.get("engine_plan")
    if not isinstance(engine_plan, list):
        return []
    return [item for item in engine_plan if isinstance(item, dict)]


def _default_worker_engine_plan(
    *,
    template_ids: list[str] | None,
    endpoint_ids: list[str] | None,
) -> list[dict[str, object]]:
    if template_ids and endpoint_ids:
        return [
            {
                "engine": "templates",
                "status": "ready",
                "reason": "template_run_claimed",
            }
        ]
    return []


def _worker_engine_accountability(
    *,
    scan_plan: dict | None,
    template_ids: list[str] | None,
    endpoint_ids: list[str] | None,
) -> dict[str, object]:
    raw_engine_plan = _scan_plan_engine_plan(scan_plan)
    engine_plan_present = bool(raw_engine_plan)
    if not raw_engine_plan:
        raw_engine_plan = _default_worker_engine_plan(
            template_ids=template_ids,
            endpoint_ids=endpoint_ids,
        )

    safe_engine_plan = Redactor.redact_json(raw_engine_plan)
    if not isinstance(safe_engine_plan, list):
        safe_engine_plan = []
    entries = {
        str(item.get("engine")): item
        for item in safe_engine_plan
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
    claim_execution_engines = list(ready_active_engines)
    required_artifacts = [
        {
            "engine": engine,
            "artifact_type": _ENGINE_EXECUTION_ARTIFACT_TYPES[engine],
            "hash_required": True,
            "verification_required": True,
        }
        for engine in claim_execution_engines
        if engine in _ENGINE_EXECUTION_ARTIFACT_TYPES
    ]
    planned_external_artifacts = [
        {
            "engine": engine,
            "artifact_type": _ENGINE_EXECUTION_ARTIFACT_TYPES[engine],
            "hash_required": True,
            "verification_required": True,
            "produced_by_this_worker": False,
        }
        for engine in ready_active_engines
        if engine not in claim_execution_engines and engine in _EXTERNAL_ENGINE_ARTIFACT_TYPES_BY_ENGINE
    ]

    return {
        **_engine_accountability_policy(),
        "scan_plan_engine_plan_present": engine_plan_present,
        "template_count": len(template_ids or []),
        "endpoint_count": len(endpoint_ids or []),
        "execution_order": list(ENGINE_EXECUTION_ORDER),
        "claim_execution_engines": claim_execution_engines,
        "required_artifacts": required_artifacts,
        "planned_external_artifacts": planned_external_artifacts,
        "ready_active_engines": ready_active_engines,
        "continuous_engines": continuous_engines,
        "blocked_engines": blocked_engines,
        "disabled_engines": disabled_engines,
        "ready_engine_count": len(ready_active_engines),
        "blocked_engine_count": len(blocked_engines),
        "disabled_engine_count": len(disabled_engines),
        "engine_outcomes": engine_outcome_summaries(safe_engine_plan),
    }


def _lease_expires_at(now: datetime.datetime) -> datetime.datetime:
    return now + datetime.timedelta(seconds=_lease_seconds())


def _worker_identity(worker_id: str | None = None) -> str:
    normalized = normalize_worker_id(worker_id)
    if normalized:
        return normalized
    generated = f"{socket.gethostname()}-{uuid.uuid4()}"
    return normalize_worker_id(generated) or str(uuid.uuid4())


async def _claimed_run_auth_context(db, run: TestRun) -> dict[str, object]:
    base: dict[str, object] = {
        "pentest_profile_id": run.pentest_profile_id,
    }
    if not run.pentest_profile_id:
        return {
            **base,
            "auth_resolution_status": "not_bound",
            **active_scan_auth_audit_context(None, None),
        }
    try:
        profile, auth_profile = await load_profile_and_auth_for_active_scan(
            db,
            account_id=int(run.account_id),
            pentest_profile_id=run.pentest_profile_id,
        )
    except (PentestProfileNotFound, ActiveScanAuthError) as exc:
        return {
            **base,
            "auth_resolution_status": "failed",
            "auth_resolution_reason": getattr(exc, "reason", "pentest_profile_not_found"),
            **active_scan_auth_audit_context(None, None),
        }
    return {
        **base,
        "auth_resolution_status": "resolved",
        **active_scan_auth_audit_context(profile, auth_profile),
    }


def _claimable_filter(now: datetime.datetime, account_id: int | None = None):
    stale_before = now - datetime.timedelta(seconds=_lease_seconds())
    claimable_status = or_(
        TestRun.status == "PENDING",
        and_(
            TestRun.status == "DISPATCHED",
            or_(
                TestRun.dispatch_lease_expires_at < now,
                and_(
                    TestRun.dispatch_lease_expires_at.is_(None),
                    or_(TestRun.started_at.is_(None), TestRun.started_at < stale_before),
                ),
            ),
        ),
        and_(
            TestRun.status == "RUNNING",
            TestRun.worker_id.is_not(None),
            TestRun.dispatch_lease_expires_at < now,
        ),
    )
    if account_id is None:
        return claimable_status
    return and_(claimable_status, TestRun.account_id == account_id)


async def _record_terminal_retest_outcome(
    db,
    *,
    run: TestRun,
    now: datetime.datetime,
    reason: str,
    status: str = "FAILED",
    outcome: str = "FAILED",
    errors: int = 1,
) -> None:
    if not is_vulnerability_retest_trigger_source(run.trigger_source) or not run.source_vulnerability_id:
        return

    vulnerability = (
        await db.execute(
            select(Vulnerability).where(
                and_(
                    Vulnerability.id == run.source_vulnerability_id,
                    Vulnerability.account_id == run.account_id,
                )
            )
        )
    ).scalar_one_or_none()
    if vulnerability is None:
        return

    retest = {
        "run_id": run.id,
        "status": status,
        "outcome": outcome,
        "completed_at": isoformat(now),
        "executed": 0,
        "vulnerable": 0,
        "errors": errors,
        "skipped": 0,
        "reason": reason,
    }
    retest["hash_algorithm"] = "sha256"
    retest["retest_hash"] = retest_outcome_digest(retest)

    evidence = dict(vulnerability.evidence or {})
    previous_retests = evidence.get("remediation_retests")
    if not isinstance(previous_retests, list):
        previous_retests = []
    evidence["remediation_retests"] = (previous_retests + [retest])[-10:]
    evidence["latest_remediation_retest"] = retest
    vulnerability.evidence = evidence

    db.add(
        AuditLog(
            account_id=int(run.account_id),
            action="VULNERABILITY_RETEST_COMPLETED",
            resource_type="vulnerability",
            resource_id=vulnerability.id,
            details={
                "run_id": run.id,
                "status": status,
                "outcome": outcome,
                "previous_status": vulnerability.status,
                "new_status": vulnerability.status,
                "executed": 0,
                "vulnerable": 0,
                "errors": errors,
                "skipped": 0,
                "reason": reason,
                "hash_algorithm": retest["hash_algorithm"],
                "retest_hash": retest["retest_hash"],
                "retest_integrity": latest_remediation_retest_integrity(evidence),
            },
        )
    )


def _worker_run_timeout_seconds(isolation_session_timeout: int | None = None) -> int:
    """Scan-run wall clock budget; lease seconds is the authoritative upper bound."""
    lease_budget = _lease_seconds()
    configured = int(getattr(settings, "PENTEST_SCAN_WORKER_TIMEOUT_SECONDS", 0) or 0)
    if configured > 0:
        return max(1, min(configured, lease_budget))
    isolation_budget = int(isolation_session_timeout or 0)
    if isolation_budget > 15:
        return max(1, min(isolation_budget, lease_budget))
    return lease_budget


def _redacted_worker_failure_context(
    *,
    run_id: str,
    worker_id: str | None,
    reason: str,
    previous_status: str | None = None,
    worker_isolation: dict[str, object] | None = None,
    engine: str | None = None,
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    details: dict[str, object] = {
        "run_id": Redactor.redact_text(run_id),
        "worker_id": normalize_worker_id(worker_id),
        "reason": Redactor.redact_text(reason),
    }
    if previous_status:
        details["previous_status"] = previous_status
    if engine:
        details["engine"] = Redactor.redact_text(engine)
    if worker_isolation:
        details["worker_isolation"] = Redactor.redact_json(worker_isolation)
    if extra:
        details.update(Redactor.redact_json(extra) if isinstance(extra, dict) else {"extra": str(extra)})
    return details


async def _mark_claimed_run_failed(
    *,
    db_bind: AsyncEngine | None,
    run_id: str,
    account_id: int,
    worker_id: str | None,
    reason: str,
    action: str = "SCAN_RUN_FAILED",
    worker_isolation: dict[str, object] | None = None,
    engine: str | None = None,
) -> None:
    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    async with session_factory() as db:
        run = (
            await db.execute(
                select(TestRun).where(
                    TestRun.id == run_id,
                    TestRun.account_id == account_id,
                )
            )
        ).scalar_one_or_none()
        if run is None:
            return
        if worker_id and run.worker_id != worker_id:
            return
        if run.status in _TERMINAL_RUN_STATUSES:
            return
        previous_status = run.status
        now = _utc_now()
        run.status = "FAILED"
        run.completed_at = now
        run.error_count = max(1, int(run.error_count or 0))
        run.dispatch_lease_expires_at = None
        db.add(
            AuditLog(
                account_id=int(run.account_id),
                action=action,
                resource_type="test_run",
                resource_id=run.id,
                details=_redacted_worker_failure_context(
                    run_id=run.id,
                    worker_id=worker_id or run.worker_id,
                    reason=reason,
                    previous_status=previous_status,
                    worker_isolation=worker_isolation,
                    engine=engine,
                ),
            )
        )
        await db.commit()


async def _mark_claimed_run_canceled(
    *,
    db_bind: AsyncEngine | None,
    run_id: str,
    account_id: int,
    worker_id: str | None,
    reason: str,
    worker_isolation: dict[str, object] | None = None,
    engine: str | None = None,
) -> None:
    """Finalize an operator-canceled claimed run without deleting evidence or findings."""
    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    async with session_factory() as db:
        run = (
            await db.execute(
                select(TestRun).where(
                    TestRun.id == run_id,
                    TestRun.account_id == account_id,
                )
            )
        ).scalar_one_or_none()
        if run is None:
            return
        if worker_id and run.worker_id != worker_id:
            return
        if run.status in _TERMINAL_RUN_STATUSES:
            return
        previous_status = run.status
        now = _utc_now()
        run.status = "CANCELED"
        run.completed_at = now
        run.dispatch_lease_expires_at = None
        await _record_terminal_retest_outcome(
            db,
            run=run,
            now=now,
            reason=reason,
            status="CANCELED",
            outcome="CANCELED",
            errors=0,
        )
        db.add(
            AuditLog(
                account_id=int(run.account_id),
                action="SCAN_RUN_CANCELED",
                resource_type="test_run",
                resource_id=run.id,
                details=_redacted_worker_failure_context(
                    run_id=run.id,
                    worker_id=worker_id or run.worker_id,
                    reason=reason,
                    previous_status=previous_status,
                    worker_isolation=worker_isolation,
                    engine=engine,
                ),
            )
        )
        await db.commit()


async def _dead_letter_exhausted_claims(db, *, now: datetime.datetime, account_id: int | None) -> int:
    """Fail claimable runs that have exceeded the worker retry budget."""
    max_claims = _max_claims()
    exhausted_filter = and_(
        _claimable_filter(now, account_id),
        func.coalesce(TestRun.claim_count, 0) >= max_claims,
    )
    result = await db.execute(
        select(TestRun)
        .where(exhausted_filter)
        .order_by(TestRun.created_at.asc())
        .limit(50)
    )
    exhausted_runs = result.scalars().all()
    if not exhausted_runs:
        return 0

    for run in exhausted_runs:
        previous_status = run.status
        reason = "worker_claim_limit_exceeded"
        run.worker_id = normalize_worker_id(run.worker_id)
        run.status = "FAILED"
        run.completed_at = now
        run.error_count = max(1, int(run.error_count or 0))
        run.dispatch_lease_expires_at = None
        await _record_terminal_retest_outcome(db, run=run, now=now, reason=reason)
        db.add(
            AuditLog(
                account_id=int(run.account_id),
                action="SCAN_RUN_DEAD_LETTERED",
                resource_type="test_run",
                resource_id=run.id,
                details=_redacted_worker_failure_context(
                    run_id=run.id,
                    worker_id=run.worker_id,
                    reason=reason,
                    previous_status=previous_status,
                    extra={
                        "claim_count": int(run.claim_count or 0),
                        "max_claims": max_claims,
                        "trigger_source": run.trigger_source,
                        "source_vulnerability_id": run.source_vulnerability_id,
                        "source_schedule_id": run.source_schedule_id,
                    },
                ),
            )
        )
    await db.flush()
    return len(exhausted_runs)


async def claim_next_pending_run(
    *,
    db_bind: AsyncEngine | None = None,
    account_id: int | None = None,
    worker_id: str | None = None,
) -> ClaimedScanRun | None:
    """Atomically claim one queued scan run for external worker execution."""
    if kill_switch_enabled():
        return None

    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    async with session_factory() as db:
        now = _utc_now()
        lease_expires = _lease_expires_at(now)
        worker_identity = _worker_identity(worker_id)
        dead_lettered = await _dead_letter_exhausted_claims(db, now=now, account_id=account_id)
        if dead_lettered:
            await db.commit()
        claimable = and_(
            _claimable_filter(now, account_id),
            func.coalesce(TestRun.claim_count, 0) < _max_claims(),
        )
        result = await db.execute(
            select(TestRun)
            .where(claimable)
            .order_by(TestRun.created_at.asc())
            .limit(1)
        )
        run = result.scalar_one_or_none()
        if run is None:
            return None

        update_result = await db.execute(
            update(TestRun)
            .where(and_(TestRun.id == run.id, claimable))
            .values(
                status="DISPATCHED",
                started_at=now,
                worker_id=worker_identity,
                dispatch_lease_expires_at=lease_expires,
                worker_heartbeat_at=now,
                claim_count=func.coalesce(TestRun.claim_count, 0) + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if update_result.rowcount != 1:
            await db.rollback()
            return None

        next_claim_count = int(run.claim_count or 0) + 1
        auth_context = await _claimed_run_auth_context(db, run)
        template_ids = list(run.template_ids or [])
        endpoint_ids = list(run.endpoint_ids or [])
        scan_plan = _claim_scan_plan_with_integrity(getattr(run, "scan_plan", None))
        engine_accountability = _worker_engine_accountability(
            scan_plan=scan_plan,
            template_ids=template_ids,
            endpoint_ids=endpoint_ids,
        )
        previous_status = run.status
        reclaim = previous_status in {"DISPATCHED", "RUNNING"}
        claim_details = {
            "run_id": run.id,
            "worker_id": worker_identity,
            "lease_expires_at": isoformat(lease_expires),
            "claim_count": next_claim_count,
            "previous_status": previous_status,
            "previous_worker_id": normalize_worker_id(run.worker_id) if reclaim else None,
            "reclaimed": reclaim,
            "trigger_source": run.trigger_source,
            "source_vulnerability_id": run.source_vulnerability_id,
            "source_schedule_id": run.source_schedule_id,
            **auth_context,
            "template_count": len(template_ids),
            "endpoint_count": len(endpoint_ids),
            "test_intensity": getattr(run, "test_intensity", None),
            "scan_plan": _scan_plan_claim_summary(scan_plan),
            "worker_governance": _worker_governance_policy(account_id),
            # Advertise the executing worker's actual engine capabilities at claim time;
            # the later execution artifact repeats this evidence for artifact consumers.
            "worker_capabilities": (worker_capabilities := _worker_engine_capabilities()),
            "worker_capability_digest": worker_capabilities["digest"],
            "engine_accountability": engine_accountability,
        }
        db.add(
            AuditLog(
                account_id=int(run.account_id),
                action="SCAN_RUN_CLAIMED",
                resource_type="test_run",
                resource_id=run.id,
                details=claim_details,
            )
        )
        if reclaim:
            db.add(
                AuditLog(
                    account_id=int(run.account_id),
                    action="SCAN_RUN_WORKER_LOST",
                    resource_type="test_run",
                    resource_id=run.id,
                    details={
                        "run_id": run.id,
                        "previous_status": previous_status,
                        "previous_worker_id": normalize_worker_id(run.worker_id),
                        "new_worker_id": worker_identity,
                        "claim_count": next_claim_count,
                        "reason": "lease_expired_or_stale_worker",
                    },
                )
            )
        await db.commit()
        return ClaimedScanRun(
            run_id=run.id,
            template_ids=template_ids,
            endpoint_ids=endpoint_ids,
            account_id=int(run.account_id),
            test_intensity=getattr(run, "test_intensity", None),
            scan_plan=_claimed_scan_plan_handoff(scan_plan),
            pentest_profile_id=run.pentest_profile_id,
            trigger_source=run.trigger_source,
            source_vulnerability_id=run.source_vulnerability_id,
            source_schedule_id=run.source_schedule_id,
            auth_context=auth_context,
            engine_accountability=engine_accountability,
            worker_id=worker_identity,
            lease_expires_at=lease_expires,
            claim_count=next_claim_count,
        )


async def heartbeat_claimed_run(
    run_id: str,
    worker_id: str,
    *,
    db_bind: AsyncEngine | None = None,
    account_id: int | None = None,
) -> bool:
    """Refresh the lease for a run still owned by the same worker."""
    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    async with session_factory() as db:
        now = _utc_now()
        normalized_worker_id = _worker_identity(worker_id)
        filters = [
            TestRun.id == run_id,
            TestRun.worker_id == normalized_worker_id,
            TestRun.status.in_(WORKER_HELD_STATUSES),
            TestRun.dispatch_lease_expires_at >= now,
        ]
        if account_id is not None:
            filters.append(TestRun.account_id == account_id)
        run = (
            await db.execute(
                select(TestRun)
                .where(and_(*filters))
                .limit(1)
            )
        ).scalar_one_or_none()
        if run is None:
            return False
        previous_lease_expires_at = run.dispatch_lease_expires_at
        previous_heartbeat_at = run.worker_heartbeat_at
        lease_expires_at = _lease_expires_at(now)
        result = await db.execute(
            update(TestRun)
            .where(and_(*filters))
            .values(
                worker_heartbeat_at=now,
                dispatch_lease_expires_at=lease_expires_at,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            db.add(
                AuditLog(
                    account_id=int(run.account_id),
                    action="SCAN_RUN_HEARTBEAT",
                    resource_type="test_run",
                    resource_id=run.id,
                    details={
                        "worker_id": normalized_worker_id,
                        "status": run.status,
                        "claim_count": int(run.claim_count or 0),
                        "heartbeat_at": isoformat(now),
                        "previous_heartbeat_at": isoformat(previous_heartbeat_at),
                        "lease_expires_at": isoformat(lease_expires_at),
                        "previous_lease_expires_at": isoformat(previous_lease_expires_at),
                        "lease_seconds": _lease_seconds(),
                    },
                )
            )
        await db.commit()
        return result.rowcount == 1


def _claimed_run_requests_external_engine_retest(claimed: ClaimedScanRun) -> bool:
    """True when the claimed run is a queued retest of an external-engine finding."""
    if any(
        str(template_id) == _EXTERNAL_ENGINE_RETEST_TEMPLATE_ID
        for template_id in claimed.template_ids
    ):
        return True
    return any(
        str(item.get("engine")) in _EXTERNAL_ENGINE_ARTIFACT_TYPES_BY_ENGINE
        and str(item.get("status") or "").lower() == "ready"
        and str(item.get("reason") or "") == "retest_external_engine"
        for item in _scan_plan_engine_plan(claimed.scan_plan)
    )


def _external_engine_retest_engine(claimed: ClaimedScanRun) -> str:
    """Return the retest engine; falls back to the first ready external engine."""
    for item in _scan_plan_engine_plan(claimed.scan_plan):
        if (
            str(item.get("status") or "").lower() == "ready"
            and str(item.get("reason") or "") == "retest_external_engine"
            and str(item.get("engine")) in _EXTERNAL_ENGINE_ARTIFACT_TYPES_BY_ENGINE
        ):
            return str(item.get("engine"))
    return "schemathesis"


def _claimed_run_requests_authorization_replay(claimed: ClaimedScanRun) -> bool:
    engine_plan = _scan_plan_engine_plan(claimed.scan_plan)
    if any(
        str(item.get("engine")) == _AUTHORIZATION_REPLAY_ENGINE
        and str(item.get("status") or "").lower() == "ready"
        for item in engine_plan
    ):
        return True
    return any(str(template_id) == _AUTHORIZATION_REPLAY_TEMPLATE_ID for template_id in claimed.template_ids)


def _claimed_run_is_authorization_replay_only(claimed: ClaimedScanRun) -> bool:
    """Return whether this claim is an explicit replay retest, not a normal scan.

    Normal scans may include the replay engine as an additional authorization phase.
    Only the dedicated replay template/trigger is replay-only and may finalize the run
    inside the replay executor.
    """
    return (
        any(str(template_id) == _AUTHORIZATION_REPLAY_TEMPLATE_ID for template_id in claimed.template_ids)
        or str(claimed.trigger_source or "").lower() == "authorization_replay_matrix"
    )


async def _execute_external_engine_retest_claimed_run(
    claimed: ClaimedScanRun,
    *,
    db_bind: AsyncEngine | None,
    worker_isolation: dict[str, object] | None = None,
    worker_isolation_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Finalize a queued retest of an external-engine finding (LIFE-1).

    The producing engine has already run in the external phase
    (_execute_planned_external_engines), which persisted the hash-verified artifact and
    promoted findings into Vulnerability. This executor turns that evidence into the
    retest lifecycle: verified engine artifacts count as executed checks, promoted
    findings count as still-vulnerable observations, and the hashed remediation-retest
    outcome recorded here is what the closure gate (decision D) consumes.

    Failure, timeout, and cancel paths never reach this executor: the external phase's
    failure propagates to run_pending_scan_once, whose terminal handlers already record
    the FAILED/TIMEOUT/CANCELED retest outcome generically.
    """
    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    async with session_factory() as db:
        run = (
            await db.execute(
                select(TestRun).where(
                    TestRun.id == claimed.run_id,
                    TestRun.account_id == claimed.account_id,
                    TestRun.worker_id == claimed.worker_id,
                    TestRun.status.in_(WORKER_HELD_STATUSES),
                )
            )
        ).scalar_one_or_none()
        if run is None:
            return {"status": "aborted", "reason": "worker_claim_lost", "run_id": claimed.run_id}

        now = _utc_now()
        run.status = "RUNNING"
        run.worker_heartbeat_at = now

        artifacts = (
            await db.execute(
                select(PentestArtifact).where(
                    PentestArtifact.account_id == claimed.account_id,
                    PentestArtifact.run_id == claimed.run_id,
                    PentestArtifact.artifact_type.in_(list(_EXTERNAL_ENGINE_ARTIFACT_TYPES)),
                )
            )
        ).scalars().all()

        engine_name = _external_engine_retest_engine(claimed)
        executed = 0
        vulnerable = 0
        errors = 0
        retest_vulnerability_ids: list[str] = []
        for artifact in artifacts:
            payload = artifact.content_json if isinstance(artifact.content_json, dict) else {}
            verification = verify_execution_artifact_payload(payload) if payload else {"verified": False}
            if not verification.get("verified"):
                errors += 1
                continue
            executed += 1
            summary = _external_finding_summary(payload.get("findings") if isinstance(payload.get("findings"), dict) else {})
            vulnerable += _safe_nonnegative_int(summary.get("normalized_finding_count"))
            for vulnerability_id in summary.get("vulnerability_ids") or []:
                if vulnerability_id and str(vulnerability_id) not in retest_vulnerability_ids:
                    retest_vulnerability_ids.append(str(vulnerability_id))

        # _finish_authorization_replay_run is the engine-agnostic retest finalizer:
        # it maps counters to the decision-B outcome vocabulary, records the hashed
        # remediation-retest evidence, and transitions the source finding's status.
        await _finish_authorization_replay_run(
            db,
            run=run,
            status="COMPLETED",
            executed=executed,
            vulnerable=vulnerable,
            errors=errors,
            skipped=0,
            reason=None,
        )
        db.add(
            AuditLog(
                account_id=int(run.account_id),
                action="SCAN_RUN_COMPLETED",
                resource_type="test_run",
                resource_id=run.id,
                details={
                    "run_id": run.id,
                    "worker_id": claimed.worker_id,
                    "engine": engine_name,
                    "execution_mode": "queued_retest",
                    "retest_vulnerability_ids": retest_vulnerability_ids,
                    "executed": executed,
                    "vulnerable": vulnerable,
                    "errors": errors,
                    "worker_isolation": worker_isolation or {},
                },
            )
        )
        await db.commit()
        return {
            "status": "completed",
            "engine": engine_name,
            "executed": executed,
            "vulnerable": vulnerable,
            "errors": errors,
            "retest_vulnerability_ids": retest_vulnerability_ids,
        }


def _authorization_replay_options(scan_plan: dict[str, object] | None) -> dict[str, object]:
    raw_options = {}
    if isinstance(scan_plan, dict) and isinstance(scan_plan.get(_AUTHORIZATION_REPLAY_ENGINE), dict):
        raw_options = scan_plan[_AUTHORIZATION_REPLAY_ENGINE]

    return {
        "allow_state_change": bool(raw_options.get("allow_state_change", False)),
        "require_response_similarity": bool(raw_options.get("require_response_similarity", True)),
        "body_similarity_threshold": _safe_float(raw_options.get("body_similarity_threshold"), 70.0),
        "schema_similarity_threshold": _safe_float(raw_options.get("schema_similarity_threshold"), 70.0),
        "attacker_account_ids": [
            str(account_id)
            for account_id in (raw_options.get("attacker_account_ids") or [])
            if isinstance(account_id, str) and account_id
        ],
    }


def _safe_float(value: object, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _http_content(body: object) -> str | bytes | None:
    if body in (None, ""):
        return None
    if isinstance(body, (str, bytes)):
        return body
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


def _authorization_replay_template_id(issue_type: str | None, victim: TestAccount | None, attacker: TestAccount) -> str:
    victim_role = authorization_role_key(victim) or "UNKNOWN"
    attacker_role = authorization_role_key(attacker) or "UNKNOWN"
    return f"{issue_type or 'AUTHZ'}_AUTHZ_REPLAY_{victim_role}_TO_{attacker_role}"[:100]


async def _load_authorization_replay_endpoint_and_sample(
    db,
    *,
    account_id: int,
    endpoint_id: str,
) -> tuple[APIEndpoint, SampleData]:
    endpoint = (
        await db.execute(
            select(APIEndpoint).where(
                APIEndpoint.id == endpoint_id,
                APIEndpoint.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if endpoint is None:
        raise ValueError("authorization_replay_endpoint_not_found")

    sample = (
        await db.execute(
            select(SampleData)
            .where(
                SampleData.endpoint_id == endpoint_id,
                SampleData.account_id == account_id,
            )
            .order_by(SampleData.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if sample is None:
        raise ValueError("authorization_replay_sample_missing")
    return endpoint, sample


async def _authorization_replay_accounts(db, *, account_id: int) -> tuple[list[TestAccount], list[TestAccount]]:
    result = await db.execute(
        select(TestAccount)
        .where(TestAccount.account_id == account_id)
        .order_by(TestAccount.created_at.asc())
    )
    all_accounts = result.scalars().all()
    # COV-1: expired, disabled, and credential-less identities never enter the matrix.
    # Anonymous-role accounts stay eligible: they are the unauthenticated baseline.
    return all_accounts, eligible_test_accounts(all_accounts)


async def _execute_authorization_replay_claimed_run(
    claimed: ClaimedScanRun,
    *,
    db_bind: AsyncEngine | None,
    worker_isolation: dict[str, object] | None = None,
    worker_isolation_context: dict[str, object] | None = None,
    finalize_run: bool = True,
) -> dict[str, object]:
    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    async with session_factory() as db:
        run = (
            await db.execute(
                select(TestRun).where(
                    TestRun.id == claimed.run_id,
                    TestRun.account_id == claimed.account_id,
                    TestRun.worker_id == claimed.worker_id,
                    TestRun.status.in_(WORKER_HELD_STATUSES),
                )
            )
        ).scalar_one_or_none()
        if run is None:
            return {"status": "aborted", "reason": "worker_claim_lost", "run_id": claimed.run_id}

        now = _utc_now()
        run.status = "RUNNING"
        run.worker_heartbeat_at = now
        options = _authorization_replay_options(claimed.scan_plan)
        execution_results: list[dict[str, object]] = []
        executed = 0
        vulnerable = 0
        errors = 0
        skipped = 0
        first_target_url = None
        replay_plan = claimed.scan_plan.get("authorization_replay") if isinstance(claimed.scan_plan, dict) else None
        replay_endpoint_ids = (
            [str(endpoint_id) for endpoint_id in replay_plan.get("endpoint_ids") if endpoint_id]
            if isinstance(replay_plan, dict) and isinstance(replay_plan.get("endpoint_ids"), list)
            else list(claimed.endpoint_ids)
        )
        endpoint_ids = [
            endpoint_id for endpoint_id in claimed.endpoint_ids
            if endpoint_id in replay_endpoint_ids
        ] or (list(claimed.endpoint_ids) if finalize_run else [])

        try:
            for endpoint_id in endpoint_ids:
                ensure_pentest_not_killed()
                await heartbeat_claimed_run(
                    claimed.run_id,
                    claimed.worker_id or "",
                    db_bind=db_bind,
                    account_id=claimed.account_id,
                )
                summary = await _execute_authorization_replay_endpoint(
                    db,
                    account_id=claimed.account_id,
                    run_id=claimed.run_id,
                    endpoint_id=endpoint_id,
                    options=options,
                    source_vulnerability_id=claimed.source_vulnerability_id,
                )
                execution_results.append(summary)
                first_target_url = first_target_url or str(summary.get("target_url") or "")
                executed += int(summary.get("executed") or 0)
                vulnerable += int(summary.get("vulnerable") or 0)
                errors += int(summary.get("errors") or 0)
                skipped += int(summary.get("skipped") or 0)
        except PentestKillSwitchError as exc:
            errors += 1
            reason = Redactor.redact_text(str(exc))
            if finalize_run:
                await _finish_authorization_replay_run(
                    db,
                    run=run,
                    status="FAILED",
                    executed=executed,
                    vulnerable=vulnerable,
                    errors=errors,
                    skipped=skipped,
                    reason=reason,
                )
            if finalize_run:
                db.add(
                    AuditLog(
                        account_id=int(run.account_id),
                        action="SCAN_RUN_FAILED",
                        resource_type="test_run",
                        resource_id=run.id,
                        details=_redacted_worker_failure_context(
                            run_id=run.id,
                            worker_id=claimed.worker_id,
                            reason=reason,
                            previous_status="RUNNING",
                            worker_isolation=worker_isolation,
                            engine=_AUTHORIZATION_REPLAY_ENGINE,
                        ),
                    )
                )
            await db.commit()
            return {
                "status": "failed",
                "engine": _AUTHORIZATION_REPLAY_ENGINE,
                "executed": executed,
                "vulnerable": vulnerable,
                "errors": errors,
                "skipped": skipped,
                "reason": reason,
            }
        except Exception as exc:
            errors += 1
            reason = Redactor.redact_text(str(exc))
            if finalize_run:
                await _finish_authorization_replay_run(
                    db,
                    run=run,
                    status="FAILED",
                    executed=executed,
                    vulnerable=vulnerable,
                    errors=errors,
                    skipped=skipped,
                    reason=reason,
                )
            if finalize_run:
                db.add(
                    AuditLog(
                        account_id=int(run.account_id),
                        action="SCAN_RUN_FAILED",
                        resource_type="test_run",
                        resource_id=run.id,
                        details=_redacted_worker_failure_context(
                            run_id=run.id,
                            worker_id=claimed.worker_id,
                            reason=reason,
                            previous_status="RUNNING",
                            worker_isolation=worker_isolation,
                            engine=_AUTHORIZATION_REPLAY_ENGINE,
                        ),
                    )
                )
            await db.commit()
            return {
                "status": "failed",
                "engine": _AUTHORIZATION_REPLAY_ENGINE,
                "executed": executed,
                "vulnerable": vulnerable,
                "errors": errors,
                "skipped": skipped,
                "reason": reason,
            }

        if finalize_run:
            await _finish_authorization_replay_run(
                db,
                run=run,
                status="COMPLETED",
                executed=executed,
                vulnerable=vulnerable,
                errors=errors,
                skipped=skipped,
                reason=None,
            )
        execution_payload = {
            "status": "COMPLETED",
            "engine": _AUTHORIZATION_REPLAY_ENGINE,
            "executed": executed,
            "vulnerable": vulnerable,
            "errors": errors,
            "skipped": skipped,
            "trigger_source": claimed.trigger_source,
            "source_vulnerability_id": claimed.source_vulnerability_id,
            "worker_id": claimed.worker_id,
            "claim_count": claimed.claim_count,
            "test_intensity": claimed.test_intensity,
            "scan_plan": claimed.scan_plan,
            "results": execution_results,
            "worker_isolation_enforcement": worker_isolation_enforcement_metadata(
                worker_isolation_context,
                engine=_AUTHORIZATION_REPLAY_ENGINE,
            ),
        }
        await persist_execution_artifact(
            db,
            account_id=claimed.account_id,
            engine=_AUTHORIZATION_REPLAY_ENGINE,
            target_url=first_target_url or "http://unknown.local/",
            profile_id=claimed.pentest_profile_id,
            execution=execution_payload,
            engine_plan=_scan_plan_engine_plan(claimed.scan_plan),
            findings={
                "created_count": vulnerable,
                "vulnerable_count": vulnerable,
                "endpoint_count": len(claimed.endpoint_ids),
            },
            auth_context=claimed.auth_context,
            run_id=claimed.run_id,
            worker_isolation=worker_isolation,
        )
        if finalize_run:
            db.add(
                AuditLog(
                    account_id=claimed.account_id,
                    action="SCAN_RUN_COMPLETED",
                    resource_type="test_run",
                    resource_id=claimed.run_id,
                    details={
                        "engine": _AUTHORIZATION_REPLAY_ENGINE,
                        "executed": executed,
                        "vulnerable": vulnerable,
                        "errors": errors,
                        "skipped": skipped,
                        "trigger_source": claimed.trigger_source,
                        "source_vulnerability_id": claimed.source_vulnerability_id,
                        "worker_id": claimed.worker_id,
                        "scan_plan": _scan_plan_claim_summary(claimed.scan_plan),
                    },
                )
            )
        await db.commit()

    return {
        "status": "completed",
        "engine": _AUTHORIZATION_REPLAY_ENGINE,
        "executed": executed,
        "vulnerable": vulnerable,
        "errors": errors,
        "skipped": skipped,
    }


async def _execute_authorization_replay_endpoint(
    db,
    *,
    account_id: int,
    run_id: str,
    endpoint_id: str,
    options: dict[str, object],
    source_vulnerability_id: str | None,
) -> dict[str, object]:
    endpoint, sample = await _load_authorization_replay_endpoint_and_sample(
        db,
        account_id=account_id,
        endpoint_id=endpoint_id,
    )
    original_request = dict(sample.request or {})
    original_response = dict(sample.response or {})
    original_url = str(original_request.get("url") or endpoint_target_url(endpoint))
    original_request["url"] = original_url
    original_request["method"] = str(original_request.get("method") or endpoint.method or "GET").upper()

    target_guard = TargetGuard.from_settings()
    allow_state_change = bool(options.get("allow_state_change"))
    allow_destructive_methods = bool(
        options.get(
            "allow_destructive_methods",
            options.get("allow_destructive", False),
        )
    )
    state_guard = StateChangeGuard(
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )
    target_guard.validate_url(original_url)
    state_guard.validate_request(original_request)

    all_accounts, replayable_accounts = await _authorization_replay_accounts(db, account_id=account_id)
    victim = infer_victim_account(all_accounts, original_request)
    requested_attacker_ids = set(options.get("attacker_account_ids") or [])
    if requested_attacker_ids:
        # An explicit attacker selection replays exactly those identities.
        attackers = [
            account for account in replayable_accounts if getattr(account, "id", None) in requested_attacker_ids
        ]
    else:
        attackers = [
            account
            for account in replayable_accounts
            if victim is None or getattr(account, "id", None) != getattr(victim, "id", None)
        ]
    if not attackers:
        return {
            "endpoint_id": endpoint_id,
            "target_url": Redactor.redact_url(original_url),
            "executed": 0,
            "vulnerable": 0,
            "errors": 0,
            "skipped": 1,
            "reason": "no_replayable_attacker_accounts",
        }

    executed = 0
    vulnerable = 0
    errors = 0
    results: list[dict[str, object]] = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        for attacker in attackers:
            replay_request = build_replay_request(original_request, attacker)
            replay_request["method"] = str(replay_request.get("method") or "GET").upper()
            replay_url = str(replay_request.get("url") or original_url)
            target_guard.validate_url(replay_url, base_url=original_url)
            state_guard.validate_request(replay_request)
            started_at = _utc_now()
            response = await client.request(
                method=replay_request["method"],
                url=replay_url,
                headers=replay_request.get("headers", {}),
                content=_http_content(replay_request.get("body")),
            )
            finished_at = _utc_now()
            attacker_response = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:4000],
                "duration_ms": int((finished_at - started_at).total_seconds() * 1000),
                "url": replay_url,
            }
            assessment = evaluate_authorization_replay(
                original_response,
                attacker_response,
                body_similarity_threshold=float(options.get("body_similarity_threshold") or 70.0),
                schema_similarity_threshold=float(options.get("schema_similarity_threshold") or 70.0),
                require_response_similarity=bool(options.get("require_response_similarity", True)),
            )
            issue_type = classify_authorization_issue(
                victim=victim,
                attacker=attacker,
                assessment=assessment,
                original_request=original_request,
                replay_request=replay_request,
            )
            evidence = build_authorization_replay_evidence(
                endpoint_id=endpoint_id,
                issue_type=issue_type,
                victim=victim,
                attacker=attacker,
                original_request=original_request,
                original_response=original_response,
                replay_request=replay_request,
                attacker_response=attacker_response,
                assessment=assessment,
                allow_state_change=bool(options.get("allow_state_change")),
            )
            safe_request = Redactor.redact_http_message(replay_request)
            safe_response = Redactor.redact_http_message(attacker_response)
            test_result = TestResult(
                run_id=run_id,
                endpoint_id=endpoint_id,
                template_id=_authorization_replay_template_id(issue_type, victim, attacker),
                is_vulnerable=bool(issue_type),
                severity="HIGH" if issue_type else "INFO",
                sent_request=safe_request,
                received_response=safe_response,
                percentage_match=assessment.get("similarity_pct"),
                evidence=json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str),
            )
            db.add(test_result)
            await db.flush()

            vulnerability_summary = None
            if issue_type:
                vulnerable += 1
                if source_vulnerability_id:
                    vulnerability_summary = {
                        "id": source_vulnerability_id,
                        "created": False,
                        "template_id": test_result.template_id,
                        "type": issue_type,
                    }
                else:
                    vulnerability, created, fingerprint = await create_or_merge_vulnerability(
                        db,
                        {
                            "account_id": account_id,
                            "template_id": test_result.template_id,
                            "endpoint_id": endpoint_id,
                            "url": Redactor.redact_url(replay_url),
                            "method": replay_request["method"],
                            "severity": "HIGH" if assessment.get("confidence") == "HIGH" else "MEDIUM",
                            "type": issue_type,
                            "description": (
                                f"{issue_type} authorization replay succeeded for "
                                f"{authorization_identity_label(attacker)} against captured victim traffic."
                            ),
                            "confidence": assessment.get("confidence"),
                            "remediation": (
                                "Enforce object and function-level authorization on every request using server-side "
                                "ownership, tenant, and role checks. Deny by default when the authenticated principal "
                                "does not own the object or lacks the required role."
                            ),
                            "evidence": evidence,
                        },
                    )
                    vulnerability_summary = {
                        "id": vulnerability.id,
                        "created": created,
                        "fingerprint": fingerprint,
                        "template_id": vulnerability.template_id,
                        "type": vulnerability.type,
                    }

            executed += 1
            results.append(
                {
                    "attacker": authorization_identity_summary(attacker),
                    "victim": authorization_identity_summary(victim),
                    "test_id": test_result.id,
                    "issue_type": issue_type,
                    "is_vulnerable": bool(issue_type),
                    "response_code": assessment.get("attacker_status_code"),
                    "confidence": assessment.get("confidence"),
                    "vulnerability": vulnerability_summary,
                }
            )

    return {
        "endpoint_id": endpoint_id,
        "target_url": Redactor.redact_url(original_url),
        "executed": executed,
        "vulnerable": vulnerable,
        "errors": errors,
        "skipped": 0,
        "results": results,
    }


async def _finish_authorization_replay_run(
    db,
    *,
    run: TestRun,
    status: str,
    executed: int,
    vulnerable: int,
    errors: int,
    skipped: int,
    reason: str | None,
) -> None:
    run.status = status
    run.completed_at = _utc_now()
    run.total_tests = executed
    run.vulnerable_count = vulnerable
    run.error_count = errors
    run.dispatch_lease_expires_at = None
    outcome = (
        "FAILED"
        if status == "FAILED" or errors > 0
        else "NO_EXECUTION"
        if executed == 0
        else "STILL_VULNERABLE"
        if vulnerable > 0
        else "CLEAN"
    )
    await _record_authorization_replay_retest_outcome(
        db,
        run=run,
        status=status,
        outcome=outcome,
        executed=executed,
        vulnerable=vulnerable,
        errors=errors,
        skipped=skipped,
        reason=reason,
    )


async def _record_authorization_replay_retest_outcome(
    db,
    *,
    run: TestRun,
    status: str,
    outcome: str,
    executed: int,
    vulnerable: int,
    errors: int,
    skipped: int,
    reason: str | None,
) -> None:
    if not is_vulnerability_retest_trigger_source(run.trigger_source) or not run.source_vulnerability_id:
        return
    source = (
        await db.execute(
            select(Vulnerability).where(
                Vulnerability.id == run.source_vulnerability_id,
                Vulnerability.account_id == run.account_id,
            )
        )
    ).scalar_one_or_none()
    if source is None:
        return

    now = _utc_now()
    previous_status = source.status
    retest = {
        "run_id": run.id,
        "status": status,
        "outcome": outcome,
        "completed_at": isoformat(now),
        "executed": int(executed),
        "vulnerable": int(vulnerable),
        "errors": int(errors),
        "skipped": int(skipped),
    }
    if reason:
        retest["reason"] = Redactor.redact_text(reason)
    retest["hash_algorithm"] = "sha256"
    retest["retest_hash"] = retest_outcome_digest(retest)

    evidence = dict(source.evidence or {})
    previous_retests = evidence.get("remediation_retests")
    if not isinstance(previous_retests, list):
        previous_retests = []
    evidence["remediation_retests"] = (previous_retests + [retest])[-10:]
    evidence["latest_remediation_retest"] = retest
    source.evidence = evidence

    if not source.false_positive and str(source.status or "").upper() != "ACCEPTED_RISK":
        if outcome == "CLEAN":
            source.status = "CLOSED"
        elif outcome == "STILL_VULNERABLE":
            source.status = "OPEN"
            source.last_seen_at = now

    db.add(
        AuditLog(
            account_id=int(run.account_id),
            action="VULNERABILITY_RETEST_COMPLETED",
            resource_type="vulnerability",
            resource_id=source.id,
            details={
                "run_id": run.id,
                "status": status,
                "outcome": outcome,
                "previous_status": previous_status,
                "new_status": source.status,
                "executed": int(executed),
                "vulnerable": int(vulnerable),
                "errors": int(errors),
                "skipped": int(skipped),
                "reason": reason,
                "hash_algorithm": retest["hash_algorithm"],
                "retest_hash": retest["retest_hash"],
                "retest_integrity": latest_remediation_retest_integrity(evidence),
            },
        )
    )


async def _claimed_run_cancel_requested(
    db_bind: AsyncEngine | None,
    *,
    run_id: str,
    account_id: int,
) -> bool:
    """Return True when an operator has requested cancellation of the claimed run."""
    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    async with session_factory() as db:
        status = await db.scalar(
            select(TestRun.status).where(
                TestRun.id == run_id,
                TestRun.account_id == account_id,
            )
        )
    return str(status or "").upper() in {"CANCEL_REQUESTED", "CANCELED"}


async def _assert_claim_live(claimed: ClaimedScanRun, *, db_bind: AsyncEngine | None) -> None:
    """Raise on operator cancel, or on claim loss when the lease is no longer ours.

    Cancel is intentionally checked before the heartbeat: an operator cancel sets the run
    to CANCEL_REQUESTED, which the heartbeat's status filter rejects, so ordering matters.
    """
    if await _claimed_run_cancel_requested(
        db_bind, run_id=claimed.run_id, account_id=claimed.account_id
    ):
        raise ScanCancelRequestedError("cancel_requested")
    if not await heartbeat_claimed_run(
        claimed.run_id, claimed.worker_id,
        db_bind=db_bind, account_id=claimed.account_id,
    ):
        raise RuntimeError("worker_claim_lost")


async def _run_external_with_lease(claimed: ClaimedScanRun, *, db_bind, **kwargs):
    task = asyncio.create_task(_execute_planned_external_engines(claimed, db_bind=db_bind, **kwargs))
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=max(0.1, min(5, _lease_seconds() / 3)))
            if done:
                return await task
            ensure_pentest_not_killed()
            await _assert_claim_live(claimed, db_bind=db_bind)
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


async def _execute_planned_external_engines(
    claimed: ClaimedScanRun,
    *,
    db_bind: AsyncEngine | None,
    worker_isolation_context: dict[str, object] | None,
    worker_isolation: dict[str, object] | None = None,
) -> dict[str, object]:
    """Execute every ready external engine from the immutable scan plan."""
    scan_plan = claimed.scan_plan if isinstance(claimed.scan_plan, dict) else {}
    engine_plan = _scan_plan_engine_plan(scan_plan)
    ready_engines = [
        str(item.get("engine"))
        for item in engine_plan
        if isinstance(item, dict)
        and item.get("status") == "ready"
        and str(item.get("engine")) in _EXTERNAL_ENGINE_ARTIFACT_TYPES_BY_ENGINE
    ]
    if not ready_engines:
        return {"status": "completed", "engines": [], "reason": "no_external_engines_ready"}
    if not verify_scan_plan_integrity(scan_plan).get("verified"):
        raise ValueError("worker_scan_plan_integrity_failed")

    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    engine_results: list[dict[str, object]] = []
    async with session_factory() as db:
        endpoints = list(
            (
                await db.execute(
                    select(APIEndpoint).where(
                        APIEndpoint.account_id == claimed.account_id,
                        APIEndpoint.id.in_(claimed.endpoint_ids),
                    )
                )
            ).scalars().all()
        )
        if not endpoints or {str(ep.id) for ep in endpoints} != set(claimed.endpoint_ids):
            return {"status": "failed", "reason": "worker_endpoints_missing", "engines": []}

        target_urls = {endpoint_target_url(endpoint) for endpoint in endpoints}
        target_hosts = {(urlsplit(url).scheme, urlsplit(url).netloc) for url in target_urls}
        if len(target_hosts) > 1:
            return {
                "status": "failed",
                "reason": "worker_multi_target_run_requires_separate_scopes",
                "engines": [],
            }
        # External engines require an explicit target binding, never an arbitrary
        # endpoint or the tenant's most recently imported specification.
        binding = scan_plan.get("external_engine_scope") or {}
        target_url = binding.get("target_url")
        if not isinstance(target_url, str) or not target_url:
            raise ValueError("worker_external_target_binding_missing")
        parsed_target = urlsplit(target_url)
        if (parsed_target.scheme, parsed_target.netloc) not in target_hosts:
            raise ValueError("worker_external_target_scope_mismatch")
        validate_pentest_target(target_url)

        profile, auth_profile = await load_profile_and_auth_for_active_scan(
            db,
            account_id=claimed.account_id,
            pentest_profile_id=claimed.pentest_profile_id,
            profiles=PentestProfileService(),
        )
        if profile is None:
            return {"status": "failed", "reason": "worker_pentest_profile_missing", "engines": []}
        if auth_profile is None:
            raise ValueError("worker_external_auth_profile_required")
        from sentinel_core.modules.pentest.auth_scope import validate_auth_profile_scope
        validate_auth_profile_scope(auth_profile, target_url)

        spec_record = (
            await db.execute(
                select(OpenAPISpec)
                .where(OpenAPISpec.account_id == claimed.account_id, OpenAPISpec.id == binding.get("openapi_spec_id"))
                .limit(1)
            )
        ).scalar_one_or_none()
        # ISO-1: record what this worker can actually run; the plan's runtime_available
        # was evaluated on the API host and is advisory for the executing worker.
        worker_capabilities = _worker_engine_capabilities()
        if spec_record is not None and binding.get("openapi_spec_sha256") != worker_spec_digest(spec_record.spec_json):
            raise ValueError("worker_openapi_spec_changed")
        scoped_spec = scoped_worker_spec(spec_record.spec_json, endpoints, target_url) if spec_record else None
        auth_context = build_auth_readiness(profile=profile, auth_profile=auth_profile, require_authenticated_active_scan=True)
        execution_id = f"{claimed.run_id}-worker"

        for engine_name in ready_engines:
            ensure_pentest_not_killed()
            await _assert_claim_live(claimed, db_bind=db_bind)
            try:
                if engine_name == "schemathesis":
                    if spec_record is None or not isinstance(spec_record.spec_json, dict):
                        raise ValueError("worker_openapi_spec_missing")
                    execution = await SchemathesisRunner().run_scan(
                        target_url=target_url,
                        openapi_spec=scoped_spec,
                        profile=profile,
                        auth_profile=auth_profile,
                        timeout_seconds=settings.PENTEST_SCHEMATHESIS_TIMEOUT_SECONDS,
                        worker_isolation_context=worker_isolation_context,
                    )
                    openapi_spec_id = spec_record.id
                elif engine_name == "nuclei":
                    if not (profile.allow_state_change and profile.allow_destructive_methods):
                        raise ValueError("worker_nuclei_requires_explicit_method_arming")
                    secret_file = NucleiSecretFileBuilder().build(
                        auth_profile=auth_profile,
                        target_url=target_url,
                    )
                    execution = await NucleiRunner.run_scan(
                        target=target_url,
                        tags=getattr(profile, "nuclei_template_tags", None) or None,
                        secret_file_content=secret_file.get("content"),
                        include_dast=bool(getattr(profile, "nuclei_include_dast", False)),
                        timeout=settings.NUCLEI_TIMEOUT,
                        worker_isolation_context=worker_isolation_context,
                    )
                    openapi_spec_id = None
                else:
                    if spec_record is None or not isinstance(spec_record.spec_json, dict):
                        raise ValueError("worker_openapi_spec_missing")
                    execution = await ZapRunner().run_scan(
                        target_url=target_url,
                        openapi_spec=scoped_spec,
                        profile=profile,
                        auth_profile=auth_profile,
                        timeout_seconds=settings.PENTEST_ZAP_TIMEOUT_SECONDS,
                        worker_isolation_context=worker_isolation_context,
                    )
                    openapi_spec_id = spec_record.id
            except Exception as exc:
                execution = {
                    "status": "FAILED",
                    "reason": "worker_external_engine_failed",
                    "error_type": type(exc).__name__,
                }
                openapi_spec_id = None

            safe_execution = Redactor.redact_json(execution)
            if not isinstance(safe_execution, dict):
                safe_execution = {"status": "FAILED", "reason": "invalid_engine_result"}
            findings = {
                "failures": int(safe_execution.get("failures") or 0),
                "alerts": int(safe_execution.get("alerts") or 0),
                "total_found": int(safe_execution.get("total_found") or 0),
            }
            await _assert_claim_live(claimed, db_bind=db_bind)
            if engine_name == "schemathesis" and safe_execution.get("junit_xml"):
                findings.update(await persist_schemathesis_junit(db, account_id=claimed.account_id, target_url=target_url, junit_xml=safe_execution["junit_xml"]))
            elif engine_name == "nuclei" and safe_execution.get("findings"):
                findings.update(await persist_nuclei_findings(db, account_id=claimed.account_id, target=target_url, findings=safe_execution["findings"]))
            elif engine_name == "zap" and safe_execution.get("report"):
                findings.update(await persist_zap_report(db, account_id=claimed.account_id, target_url=target_url, report=safe_execution["report"]))
            artifact = await persist_execution_artifact(
                db,
                account_id=claimed.account_id,
                engine=engine_name,
                target_url=target_url,
                profile_id=profile.id,
                openapi_spec_id=openapi_spec_id,
                execution={
                    **safe_execution,
                    "scan_plan": _scan_plan_claim_summary(scan_plan),
                    "worker_id": claimed.worker_id,
                    "claim_count": claimed.claim_count,
                },
                engine_plan=engine_plan,
                findings=findings,
                auth_context=auth_context,
                run_id=claimed.run_id,
                execution_id=execution_id,
                worker_isolation=worker_isolation,
                worker_capabilities=worker_capabilities,
            )
            engine_results.append(
                {
                    "engine": engine_name,
                    "status": safe_execution.get("status"),
                    "artifact_id": str(artifact.id),
                    "artifact_type": artifact.artifact_type,
                    "artifact_hash": (artifact.content_json or {}).get("artifact_hash"),
                    "finding_summary": _external_finding_summary(findings),
                }
            )
            await db.commit()

            if str(safe_execution.get("status") or "").upper() not in SUCCESSFUL_ENGINE_EXECUTION_STATUSES:
                break

    failed = any(
        not engine_execution_succeeded(item.get("status"))
        for item in engine_results
    )
    finding_summary = _aggregate_external_finding_summaries(
        [item.get("finding_summary") for item in engine_results]
    )
    return {
        "status": "failed" if failed else "completed",
        "engines": Redactor.redact_json(engine_results),
        "engine_count": len(engine_results),
        "finding_summary": finding_summary,
    }


def _external_finding_summary(findings: dict[str, object]) -> dict[str, object]:
    """Return the stable run/report contract for one external engine."""
    vulnerabilities = findings.get("vulnerabilities")
    vulnerability_ids = [
        str(item.get("id"))
        for item in vulnerabilities
        if isinstance(item, dict) and item.get("id")
    ] if isinstance(vulnerabilities, list) else []
    created = _safe_nonnegative_int(findings.get("created_count"))
    merged = _safe_nonnegative_int(findings.get("merged_count"))
    normalized = _safe_nonnegative_int(findings.get("normalized_finding_count"))
    return {
        "created_count": created,
        "merged_count": merged,
        "normalized_finding_count": normalized or created + merged,
        "vulnerability_ids": vulnerability_ids,
    }


def _aggregate_external_finding_summaries(
    summaries: list[object],
) -> dict[str, object]:
    created = 0
    merged = 0
    normalized = 0
    vulnerability_ids: list[str] = []
    for item in summaries:
        if not isinstance(item, dict):
            continue
        created += _safe_nonnegative_int(item.get("created_count"))
        merged += _safe_nonnegative_int(item.get("merged_count"))
        normalized += _safe_nonnegative_int(item.get("normalized_finding_count"))
        for vulnerability_id in item.get("vulnerability_ids") or []:
            if vulnerability_id and str(vulnerability_id) not in vulnerability_ids:
                vulnerability_ids.append(str(vulnerability_id))
    return {
        "created_count": created,
        "merged_count": merged,
        "normalized_finding_count": normalized,
        "vulnerability_ids": vulnerability_ids,
    }


def _safe_nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


async def run_pending_scan_once(
    *,
    db_bind: AsyncEngine | None = None,
    account_id: int | None = None,
    worker_id: str | None = None,
) -> dict[str, object]:
    """Claim and execute one queued scan run outside the FastAPI request lifecycle."""
    if kill_switch_enabled():
        return {"status": "paused", "claimed": False, "reason": KILL_SWITCH_REASON}

    claimed = await claim_next_pending_run(db_bind=db_bind, account_id=account_id, worker_id=worker_id)
    if claimed is None:
        return {"status": "idle", "claimed": False}

    engine_name = _claimed_execution_engine(claimed)
    run_timeout = _worker_run_timeout_seconds()
    isolation_session = create_worker_isolation_session(
        run_id=claimed.run_id,
        worker_id=claimed.worker_id or "",
        account_id=claimed.account_id,
        engine=engine_name,
        claim_count=claimed.claim_count,
        lease_expires_at=claimed.lease_expires_at,
        timeout_seconds=run_timeout,
    )
    worker_isolation_context = isolation_session.to_runtime_context()
    worker_isolation = isolation_session.to_metadata(
        runtime_context_created=True,
        enforced_engines=[engine_name] + [
            str(item.get("engine")) for item in _scan_plan_engine_plan(claimed.scan_plan)
            if item.get("status") == "ready" and item.get("engine") in _EXTERNAL_ENGINE_ARTIFACT_TYPES_BY_ENGINE
        ],
    )
    cleanup: dict[str, object] | None = None
    execution: dict[str, object] = {"status": "failed", "reason": "worker_execution_not_started"}

    async def _execute_claimed() -> dict[str, object]:
        ensure_pentest_not_killed()
        external_execution = await _run_external_with_lease(
            claimed, db_bind=db_bind,
            worker_isolation_context=worker_isolation_context,
            worker_isolation=worker_isolation,
        )
        if str(external_execution.get("status") or "").lower() == "failed":
            raise RuntimeError("external_engine_execution_failed")
        authorization_replay = None
        replay_requested = _claimed_run_requests_authorization_replay(claimed)
        replay_only = _claimed_run_is_authorization_replay_only(claimed)
        if replay_requested:
            authorization_replay = await _execute_authorization_replay_claimed_run(
                claimed,
                db_bind=db_bind,
                worker_isolation=worker_isolation,
                worker_isolation_context=worker_isolation_context,
                finalize_run=replay_only,
            )
            if str(authorization_replay.get("status") or "").lower() == "failed":
                raise RuntimeError("authorization_replay_execution_failed")
        if _claimed_run_requests_external_engine_retest(claimed):
            # LIFE-1: the engine ran in the external phase above; finalize the
            # retest lifecycle from its verified artifacts. Skips the templates phase.
            primary_execution = await _execute_external_engine_retest_claimed_run(
                claimed,
                db_bind=db_bind,
                worker_isolation=worker_isolation,
                worker_isolation_context=worker_isolation_context,
            )
        elif replay_only:
            primary_execution = authorization_replay or {"status": "completed"}
        else:
            from sentinel_worker.modules.test_executor.run_executor import run_security_tasks

            primary_execution = await run_security_tasks(
                claimed.run_id,
                claimed.template_ids,
                claimed.endpoint_ids,
                claimed.account_id,
                claimed.pentest_profile_id,
                worker_id=claimed.worker_id,
                db_bind=db_bind,
                worker_isolation=worker_isolation,
                worker_isolation_context=worker_isolation_context,
            ) or {"status": "completed"}

        return {
            **primary_execution,
            "authorization_replay": authorization_replay,
            "external_engines": external_execution,
            "status": (
                "failed"
                if str(external_execution.get("status") or "").lower() == "failed"
                else primary_execution.get("status", "completed")
            ),
        }

    try:
        try:
            execution = await asyncio.wait_for(_execute_claimed(), timeout=run_timeout)
        except asyncio.TimeoutError:
            reason = f"worker_run_timed_out_after_{run_timeout}s"
            await _mark_claimed_run_failed(
                db_bind=db_bind,
                run_id=claimed.run_id,
                account_id=claimed.account_id,
                worker_id=claimed.worker_id,
                reason=reason,
                action="SCAN_RUN_TIMED_OUT",
                worker_isolation=worker_isolation,
                engine=engine_name,
            )
            # TIMEOUT (upper-snake) matches the runner status vocabulary (decision F).
            execution = {"status": "TIMEOUT", "reason": reason}
        except PentestKillSwitchError as exc:
            reason = Redactor.redact_text(str(exc))
            await _mark_claimed_run_failed(
                db_bind=db_bind,
                run_id=claimed.run_id,
                account_id=claimed.account_id,
                worker_id=claimed.worker_id,
                reason=reason,
                worker_isolation=worker_isolation,
                engine=engine_name,
            )
            execution = {"status": "failed", "reason": reason}
        except ScanCancelRequestedError:
            reason = "cancel_requested"
            await _mark_claimed_run_canceled(
                db_bind=db_bind,
                run_id=claimed.run_id,
                account_id=claimed.account_id,
                worker_id=claimed.worker_id,
                reason=reason,
                worker_isolation=worker_isolation,
                engine=engine_name,
            )
            execution = {"status": "canceled", "reason": reason}
        except Exception as exc:
            reason = Redactor.redact_text(str(exc))
            await _mark_claimed_run_failed(
                db_bind=db_bind,
                run_id=claimed.run_id,
                account_id=claimed.account_id,
                worker_id=claimed.worker_id,
                reason=reason,
                worker_isolation=worker_isolation,
                engine=engine_name,
            )
            execution = {"status": "failed", "reason": reason}
    finally:
        cleanup = cleanup_worker_isolation_session(isolation_session)

    execution_status = str(execution.get("status") or "completed").lower()
    # "executed" is the worker envelope vocabulary for a completed run. Every other
    # envelope status passes through with the execution status's own casing, so the
    # engine-level TIMEOUT (unified with the runners per decision F) stays upper-snake
    # while worker-flow outcomes (failed/aborted/canceled) stay lower-snake.
    worker_status = "executed" if execution_status == "completed" else str(execution.get("status") or "completed")
    result = {
        "status": worker_status,
        "claimed": True,
        "run_id": claimed.run_id,
        "templates": len(claimed.template_ids),
        "endpoints": len(claimed.endpoint_ids),
        "test_intensity": claimed.test_intensity,
        "scan_plan": _scan_plan_claim_summary(claimed.scan_plan),
        "pentest_profile_id": claimed.pentest_profile_id,
        "trigger_source": claimed.trigger_source,
        "source_vulnerability_id": claimed.source_vulnerability_id,
        "source_schedule_id": claimed.source_schedule_id,
        "worker_id": claimed.worker_id,
        "lease_expires_at": claimed.lease_expires_at.isoformat() if claimed.lease_expires_at else None,
        "engine_accountability": claimed.engine_accountability,
        "worker_isolation": {
            **worker_isolation,
            "cleanup": cleanup,
        },
        "execution": execution,
    }
    artifact_summary, artifact_payload = await _latest_worker_execution_artifact(
        db_bind=db_bind,
        claimed=claimed,
    )
    result["worker_artifact"] = artifact_summary
    artifact_records = await _latest_worker_execution_artifacts(
        db_bind=db_bind,
        claimed=claimed,
    )
    result["worker_artifacts"] = [summary for summary, _payload in artifact_records]
    result["worker_acceptance"] = validate_worker_staging_scan_acceptance(
        result,
        artifact_payload,
        artifact_payloads=[payload for _summary, payload in artifact_records],
    )
    return result


async def _latest_worker_execution_artifact(
    *,
    db_bind: AsyncEngine | None,
    claimed: ClaimedScanRun,
) -> tuple[dict[str, object], dict[str, object]]:
    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    engine = _claimed_execution_engine(claimed)
    artifact_type = f"{engine}_execution"
    async with session_factory() as db:
        artifact = (
            await db.execute(
                select(PentestArtifact)
                .where(
                    PentestArtifact.account_id == claimed.account_id,
                    PentestArtifact.run_id == claimed.run_id,
                    PentestArtifact.artifact_type == artifact_type,
                )
                .order_by(PentestArtifact.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    if artifact is None:
        return (
            {
                "present": False,
                "artifact_type": artifact_type,
                "artifact_verification": {
                    "verified": False,
                    "status": "MISSING",
                    "hash_algorithm": "sha256",
                },
            },
            {},
        )

    payload = artifact.content_json if isinstance(artifact.content_json, dict) else {}
    verification = verify_execution_artifact_payload(payload) if payload else {
        "verified": False,
        "status": "MISSING",
        "hash_algorithm": None,
    }
    return (
        {
            "present": bool(payload),
            "artifact_id": Redactor.redact_text(str(artifact.id)),
            "artifact_type": artifact.artifact_type,
            "filename": Redactor.redact_text(str(artifact.filename or "")),
            "hash_algorithm": payload.get("hash_algorithm"),
            "artifact_hash": payload.get("artifact_hash"),
            "artifact_verification": verification,
        },
        payload,
    )


async def _latest_worker_execution_artifacts(
    *,
    db_bind: AsyncEngine | None,
    claimed: ClaimedScanRun,
) -> list[tuple[dict[str, object], dict[str, object]]]:
    """Return all engine artifacts needed to accept a multi-engine worker run."""
    session_factory = AsyncSessionLocal if db_bind is None else async_sessionmaker(
        bind=db_bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    async with session_factory() as db:
        artifacts = (
            await db.execute(
                select(PentestArtifact)
                .where(
                    PentestArtifact.account_id == claimed.account_id,
                    PentestArtifact.run_id == claimed.run_id,
                )
                .order_by(PentestArtifact.created_at.asc())
            )
        ).scalars().all()
    records: list[tuple[dict[str, object], dict[str, object]]] = []
    for artifact in artifacts:
        payload = artifact.content_json if isinstance(artifact.content_json, dict) else {}
        records.append(
            (
                {
                    "present": bool(payload),
                    "artifact_id": Redactor.redact_text(str(artifact.id)),
                    "artifact_type": artifact.artifact_type,
                    "artifact_hash": payload.get("artifact_hash"),
                    "artifact_verification": verify_execution_artifact_payload(payload) if payload else {
                        "verified": False,
                        "status": "MISSING",
                    },
                },
                payload,
            )
        )
    return records


def _claimed_execution_engine(claimed: ClaimedScanRun) -> str:
    if _claimed_run_requests_authorization_replay(claimed):
        return _AUTHORIZATION_REPLAY_ENGINE
    if _claimed_run_requests_external_engine_retest(claimed):
        return _external_engine_retest_engine(claimed)
    return "templates"


async def run_worker_loop(
    *,
    db_bind: AsyncEngine | None = None,
    account_id: int | None = None,
    worker_id: str | None = None,
    poll_interval_seconds: float = 2.0,
    max_runs: int | None = None,
) -> dict[str, int]:
    """Continuously execute queued scans; useful for a dedicated worker process."""
    executed = 0
    claimed_count = 0
    aborted = 0
    failed = 0
    canceled = 0
    idle_cycles = 0
    while max_runs is None or claimed_count < max_runs:
        result = await run_pending_scan_once(db_bind=db_bind, account_id=account_id, worker_id=worker_id)
        if result.get("claimed"):
            claimed_count += 1
            status = str(result.get("status") or "")
            if status == "executed":
                executed += 1
            elif status == "aborted":
                aborted += 1
            elif status == "failed":
                failed += 1
            elif status == "canceled":
                canceled += 1
            idle_cycles = 0
            continue

        idle_cycles += 1
        if max_runs is not None:
            break
        await asyncio.sleep(max(0.1, poll_interval_seconds))

    return {
        "claimed": claimed_count,
        "executed": executed,
        "aborted": aborted,
        "failed": failed,
        "canceled": canceled,
        "idle_cycles": idle_cycles,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    """CLI for the dedicated scan-worker container / process."""
    parser = argparse.ArgumentParser(
        prog="api-sentinel-scan-worker",
        description="Poll and execute queued API Sentinel scan runs in an isolated worker process.",
    )
    parser.add_argument(
        "--account-id",
        type=int,
        default=_env_int("API_SENTINEL_ACCOUNT_ID"),
        help="Optional account scope for claim selection (or API_SENTINEL_ACCOUNT_ID).",
    )
    parser.add_argument(
        "--worker-id",
        default=os.environ.get("API_SENTINEL_WORKER_ID") or None,
        help="Stable worker identity for leases/heartbeats (or API_SENTINEL_WORKER_ID).",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=_env_float("PENTEST_SCAN_WORKER_POLL_INTERVAL", 2.0),
        help="Seconds to sleep when the queue is idle (default 2).",
    )
    parser.add_argument(
        "--max-runs",
        type=int,
        default=_env_int("PENTEST_SCAN_WORKER_MAX_RUNS"),
        help="Stop after N claimed runs; omit for continuous polling.",
    )
    return parser


def _env_int(name: str) -> int | None:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return None
    return int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    return float(raw)


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    summary = asyncio.run(
        run_worker_loop(
            account_id=args.account_id,
            worker_id=args.worker_id,
            poll_interval_seconds=max(0.1, float(args.poll_interval)),
            max_runs=args.max_runs,
        )
    )
    print(json.dumps({"status": "stopped", **summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
