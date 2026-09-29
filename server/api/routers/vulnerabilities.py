from fastapi import APIRouter, BackgroundTasks, Depends, Query, Body, HTTPException, Request
import datetime
from typing import Any
from urllib.parse import urlsplit
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, func
import uuid
from server.modules.persistence.database import get_db
from server.modules.auth.rbac import Permission, RBAC
from server.modules.validation.input_validator import InputValidator, ValidationError
from server.models.core import APIEndpoint, Integration, OpenAPISpec, TestRun, Vulnerability
import server.api.routers.tests as tests_router
from server.api.rate_limiter import limiter
from server.modules.auth.audit import log_action
from server.modules.integrations.jira_client import JiraClient
from server.modules.integrations.destination_guard import (
    IntegrationDestinationError,
    validate_integration_destination_config,
)
from server.modules.integrations.secrets import IntegrationSecretCodec
from server.modules.pentest.auth_preflight import active_scan_auth_audit_context
from server.modules.pentest.profiles import PentestProfile
from server.modules.test_executor.scan_plan import finalize_scan_plan_hash
from server.modules.test_executor.target_guard import endpoint_target_url
from server.modules.utils.redactor import Redactor
from server.modules.utils.finding_fingerprint import vulnerability_fingerprint
from server.modules.vulnerability_detector.lifecycle import (
    NON_EXECUTED_RETEST_OUTCOMES,
    VULNERABILITY_RETEST_TRIGGER_SOURCES,
    confirmation_result_from_evidence,
    confirmation_status_from_evidence,
    isoformat,
    latest_remediation_retest_integrity,
    retest_outcome_digest,
    utc_now,
    verify_vulnerability_evidence,
    evidence_with_lifecycle,
    vulnerability_lifecycle_payload,
    vulnerability_retest_support,
    vulnerability_sla_escalation,
    vulnerability_sla_status,
)
from server.modules.vulnerability_detector.ticketing import (
    TicketUrlError,
    build_vulnerability_ticket,
    evidence_closure_gate,
    ticket_url_from_key,
    validate_ticket_url,
    vulnerability_closure_gate,
    vulnerability_ticket_lifecycle_payload,
)

router = APIRouter()

_ALLOWED_VULNERABILITY_STATUSES = {
    "OPEN",
    "TRIAGED",
    "IN_REMEDIATION",
    "ACCEPTED_RISK",
    "CLOSED",
}
_ALLOWED_CONFIRMATION_STATUSES = {"CONFIRMED", "DISPROVEN", "UNCONFIRMED"}
_MANUAL_RETEST_TRIGGER = "vulnerability_retest"
_AUTO_RETEST_TRIGGER = "vulnerability_auto_retest"
_FIX_EVENT_RETEST_TRIGGER = "vulnerability_fix_event"
_TICKET_SYNC_RETEST_TRIGGER = "vulnerability_ticket_sync"
_AUTHORIZATION_REPLAY_ENGINE = "authorization_replay"
_AUTHORIZATION_REPLAY_TEMPLATE_ID = "AUTHORIZATION_REPLAY_MATRIX"
# LIFE-1: sentinel template_id for retests of external-engine findings (endpoint_id=None).
# The scan worker routes runs carrying this id to the external-engine retest executor;
# it never matches a template in the tests library.
_EXTERNAL_ENGINE_RETEST_TEMPLATE_ID = "EXTERNAL_ENGINE_RETEST"
_EXTERNAL_ENGINE_RETEST_ENGINES = frozenset({"schemathesis", "nuclei", "zap"})
_ACTIVE_RETEST_STATUSES = {"PENDING", "DISPATCHED", "RUNNING", "CANCEL_REQUESTED"}
_RETEST_TRIGGER_SOURCES = VULNERABILITY_RETEST_TRIGGER_SOURCES
_ALLOWED_REMEDIATION_EVENT_TYPES = {
    "FIX_DEPLOYED",
    "TICKET_RESOLVED",
    "PULL_REQUEST_MERGED",
    "CI_DEPLOYED",
    "MANUAL_FIX",
}
_TICKET_RESOLVED_STATUSES = {"DONE", "RESOLVED", "CLOSED", "COMPLETE", "COMPLETED"}
_TICKET_IN_PROGRESS_STATUSES = {"IN_PROGRESS", "IN PROGRESS", "REMEDIATING", "REMEDIATION"}
_TICKET_OPEN_STATUSES = {"OPEN", "TO_DO", "TO DO", "BACKLOG", "REOPENED"}


def _serialize_vulnerability(v: Vulnerability) -> dict:
    fingerprint = v.fingerprint or vulnerability_fingerprint(v)
    lifecycle = _redacted_lifecycle_payload(v, fingerprint=fingerprint)
    evidence = _redacted_vulnerability_evidence(v.evidence)
    return {
        "id": v.id,
        "template_id": v.template_id,
        "endpoint_id": v.endpoint_id,
        "url": Redactor.redact_text(v.url) if v.url else v.url,
        "method": v.method,
        "severity": v.severity,
        "type": v.type,
        "description": Redactor.redact_text(v.description) if v.description else v.description,
        "status": v.status,
        "confidence": v.confidence,
        "false_positive": v.false_positive,
        "evidence": evidence,
        "evidence_redacted": evidence != v.evidence,
        "evidence_integrity": verify_vulnerability_evidence(v.evidence),
        "closure_gate": vulnerability_closure_gate(v),
        "created_at": str(v.created_at),
        **lifecycle,
    }


def _redacted_vulnerability_evidence(evidence: Any) -> Any:
    if evidence is None:
        return None
    if isinstance(evidence, dict):
        return _fully_mask_sensitive_evidence_headers(Redactor.redact_scan_result(evidence))
    redacted = Redactor.redact_json(evidence)
    return redacted


def _fully_mask_sensitive_evidence_headers(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        if (key or "").lower().endswith("headers"):
            return {
                item_key: (
                    Redactor.REDACT_VALUE
                    if Redactor._is_sensitive_header(str(item_key).lower())
                    else _fully_mask_sensitive_evidence_headers(item_value, str(item_key))
                )
                for item_key, item_value in value.items()
            }
        return {
            item_key: _fully_mask_sensitive_evidence_headers(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_fully_mask_sensitive_evidence_headers(item, key) for item in value]
    return value


def _redacted_lifecycle_payload(vulnerability: Vulnerability, *, fingerprint: str) -> dict:
    payload = vulnerability_lifecycle_payload(vulnerability, fingerprint=fingerprint)
    redacted = Redactor.redact_scan_result(payload)
    return {
        key: value
        for key, value in redacted.items()
        if not (key in {"sent_request", "received_response"} and value is None)
    }


def _validate_vulnerability_status(status: str) -> str:
    validated_status = InputValidator.validate_string(
        status,
        "status",
        max_length=30,
        allow_empty=False,
    ).upper()
    if validated_status not in _ALLOWED_VULNERABILITY_STATUSES:
        allowed = ", ".join(sorted(_ALLOWED_VULNERABILITY_STATUSES))
        raise ValidationError(f"status: Must be one of {allowed}")
    return validated_status


def _closure_gate_blocked_exception(
    *,
    closure_gate: dict[str, Any],
    blockers: list[str] | None = None,
) -> HTTPException:
    combined_blockers = []
    for blocker in list(blockers or []) + list(closure_gate.get("blockers") or []):
        blocker_text = Redactor.redact_text(str(blocker))
        if blocker_text and blocker_text not in combined_blockers:
            combined_blockers.append(blocker_text)
    return HTTPException(
        status_code=400,
        detail={
            "reason": "closure_gate_blocked",
            "message": "Vulnerability closure requires verified evidence and a clean confirmatory retest.",
            "blockers": combined_blockers,
            "closure_gate": Redactor.redact_json(closure_gate),
        },
    )


def _enforce_closure_gate(
    vulnerability: Vulnerability,
    *,
    evidence: dict[str, Any] | None = None,
    blockers: list[str] | None = None,
) -> None:
    closure_gate = (
        evidence_closure_gate(evidence)
        if evidence is not None
        else vulnerability_closure_gate(vulnerability)
    )
    if blockers or closure_gate.get("ready_for_closure") is not True:
        raise _closure_gate_blocked_exception(
            closure_gate=closure_gate,
            blockers=blockers,
        )


def _validate_confirmation_status(status: str) -> str:
    validated_status = InputValidator.validate_string(
        status,
        "confirmation_status",
        max_length=30,
        allow_empty=False,
    ).upper()
    if validated_status not in _ALLOWED_CONFIRMATION_STATUSES:
        allowed = ", ".join(sorted(_ALLOWED_CONFIRMATION_STATUSES))
        raise ValidationError(f"confirmation_status: Must be one of {allowed}")
    return validated_status


def _validate_remediation_event_type(event_type: str) -> str:
    validated_event_type = InputValidator.validate_string(
        event_type,
        "event_type",
        max_length=50,
        allow_empty=False,
    ).upper()
    if validated_event_type not in _ALLOWED_REMEDIATION_EVENT_TYPES:
        allowed = ", ".join(sorted(_ALLOWED_REMEDIATION_EVENT_TYPES))
        raise ValidationError(f"event_type: Must be one of {allowed}")
    return validated_event_type


def _validate_remediation_event_source(source: str | None) -> str:
    return InputValidator.validate_string(
        source or "api",
        "source",
        max_length=80,
        allow_empty=False,
    )


def _validate_remediation_event_external_ref(external_ref: str | None) -> str | None:
    if external_ref is None:
        return None
    return InputValidator.validate_string(
        external_ref,
        "external_ref",
        max_length=1000,
        allow_empty=False,
    )


def _redact_external_ref(external_ref: str | None) -> str | None:
    if external_ref is None:
        return None
    value = str(external_ref)
    if value.lower().startswith(("http://", "https://")):
        return Redactor.redact_url(value)
    return Redactor.redact_text(value)


async def _load_owned_vulnerability(
    db: AsyncSession,
    *,
    account_id: int,
    vuln_id: str,
) -> Vulnerability:
    validated_vuln_id = InputValidator.validate_uuid(vuln_id, "vuln_id")
    result = await db.execute(
        select(Vulnerability).where(
            and_(Vulnerability.id == validated_vuln_id, Vulnerability.account_id == account_id)
        )
    )
    vulnerability = result.scalar_one_or_none()
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vulnerability


def _is_authorization_replay_vulnerability(vulnerability: Vulnerability) -> bool:
    evidence = vulnerability.evidence if isinstance(vulnerability.evidence, dict) else {}
    retest_support = evidence.get("retest_support") if isinstance(evidence, dict) else None
    matched_rule = evidence.get("matched_rule") if isinstance(evidence, dict) else None
    return any(
        [
            str(evidence.get("engine") or "") == _AUTHORIZATION_REPLAY_ENGINE,
            str(vulnerability.template_id or "") == _AUTHORIZATION_REPLAY_TEMPLATE_ID,
            isinstance(retest_support, dict)
            and str(retest_support.get("reason") or "") == "authorization_replay_matrix_available",
            isinstance(matched_rule, dict)
            and str(matched_rule.get("rule_id") or "").startswith("authorization_replay"),
        ]
    )


def _external_engine_of_vulnerability(vulnerability: Vulnerability) -> str | None:
    """Return the producing external engine for findings promoted by the scan worker.

    External-engine findings carry endpoint_id=None and an evidence.engine of
    schemathesis/nuclei/zap (LIFE-1). Authorization-replay findings take precedence:
    they are checked first in _prepare_vulnerability_retest_run.
    """
    evidence = vulnerability.evidence if isinstance(vulnerability.evidence, dict) else {}
    engine = str(evidence.get("engine") or "")
    if engine in _EXTERNAL_ENGINE_RETEST_ENGINES:
        return engine
    template_id = str(vulnerability.template_id or "")
    if template_id.startswith("zap-"):
        return "zap"
    if template_id.startswith("schemathesis-"):
        return "schemathesis"
    if template_id.startswith("NUCLEI:") or vulnerability.type == "NUCLEI:unknown":
        return "nuclei"
    return None


async def _endpoint_id_for_external_engine_retest(
    db: AsyncSession,
    *,
    account_id: int,
    vulnerability: Vulnerability,
) -> str:
    """Resolve the retest endpoint from the finding's evidence URL against inventory.

    Evidence URLs are credential-redacted but keep scheme/netloc/path, so they can be
    matched to the discovered endpoint that produced the finding. Resolution must be
    unambiguous: zero or several candidates is a client error, not a guess.
    """
    evidence = vulnerability.evidence if isinstance(vulnerability.evidence, dict) else {}
    candidates = [
        str(evidence.get("url") or ""),
        str((evidence.get("finding") or {}).get("url") or "") if isinstance(evidence.get("finding"), dict) else "",
        str(evidence.get("target") or ""),
    ]
    parsed_candidates = [urlsplit(url) for url in candidates if url]
    if not parsed_candidates:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "retest_external_engine_target_missing",
                "message": "External-engine finding has no resolvable target URL in evidence",
            },
        )

    endpoints = (
        await db.execute(
            select(APIEndpoint).where(
                and_(APIEndpoint.account_id == account_id, APIEndpoint.host.isnot(None))
            )
        )
    ).scalars().all()
    matches: list[APIEndpoint] = []
    for endpoint in endpoints:
        endpoint_parsed = urlsplit(endpoint_target_url(endpoint))
        for candidate in parsed_candidates:
            if (
                candidate.scheme == endpoint_parsed.scheme
                and candidate.netloc == endpoint_parsed.netloc
                and candidate.path.rstrip("/") == endpoint_parsed.path.rstrip("/")
            ):
                matches.append(endpoint)
                break
    unique_matches = {str(endpoint.id): endpoint for endpoint in matches}
    if not unique_matches:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "retest_external_engine_endpoint_not_found",
                "message": "No inventory endpoint matches the finding's evidence URL; re-import or discover the target first",
            },
        )
    if len(unique_matches) > 1:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "retest_external_engine_endpoint_ambiguous",
                "message": "Multiple inventory endpoints match the finding's evidence URL",
                "endpoint_ids": sorted(unique_matches),
            },
        )
    return next(iter(unique_matches))


async def _external_engine_retest_scan_plan(
    db: AsyncSession,
    *,
    vulnerability: Vulnerability,
    endpoint: APIEndpoint,
    engine: str,
    account_id: int,
    profile: PentestProfile | None,
) -> dict[str, Any]:
    """Build the queued engine-only scan plan for an external-engine retest.

    Mirrors _enqueue_engine_run: the requested engine is ready, sibling engines are
    blocked, the templates engine is disabled (the sentinel template id already keeps
    the templates phase off), and the external scope binds target + spec hash so the
    worker's integrity checks hold.
    """
    target_url = endpoint_target_url(endpoint)
    evidence = vulnerability.evidence if isinstance(vulnerability.evidence, dict) else {}
    spec_id = evidence.get("openapi_spec_id") if isinstance(evidence, dict) else None
    spec_record: OpenAPISpec | None = None
    if isinstance(spec_id, str) and spec_id:
        spec_record = (
            await db.execute(
                select(OpenAPISpec).where(
                    OpenAPISpec.id == spec_id,
                    OpenAPISpec.account_id == account_id,
                )
            )
        ).scalar_one_or_none()
    external_engine_scope: dict[str, Any] = {"target_url": target_url}
    if spec_record is not None:
        from server.modules.test_executor.scan_worker import worker_spec_digest

        external_engine_scope["openapi_spec_id"] = str(spec_record.id)
        external_engine_scope["openapi_spec_sha256"] = worker_spec_digest(spec_record.spec_json)
    plan_engine_entries: dict[str, dict[str, Any]] = {}
    for engine_name in ("schemathesis", "nuclei", "zap"):
        armed_ok = engine_name != "nuclei" or (
            bool(getattr(profile, "allow_state_change", False))
            and bool(getattr(profile, "allow_destructive_methods", False))
        )
        if engine_name == engine:
            plan_engine_entries[engine_name] = {
                "engine": engine_name,
                "display_name": engine_name.capitalize(),
                "enabled": True,
                "status": "ready" if armed_ok else "blocked",
                "reason": (
                    "retest_external_engine"
                    if armed_ok
                    else "worker_nuclei_requires_explicit_method_arming"
                ),
                "requires_auth_profile": True,
                "requires_test_accounts": False,
                "artifact_type": f"{engine_name}_execution",
                "runtime_available": True,
            }
        else:
            plan_engine_entries[engine_name] = {
                "engine": engine_name,
                "display_name": engine_name.capitalize(),
                "enabled": True,
                "status": "blocked",
                "reason": "external_engine_scope_required",
                "requires_auth_profile": True,
                "requires_test_accounts": False,
                "artifact_type": f"{engine_name}_execution",
                "runtime_available": True,
            }
    scan_plan: dict[str, Any] = {
        "schema_version": "scan_plan.v1",
        "test_intensity": "safe",
        "selection_mode": "external_engine_retest",
        "selected_tests": [
            {
                "engine": engine,
                "endpoint_id": str(endpoint.id),
                "reason": "retest_external_engine",
                "source_vulnerability_type": Redactor.redact_text(str(vulnerability.type or "")),
            }
        ],
        "targets": [tests_router._endpoint_scan_plan_context(endpoint, account_id=account_id)],
        "engine_plan": [
            plan_engine_entries["schemathesis"],
            plan_engine_entries["nuclei"],
            plan_engine_entries["zap"],
        ],
        "external_engine_scope": external_engine_scope,
    }
    return finalize_scan_plan_hash(Redactor.redact_scan_result(scan_plan))


def _authorization_replay_retest_scan_plan(
    *,
    vulnerability: Vulnerability,
    endpoint: APIEndpoint,
    account_id: int,
    roles_context: dict | None,
    test_intensity: str,
) -> dict[str, Any]:
    endpoint_context = tests_router._endpoint_scan_plan_context(endpoint, account_id=account_id)
    evidence = vulnerability.evidence if isinstance(vulnerability.evidence, dict) else {}
    scan_plan = {
        "schema_version": "scan_plan.v1",
        "test_intensity": test_intensity,
        "selection_mode": "authorization_replay_retest",
        "selected_tests": [
            {
                "template_id": _AUTHORIZATION_REPLAY_TEMPLATE_ID,
                "engine": _AUTHORIZATION_REPLAY_ENGINE,
                "endpoint_id": endpoint.id,
                "reason": "retest_authorization_replay_matrix",
                "original_template_id": Redactor.redact_text(str(vulnerability.template_id or "")),
            }
        ],
        "targets": [endpoint_context],
        "roles_context": Redactor.redact_json(roles_context or {}),
        "engine_plan": [
            {
                "engine": _AUTHORIZATION_REPLAY_ENGINE,
                "display_name": "Authorization Replay Matrix",
                "enabled": True,
                "status": "ready",
                "reason": "authorization_replay_matrix_available",
                "requires_auth_profile": False,
                "requires_test_accounts": True,
                "artifact_type": "authorization_replay_execution",
                "runtime_available": True,
            }
        ],
        _AUTHORIZATION_REPLAY_ENGINE: {
            "require_response_similarity": True,
            "body_similarity_threshold": 70.0,
            "schema_similarity_threshold": 70.0,
            "source_finding_engine": Redactor.redact_text(str(evidence.get("engine") or "")),
            "source_issue_type": Redactor.redact_text(str(evidence.get("issue_type") or vulnerability.type or "")),
        },
    }
    return tests_router.finalize_scan_plan_hash(Redactor.redact_scan_result(scan_plan))


async def _prepare_vulnerability_retest_run(
    *,
    db: AsyncSession,
    account_id: int,
    vulnerability: Vulnerability,
    request: Request,
    user_id: str | None,
    pentest_profile_id: str | None,
    trigger_source: str,
) -> tuple[dict, list[str], list[str], str | None]:
    retest_engine = _external_engine_of_vulnerability(vulnerability)
    external_engine_retest = retest_engine is not None
    if not external_engine_retest and (not vulnerability.template_id or not vulnerability.endpoint_id):
        raise ValidationError("retest: Vulnerability must have both template_id and endpoint_id")
    authorization_replay_retest = _is_authorization_replay_vulnerability(vulnerability)
    if authorization_replay_retest:
        template_id = InputValidator.validate_string(
            _AUTHORIZATION_REPLAY_TEMPLATE_ID,
            "template_id",
            max_length=256,
            allow_empty=False,
        )
    elif external_engine_retest:
        template_id = InputValidator.validate_string(
            _EXTERNAL_ENGINE_RETEST_TEMPLATE_ID,
            "template_id",
            max_length=256,
            allow_empty=False,
        )
    else:
        template_id = InputValidator.validate_string(
            vulnerability.template_id,
            "template_id",
            max_length=256,
            allow_empty=False,
        )
    if external_engine_retest:
        # External-engine findings carry endpoint_id=None; the retest target is
        # resolved from the evidence URL against this account's inventory.
        endpoint_id = await _endpoint_id_for_external_engine_retest(
            db, account_id=account_id, vulnerability=vulnerability,
        )
    else:
        endpoint_id = InputValidator.validate_uuid(vulnerability.endpoint_id, "endpoint_id")

    if tests_router.kill_switch_enabled():
        raise HTTPException(status_code=503, detail=tests_router.KILL_SWITCH_REASON)

    template_ids = [template_id]
    endpoint_ids = [endpoint_id]
    tests_router._validate_scan_budget(template_ids, endpoint_ids)

    endpoint = (
        await db.execute(
            select(APIEndpoint).where(
                and_(APIEndpoint.id == endpoint_id, APIEndpoint.account_id == account_id)
            )
        )
    ).scalar_one_or_none()
    if endpoint is None:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "retest_endpoint_not_found",
                "message": "Vulnerability endpoint is no longer available for this account",
            },
        )

    endpoints = [endpoint]
    tests_router._validate_scan_endpoint_targets(endpoints)
    if authorization_replay_retest:
        pentest_profile = None
        auth_profile = None
        effective_pentest_profile_id = None
        execution_mode = "queued"
        effective_test_intensity = "safe"
    elif external_engine_retest:
        # LIFE-1: external-engine retests run the producing engine on an isolated
        # worker against the finding's original target. The worker performs the
        # auth preflight; templates phase is skipped via the sentinel template id.
        pentest_profile, auth_profile = await tests_router._load_scan_profile_for_execution(
            db,
            account_id=account_id,
            pentest_profile_id=pentest_profile_id,
        )
        effective_pentest_profile_id = pentest_profile.id if pentest_profile is not None else None
        execution_mode = "queued"
        effective_test_intensity = "safe"
    else:
        pentest_profile, auth_profile = await tests_router._load_scan_profile_for_execution(
            db,
            account_id=account_id,
            pentest_profile_id=pentest_profile_id,
        )
        tests_router._validate_scan_auth_scope(endpoints, auth_profile)
        effective_pentest_profile_id = pentest_profile.id if pentest_profile is not None else pentest_profile_id
        execution_mode = tests_router._scan_execution_mode()
        effective_test_intensity = tests_router.normalize_test_intensity(None, profile=pentest_profile)
    test_accounts_result = await db.execute(
        select(tests_router.TestAccount).where(tests_router.TestAccount.account_id == account_id)
    )
    roles_context = tests_router.RolesContextBuilder().build(test_accounts_result.scalars().all())
    has_openapi_spec = await tests_router._account_has_openapi_spec(db, account_id=account_id)
    if authorization_replay_retest:
        scan_plan = _authorization_replay_retest_scan_plan(
            vulnerability=vulnerability,
            endpoint=endpoint,
            account_id=account_id,
            roles_context=roles_context,
            test_intensity=effective_test_intensity,
        )
    elif external_engine_retest:
        scan_plan = await _external_engine_retest_scan_plan(
            db,
            vulnerability=vulnerability,
            endpoint=endpoint,
            engine=retest_engine or "",
            account_id=account_id,
            profile=pentest_profile,
        )
    else:
        scan_plan = tests_router._build_scan_plan_for_run(
            templates=tests_router.WordlistManager.get_instance().templates,
            template_ids=template_ids,
            endpoints=endpoints,
            account_id=account_id,
            test_intensity=effective_test_intensity,
            profile=pentest_profile,
            roles_context=roles_context,
            auth_profile=auth_profile,
            has_openapi_spec=has_openapi_spec,
            engine_runtime_availability=tests_router._scan_engine_runtime_availability(),
        )

    run_id = str(uuid.uuid4())
    run = TestRun(
        id=run_id,
        account_id=account_id,
        status="PENDING",
        template_ids=template_ids,
        endpoint_ids=endpoint_ids,
        pentest_profile_id=effective_pentest_profile_id,
        trigger_source=trigger_source,
        source_vulnerability_id=vulnerability.id,
        test_intensity=effective_test_intensity,
        scan_plan=scan_plan,
    )
    db.add(run)
    scan_details = {
        "source": trigger_source,
        "vulnerability_id": vulnerability.id,
        "template_count": 1,
        "endpoint_count": 1,
        "planned_tests": 1,
        "pentest_profile_id": effective_pentest_profile_id,
        **active_scan_auth_audit_context(pentest_profile, auth_profile),
        "trigger_source": run.trigger_source,
        "source_vulnerability_id": run.source_vulnerability_id,
        "execution_mode": execution_mode,
        "test_intensity": effective_test_intensity,
        "scan_plan": tests_router._scan_plan_audit_summary(scan_plan),
    }
    await tests_router._audit_scan_event(
        db,
        action="SCAN_RUN_QUEUED",
        account_id=account_id,
        run_id=run_id,
        user_id=user_id,
        details=scan_details,
        ip_address=tests_router._request_ip(request),
    )
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_RETEST_QUEUED",
        user_id=user_id,
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details={
            "run_id": run_id,
            "template_id": template_id,
            "original_template_id": vulnerability.template_id if authorization_replay_retest else None,
            "endpoint_id": endpoint_id,
            "pentest_profile_id": effective_pentest_profile_id,
            **active_scan_auth_audit_context(pentest_profile, auth_profile),
            "trigger_source": run.trigger_source,
            "source_vulnerability_id": run.source_vulnerability_id,
            "execution_mode": execution_mode,
            "test_intensity": effective_test_intensity,
            "scan_plan": tests_router._scan_plan_audit_summary(scan_plan),
        },
        ip_address=tests_router._request_ip(request),
    )

    return (
        {
            "status": "scan_started" if execution_mode == "background" else "scan_queued",
            "run_id": run_id,
            "vulnerability_id": vulnerability.id,
            "template_id": template_id,
            "original_template_id": vulnerability.template_id if authorization_replay_retest else None,
            "endpoint_id": endpoint_id,
            "pentest_profile_id": effective_pentest_profile_id,
            "execution_mode": execution_mode,
            "trigger_source": run.trigger_source,
            "source_vulnerability_id": run.source_vulnerability_id,
            "test_intensity": effective_test_intensity,
            "scan_plan": scan_plan,
        },
        template_ids,
        endpoint_ids,
        effective_pentest_profile_id,
    )


async def _find_active_vulnerability_retest(
    db: AsyncSession,
    *,
    account_id: int,
    vulnerability_id: str,
) -> TestRun | None:
    result = await db.execute(
        select(TestRun)
        .where(
            and_(
                TestRun.account_id == account_id,
                TestRun.source_vulnerability_id == vulnerability_id,
                TestRun.trigger_source.in_(sorted(_RETEST_TRIGGER_SOURCES)),
                TestRun.status.in_(sorted(_ACTIVE_RETEST_STATUSES)),
            )
        )
        .order_by(TestRun.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


def _existing_retest_payload(run: TestRun) -> dict:
    template_ids = list(run.template_ids or [])
    endpoint_ids = list(run.endpoint_ids or [])
    return {
        "status": "scan_already_queued",
        "run_id": run.id,
        "run_status": run.status,
        "vulnerability_id": run.source_vulnerability_id,
        "template_id": template_ids[0] if template_ids else None,
        "endpoint_id": endpoint_ids[0] if endpoint_ids else None,
        "pentest_profile_id": run.pentest_profile_id,
        "execution_mode": "queued",
        "trigger_source": run.trigger_source,
        "source_vulnerability_id": run.source_vulnerability_id,
    }


async def _record_retest_deduped(
    *,
    db: AsyncSession,
    account_id: int,
    vulnerability: Vulnerability,
    request: Request,
    user_id: str | None,
    existing_run: TestRun,
    trigger_source: str,
) -> dict:
    payload = _existing_retest_payload(existing_run)
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_RETEST_DEDUPED",
        user_id=user_id,
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details={
            "reason": "active_retest_exists",
            "existing_run_id": existing_run.id,
            "existing_run_status": existing_run.status,
            "trigger_source": trigger_source,
            "existing_trigger_source": existing_run.trigger_source,
            "source_vulnerability_id": vulnerability.id,
        },
        ip_address=tests_router._request_ip(request),
    )
    return payload


async def _record_auto_retest_skipped(
    *,
    db: AsyncSession,
    account_id: int,
    vulnerability: Vulnerability,
    request: Request,
    user_id: str | None,
    reason: str,
    trigger_source: str = _AUTO_RETEST_TRIGGER,
    include_retest_support: bool = False,
) -> dict:
    payload = {
        "status": "not_queued",
        "reason": reason,
        "vulnerability_id": vulnerability.id,
        "trigger_source": trigger_source,
        "source_vulnerability_id": vulnerability.id,
    }
    if include_retest_support:
        payload["retest_support"] = vulnerability_retest_support(vulnerability)
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_RETEST_SKIPPED",
        user_id=user_id,
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details=payload,
        ip_address=tests_router._request_ip(request),
    )
    return payload


def _retest_skip_reason(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return "retest_not_reconstructable"
    if isinstance(exc, HTTPException):
        detail = exc.detail
        if exc.status_code == 503:
            return "kill_switch_enabled"
        if isinstance(detail, dict):
            reason = detail.get("reason")
            if isinstance(reason, str) and reason:
                return reason
            message = str(detail.get("message") or "")
        else:
            message = str(detail or "")
        if "auth profile scope" in message.lower():
            return "auth_profile_scope_blocked"
        if "target guard" in message.lower():
            return "target_guard_blocked"
        if "profile" in message.lower():
            return "pentest_profile_unavailable"
    return "retest_not_queued"


def _suppressed_auto_retest_reason(vulnerability: Vulnerability) -> str | None:
    if bool(vulnerability.false_positive):
        return "false_positive"
    if str(vulnerability.status or "").upper() == "ACCEPTED_RISK":
        return "accepted_risk"
    return None


def _schedule_retest_background_task(
    *,
    background_tasks: BackgroundTasks,
    db: AsyncSession,
    retest: dict,
    template_ids: list[str],
    endpoint_ids: list[str],
    account_id: int,
    pentest_profile_id: str | None,
) -> None:
    if retest["execution_mode"] != "background":
        return
    background_tasks.add_task(
        tests_router._run_security_tasks,
        retest["run_id"],
        template_ids,
        endpoint_ids,
        account_id,
        pentest_profile_id,
        db.bind,
    )


@router.get("/summary/by-severity")
@limiter.limit("30/minute")
async def summary_by_severity(
    request: Request,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db)
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.account_id == account_id, Vulnerability.status == "OPEN")
        .group_by(Vulnerability.severity)
    )
    return {"summary": [{"severity": row[0], "count": row[1]} for row in result.all()]}


@router.get("/summary/by-type")
async def summary_by_type(
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db)
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(Vulnerability.type, func.count(Vulnerability.id))
        .where(Vulnerability.account_id == account_id, Vulnerability.status == "OPEN")
        .group_by(Vulnerability.type)
    )
    return {"summary": [{"type": row[0], "count": row[1]} for row in result.all()]}


@router.get("/summary")
@limiter.limit("30/minute")
async def get_vulnerability_summary(
    request: Request,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db),
):
    """
    Return pre-aggregated vulnerability counts by severity and status.
    Used by the dashboard to avoid fetching 1000 records client-side.
    """
    account_id = payload.get("account_id")
    # Severity breakdown for OPEN vulnerabilities
    sev_result = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .where(and_(Vulnerability.account_id == account_id, Vulnerability.status == "OPEN"))
        .group_by(Vulnerability.severity)
    )
    severity_breakdown: dict[str, int] = {}
    for sev, count in sev_result.all():
        severity_breakdown[str(sev or "UNKNOWN").upper()] = int(count or 0)

    # Status breakdown
    status_result = await db.execute(
        select(Vulnerability.status, func.count(Vulnerability.id))
        .where(Vulnerability.account_id == account_id)
        .group_by(Vulnerability.status)
    )
    status_breakdown: dict[str, int] = {}
    for status, count in status_result.all():
        status_breakdown[str(status or "UNKNOWN").upper()] = int(count or 0)

    total = sum(status_breakdown.values())
    open_count = status_breakdown.get("OPEN", 0)
    fixed_count = status_breakdown.get("CLOSED", 0) + status_breakdown.get("RESOLVED", 0)

    return {
        "totalIssues": total,
        "openIssues": open_count,
        "fixedIssues": fixed_count,
        "severityBreakdown": {
            "CRITICAL": severity_breakdown.get("CRITICAL", 0),
            "HIGH": severity_breakdown.get("HIGH", 0),
            "MEDIUM": severity_breakdown.get("MEDIUM", 0),
            "LOW": severity_breakdown.get("LOW", 0),
        },
        "statusBreakdown": status_breakdown,
    }


@router.get("/")
@limiter.limit("60/minute")
async def get_vulnerabilities(
    request: Request,
    severity: str = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    type: str = Query(None, description="BOLA | BFLA | NO_AUTH | INJECT | ..."),
    status: str = Query(None, description="OPEN | CLOSED | ACCEPTED_RISK"),
    false_positive: bool = Query(None),
    confirmed: bool = Query(None, description="true for confirmed findings, false for non-confirmed findings"),
    confirmation_status: str = Query(None, description="CONFIRMED | DISPROVEN | UNCONFIRMED"),
    limit: int = Query(100),
    offset: int = Query(0),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db),
):
    try:
        # Validate numeric parameters
        validated_limit = InputValidator.validate_integer(limit, "limit", min_value=1, max_value=10000)
        validated_offset = InputValidator.validate_integer(offset, "offset", min_value=0, max_value=1000000)

        # Validate string parameters (allowed values: CRITICAL, HIGH, MEDIUM, LOW for severity)
        validated_severity = None
        if severity:
            validated_severity = InputValidator.validate_string(
                severity, "severity", max_length=20, allow_empty=False
            ).upper()
            if validated_severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                raise ValidationError("severity: Must be one of CRITICAL, HIGH, MEDIUM, LOW")

        # Validate type parameter
        validated_type = None
        if type:
            validated_type = InputValidator.validate_string(
                type, "type", max_length=50, allow_empty=False
            ).upper()

        # Validate status parameter.
        validated_status = None
        if status:
            validated_status = _validate_vulnerability_status(status)
        validated_confirmation_status = None
        if confirmation_status:
            validated_confirmation_status = _validate_confirmation_status(confirmation_status)
        if confirmed is not None and validated_confirmation_status is not None:
            if confirmed and validated_confirmation_status != "CONFIRMED":
                raise ValidationError("confirmed=true conflicts with confirmation_status")
            if not confirmed and validated_confirmation_status == "CONFIRMED":
                raise ValidationError("confirmed=false conflicts with confirmation_status=CONFIRMED")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload.get("account_id")
    filters = [Vulnerability.account_id == account_id]
    if validated_severity:
        filters.append(Vulnerability.severity == validated_severity)
    if validated_type:
        filters.append(Vulnerability.type == validated_type)
    if validated_status:
        filters.append(Vulnerability.status == validated_status)
    if false_positive is not None:
        filters.append(Vulnerability.false_positive == false_positive)

    base_stmt = (
        select(Vulnerability)
        .where(and_(*filters))
        .order_by(Vulnerability.created_at.desc())
    )
    needs_confirmation_filter = confirmed is not None or validated_confirmation_status is not None
    if needs_confirmation_filter:
        result = await db.execute(base_stmt)
        filtered_vulns = result.scalars().all()
        if validated_confirmation_status is not None:
            filtered_vulns = [
                vulnerability
                for vulnerability in filtered_vulns
                if confirmation_status_from_evidence(vulnerability.evidence) == validated_confirmation_status
            ]
        if confirmed is not None:
            filtered_vulns = [
                vulnerability
                for vulnerability in filtered_vulns
                if (confirmation_result_from_evidence(vulnerability.evidence) is True) == confirmed
            ]
        vulns = filtered_vulns[validated_offset : validated_offset + validated_limit]
    else:
        result = await db.execute(base_stmt.limit(validated_limit).offset(validated_offset))
        vulns = result.scalars().all()
    return {
        "total": len(vulns), "offset": offset,
        "vulnerabilities": [_serialize_vulnerability(v) for v in vulns],
    }


@router.get("/trend")
async def vulnerability_trend(
    start_ts: int = Query(None),
    end_ts: int = Query(None),
    severity: str = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW — filter trend to one severity"),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db)
):
    """Returns daily vulnerability counts for the testing trend chart."""
    account_id = payload.get("account_id")
    stmt = select(Vulnerability).where(Vulnerability.account_id == account_id)
    if start_ts:
        dt = datetime.datetime.fromtimestamp(start_ts / 1000)
        stmt = stmt.where(Vulnerability.created_at >= dt)
    if end_ts:
        dt = datetime.datetime.fromtimestamp(end_ts / 1000)
        stmt = stmt.where(Vulnerability.created_at <= dt)
    if severity:
        validated_sev = severity.upper()
        if validated_sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            raise HTTPException(status_code=400, detail="severity must be one of CRITICAL, HIGH, MEDIUM, LOW")
        stmt = stmt.where(Vulnerability.severity == validated_sev)

    result = await db.execute(stmt)
    vulns = result.scalars().all()

    buckets = {}
    for v in vulns:
        day_ts = int(datetime.datetime(v.created_at.year, v.created_at.month, v.created_at.day).timestamp() * 1000)
        buckets[day_ts] = buckets.get(day_ts, 0) + 1

    trend = [{"ts": ts, "count": count} for ts, count in buckets.items()]
    trend.sort(key=lambda x: x["ts"])
    return {"issuesTrend": trend}


@router.get("/{vuln_id}")
async def get_vulnerability(
    vuln_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db)
):
    account_id = payload.get("account_id")
    try:
        v = await _load_owned_vulnerability(db, account_id=account_id, vuln_id=vuln_id)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _serialize_vulnerability(v)


@router.get("/{vuln_id}/evidence/verify")
async def verify_vulnerability_evidence_hashes(
    vuln_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    try:
        vulnerability = await _load_owned_vulnerability(db, account_id=account_id, vuln_id=vuln_id)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {
        "vulnerability_id": vulnerability.id,
        "fingerprint": vulnerability.fingerprint or vulnerability_fingerprint(vulnerability),
        "evidence_integrity": verify_vulnerability_evidence(vulnerability.evidence),
    }


def _ticket_status_to_vulnerability_status(
    external_status: str,
    current_status: str | None,
) -> tuple[str, str]:
    normalized = str(external_status or "").strip().upper().replace("-", "_")
    current = (current_status or "OPEN").upper()
    if normalized in _TICKET_RESOLVED_STATUSES:
        if current == "CLOSED":
            return "CLOSED", "ticket_resolved_already_closed"
        return "IN_REMEDIATION", "ticket_resolved_requires_confirmatory_retest"
    if normalized in _TICKET_IN_PROGRESS_STATUSES:
        return "IN_REMEDIATION", "ticket_in_progress"
    if normalized in _TICKET_OPEN_STATUSES:
        return "OPEN", "ticket_open"
    return current, "ticket_status_unmapped"


def _append_ticket_sync_evidence(
    vulnerability: Vulnerability,
    sync_event: dict[str, Any],
) -> None:
    evidence = dict(vulnerability.evidence) if isinstance(vulnerability.evidence, dict) else {}
    previous_syncs = evidence.get("ticket_syncs")
    if not isinstance(previous_syncs, list):
        previous_syncs = []
    evidence["ticket_syncs"] = (previous_syncs + [sync_event])[-10:]
    evidence["latest_ticket_sync"] = sync_event
    vulnerability.evidence = evidence


def _retest_decision_evidence(retest: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(retest, dict):
        return None
    payload: dict[str, Any] = {}
    for key in ("status", "run_id", "reason", "trigger_source"):
        value = retest.get(key)
        if value is None:
            continue
        payload[key] = Redactor.redact_text(str(value))
    return payload or None


def _append_remediation_event_evidence(
    vulnerability: Vulnerability,
    event: dict[str, Any],
) -> None:
    evidence = dict(vulnerability.evidence) if isinstance(vulnerability.evidence, dict) else {}
    previous_events = evidence.get("remediation_events")
    if not isinstance(previous_events, list):
        previous_events = []
    clean_event = {key: value for key, value in event.items() if value is not None}
    evidence["remediation_events"] = (previous_events + [clean_event])[-10:]
    evidence["latest_remediation_event"] = clean_event
    vulnerability.evidence = evidence


def _validate_retest_outcome(outcome: str) -> str:
    """Normalize an operator-supplied outcome into the stored vocabulary (decision B).

    The API accepts synonyms and folds them into the canonical set; the run path
    may additionally write FAILED / CANCELED / NO_EXECUTION when a retest run
    could not execute the finding's checks (see REMEDIATION_RETEST_OUTCOMES).
    """
    validated = InputValidator.validate_string(
        outcome,
        "outcome",
        max_length=40,
        allow_empty=False,
    ).upper()
    normalized = validated.replace("-", "_")
    if normalized in {"CLEAN", "FIXED", "PASSED"}:
        return "CLEAN"
    if normalized in {"STILL_VULNERABLE", "VULNERABLE"}:
        return "STILL_VULNERABLE"
    if normalized in NON_EXECUTED_RETEST_OUTCOMES:
        return normalized
    raise ValidationError("outcome: Must be clean, still_vulnerable, failed, canceled, or no_execution")


@router.post("/{vuln_id}/retest/outcome")
async def record_vulnerability_retest_outcome(
    vuln_id: str,
    outcome: str = Body(..., embed=True),
    run_id: str | None = Body(default=None, embed=True),
    executed: int = Body(default=0, embed=True),
    vulnerable: int = Body(default=0, embed=True),
    errors: int = Body(default=0, embed=True),
    skipped: int = Body(default=0, embed=True),
    reason: str | None = Body(default=None, embed=True),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    try:
        vulnerability = await _load_owned_vulnerability(db, account_id=account_id, vuln_id=vuln_id)
        validated_outcome = _validate_retest_outcome(outcome)
        validated_run_id = (
            InputValidator.validate_string(run_id, "run_id", max_length=100, allow_empty=False)
            if run_id
            else str(uuid.uuid4())
        )
        validated_reason = (
            InputValidator.validate_string(reason, "reason", max_length=1000, allow_empty=False)
            if reason
            else None
        )
        validated_counts = {
            "executed": InputValidator.validate_integer(executed, "executed", min_value=0),
            "vulnerable": InputValidator.validate_integer(vulnerable, "vulnerable", min_value=0),
            "errors": InputValidator.validate_integer(errors, "errors", min_value=0),
            "skipped": InputValidator.validate_integer(skipped, "skipped", min_value=0),
        }
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    previous_status = vulnerability.status
    now = utc_now()
    retest = {
        "run_id": Redactor.redact_text(validated_run_id),
        "status": "COMPLETED",
        "outcome": validated_outcome,
        "completed_at": isoformat(now),
        **validated_counts,
    }
    if validated_reason:
        retest["reason"] = Redactor.redact_text(validated_reason)
    retest["hash_algorithm"] = "sha256"
    retest["retest_hash"] = retest_outcome_digest(retest)

    evidence = dict(vulnerability.evidence) if isinstance(vulnerability.evidence, dict) else {}
    retests = evidence.get("remediation_retests")
    if not isinstance(retests, list):
        retests = []
    evidence["remediation_retests"] = (retests + [retest])[-10:]
    evidence["latest_remediation_retest"] = retest
    if validated_outcome == "CLEAN":
        closure_blockers: list[str] = []
        if retest["executed"] <= 0:
            closure_blockers.append("executed")
        if retest["errors"] > 0:
            closure_blockers.append("errors")
        if retest["vulnerable"] > 0:
            closure_blockers.append("vulnerable")
        _enforce_closure_gate(
            vulnerability,
            evidence=evidence,
            blockers=closure_blockers,
        )
    vulnerability.last_seen_at = now
    if validated_outcome == "STILL_VULNERABLE":
        vulnerability.occurrence_count = int(vulnerability.occurrence_count or 1) + 1
        evidence = evidence_with_lifecycle(
            evidence,
            fingerprint=vulnerability.fingerprint or vulnerability_fingerprint(vulnerability),
            first_seen_at=vulnerability.first_seen_at or vulnerability.created_at,
            last_seen_at=now,
            occurrence_count=int(vulnerability.occurrence_count or 1),
            sla_due_at=vulnerability.sla_due_at,
        )
        vulnerability.status = "OPEN"
    elif validated_outcome == "CLEAN":
        vulnerability.status = "CLOSED"
    # else: FAILED / CANCELED / NO_EXECUTION — the retest never executed the
    # finding's checks, so the finding status must stay unchanged (decision B).
    vulnerability.evidence = evidence

    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_RETEST_COMPLETED",
        user_id=payload.get("user_id"),
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details={
            "run_id": retest["run_id"],
            "outcome": validated_outcome,
            "previous_status": previous_status,
            "new_status": vulnerability.status,
            "executed": retest["executed"],
            "vulnerable": retest["vulnerable"],
            "errors": retest["errors"],
            "skipped": retest["skipped"],
            "hash_algorithm": retest["hash_algorithm"],
            "retest_hash": retest["retest_hash"],
            "retest_integrity": latest_remediation_retest_integrity(evidence),
        },
    )
    await db.commit()
    await db.refresh(vulnerability)
    return {
        "status": "success",
        "retest": {
            **retest,
            "retest_integrity": latest_remediation_retest_integrity(vulnerability.evidence),
        },
        "vulnerability": _serialize_vulnerability(vulnerability),
    }


@router.post("/{vuln_id}/ticket")
async def link_vulnerability_ticket(
    vuln_id: str,
    ticket_url: str = Body(..., embed=True),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    try:
        validated_vuln_id = InputValidator.validate_uuid(vuln_id, "vuln_id")
        validated_ticket_url = InputValidator.validate_string(
            ticket_url,
            "ticket_url",
            max_length=2000,
            allow_empty=False,
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        validated_ticket_url = validate_ticket_url(validated_ticket_url)
    except TicketUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result = await db.execute(
        select(Vulnerability).where(
            and_(Vulnerability.id == validated_vuln_id, Vulnerability.account_id == account_id)
        )
    )
    vulnerability = result.scalar_one_or_none()
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vulnerability.ticket_url = validated_ticket_url
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_TICKET_LINKED",
        user_id=payload.get("user_id"),
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details={"ticket_url": Redactor.redact_url(validated_ticket_url)},
    )
    await db.commit()
    await db.refresh(vulnerability)
    return {"status": "success", "vulnerability": _serialize_vulnerability(vulnerability)}


@router.post("/{vuln_id}/ticket/sync")
async def sync_vulnerability_ticket(
    vuln_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    ticket_url: str | None = Body(default=None, embed=True),
    external_key: str | None = Body(default=None, embed=True),
    external_status: str = Body(..., embed=True),
    source: str = Body(default="manual", embed=True),
    pentest_profile_id: str | None = Body(default=None, embed=True),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    try:
        validated_vuln_id = InputValidator.validate_uuid(vuln_id, "vuln_id")
        validated_external_status = InputValidator.validate_string(
            external_status,
            "external_status",
            max_length=80,
            allow_empty=False,
        )
        validated_source = InputValidator.validate_string(
            source,
            "source",
            max_length=50,
            allow_empty=False,
        )
        validated_external_key = (
            InputValidator.validate_string(
                external_key,
                "external_key",
                max_length=100,
                allow_empty=False,
            )
            if external_key
            else None
        )
        validated_ticket_url = None
        if ticket_url:
            validated_ticket_url = InputValidator.validate_string(
                ticket_url,
                "ticket_url",
                max_length=2000,
                allow_empty=False,
            )
            validated_ticket_url = validate_ticket_url(validated_ticket_url)
    except TicketUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    vulnerability = (
        await db.execute(
            select(Vulnerability).where(
                and_(Vulnerability.id == validated_vuln_id, Vulnerability.account_id == account_id)
            )
        )
    ).scalar_one_or_none()
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    previous_status = vulnerability.status
    new_status, reason = _ticket_status_to_vulnerability_status(
        validated_external_status,
        previous_status,
    )
    if validated_ticket_url:
        vulnerability.ticket_url = validated_ticket_url
    safe_ticket_url = Redactor.redact_url(validated_ticket_url or vulnerability.ticket_url or "")
    synced_at = utc_now()
    sync_event = {
        "synced_at": isoformat(synced_at),
        "source": Redactor.redact_text(validated_source),
        "external_key": Redactor.redact_text(validated_external_key) if validated_external_key else None,
        "external_status": Redactor.redact_text(validated_external_status),
        "ticket_url": safe_ticket_url or None,
        "previous_status": previous_status,
        "new_status": new_status,
        "reason": reason,
    }
    sync_event = {key: value for key, value in sync_event.items() if value is not None}
    vulnerability.status = new_status
    sla_snapshot = vulnerability_sla_status(vulnerability, now=synced_at)
    sync_event["sla"] = sla_snapshot
    sync_event["sla_escalation"] = vulnerability_sla_escalation(vulnerability, sla=sla_snapshot)

    retest = None
    retest_template_ids: list[str] = []
    retest_endpoint_ids: list[str] = []
    retest_pentest_profile_id: str | None = None
    if reason == "ticket_resolved_requires_confirmatory_retest":
        existing_retest = await _find_active_vulnerability_retest(
            db,
            account_id=account_id,
            vulnerability_id=vulnerability.id,
        )
        if existing_retest is not None:
            retest = await _record_retest_deduped(
                db=db,
                account_id=account_id,
                vulnerability=vulnerability,
                request=request,
                user_id=payload.get("user_id"),
                existing_run=existing_retest,
                trigger_source=_TICKET_SYNC_RETEST_TRIGGER,
            )
        else:
            try:
                (
                    retest,
                    retest_template_ids,
                    retest_endpoint_ids,
                    retest_pentest_profile_id,
                ) = await _prepare_vulnerability_retest_run(
                    db=db,
                    account_id=account_id,
                    vulnerability=vulnerability,
                    request=request,
                    user_id=payload.get("user_id"),
                    pentest_profile_id=pentest_profile_id,
                    trigger_source=_TICKET_SYNC_RETEST_TRIGGER,
                )
            except (ValidationError, HTTPException) as exc:
                retest = await _record_auto_retest_skipped(
                    db=db,
                    account_id=account_id,
                    vulnerability=vulnerability,
                    request=request,
                    user_id=payload.get("user_id"),
                    reason=_retest_skip_reason(exc),
                    trigger_source=_TICKET_SYNC_RETEST_TRIGGER,
                )
    retest_decision = _retest_decision_evidence(retest)
    if retest_decision:
        sync_event["retest_decision"] = retest_decision
    sync_event["closure_gate"] = vulnerability_closure_gate(vulnerability)
    _append_ticket_sync_evidence(vulnerability, sync_event)
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_TICKET_SYNCED",
        user_id=payload.get("user_id"),
        resource_type="vulnerability",
            resource_id=vulnerability.id,
            details=sync_event,
    )
    await db.commit()
    if retest is not None and retest.get("status") != "not_queued":
        _schedule_retest_background_task(
            background_tasks=background_tasks,
            db=db,
            retest=retest,
            template_ids=retest_template_ids,
            endpoint_ids=retest_endpoint_ids,
            account_id=account_id,
            pentest_profile_id=retest_pentest_profile_id,
        )
    await db.refresh(vulnerability)
    response = {
        "status": "synced",
        "sync": sync_event,
        "vulnerability": _serialize_vulnerability(vulnerability),
    }
    if retest is not None:
        response["retest"] = retest
    return response


@router.post("/{vuln_id}/ticket/create")
async def create_vulnerability_ticket(
    vuln_id: str,
    integration_id: str | None = Body(default=None),
    issue_type: str = Body(default="Bug"),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    try:
        validated_vuln_id = InputValidator.validate_uuid(vuln_id, "vuln_id")
        validated_issue_type = InputValidator.validate_string(
            issue_type,
            "issue_type",
            max_length=50,
            allow_empty=False,
        )
        validated_integration_id = (
            InputValidator.validate_uuid(
                integration_id,
                "integration_id",
            )
            if integration_id
            else None
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    vulnerability = (
        await db.execute(
            select(Vulnerability).where(
                and_(Vulnerability.id == validated_vuln_id, Vulnerability.account_id == account_id)
            )
        )
    ).scalar_one_or_none()
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    integration_filters = [
        Integration.account_id == account_id,
        Integration.type == "jira",
        Integration.enabled == True,
    ]
    if validated_integration_id:
        integration_filters.append(Integration.id == validated_integration_id)
    integration = (
        await db.execute(select(Integration).where(and_(*integration_filters)).order_by(Integration.created_at.asc()))
    ).scalar_one_or_none()
    if integration is None:
        raise HTTPException(status_code=404, detail="Enabled Jira integration not found")

    cfg = IntegrationSecretCodec.runtime_config(integration)
    try:
        validate_integration_destination_config(integration.type, cfg)
    except IntegrationDestinationError as exc:
        raise HTTPException(
            status_code=400,
            detail={"message": "Integration destination blocked", "reason": str(exc)},
        ) from exc
    project_key = cfg.get("project_key") or "SEC"
    ticket_created_at = utc_now()
    ticket_lifecycle = vulnerability_ticket_lifecycle_payload(vulnerability, now=ticket_created_at)
    ticket = build_vulnerability_ticket(vulnerability, now=ticket_created_at)
    issue_key = await JiraClient(
        cfg.get("base_url", ""),
        cfg.get("email", ""),
        cfg.get("api_token", ""),
    ).create_issue(project_key, ticket["summary"], ticket["description"], validated_issue_type)
    if not issue_key:
        raise HTTPException(status_code=502, detail="Jira issue creation failed")

    ticket_url = ticket_url_from_key(cfg.get("base_url", ""), issue_key)
    vulnerability.ticket_url = ticket_url
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_TICKET_CREATED",
        user_id=payload.get("user_id"),
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details={
            "integration_id": integration.id,
            "issue_key": issue_key,
            "ticket_url": Redactor.redact_url(ticket_url),
            "ticket_lifecycle": ticket_lifecycle,
        },
    )
    await db.commit()
    await db.refresh(vulnerability)
    return {
        "status": "created",
        "issue_key": issue_key,
        "ticket_url": ticket_url,
        "ticket_lifecycle": ticket_lifecycle,
        "vulnerability": _serialize_vulnerability(vulnerability),
    }


@router.post("/{vuln_id}/retest")
async def queue_vulnerability_retest(
    vuln_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    pentest_profile_id: str | None = Body(default=None, embed=True),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Queue a scoped retest for the vulnerable template/endpoint pair."""
    account_id = payload.get("account_id")
    try:
        vulnerability = await _load_owned_vulnerability(db, account_id=account_id, vuln_id=vuln_id)
        existing_retest = await _find_active_vulnerability_retest(
            db,
            account_id=account_id,
            vulnerability_id=vulnerability.id,
        )
        if existing_retest is not None:
            retest = await _record_retest_deduped(
                db=db,
                account_id=account_id,
                vulnerability=vulnerability,
                request=request,
                user_id=payload.get("user_id"),
                existing_run=existing_retest,
                trigger_source=_MANUAL_RETEST_TRIGGER,
            )
            await db.commit()
            return retest
        support = vulnerability_retest_support(vulnerability)
        if not support["queued_scan_supported"]:
            retest = await _record_auto_retest_skipped(
                db=db,
                account_id=account_id,
                vulnerability=vulnerability,
                request=request,
                user_id=payload.get("user_id"),
                reason=str(support["reason"]),
                trigger_source=_MANUAL_RETEST_TRIGGER,
                include_retest_support=True,
            )
            await db.commit()
            return retest
        retest, template_ids, endpoint_ids, effective_pentest_profile_id = await _prepare_vulnerability_retest_run(
            db=db,
            account_id=account_id,
            vulnerability=vulnerability,
            request=request,
            user_id=payload.get("user_id"),
            pentest_profile_id=pentest_profile_id,
            trigger_source=_MANUAL_RETEST_TRIGGER,
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    await db.commit()
    _schedule_retest_background_task(
        background_tasks=background_tasks,
        db=db,
        retest=retest,
        template_ids=template_ids,
        endpoint_ids=endpoint_ids,
        account_id=account_id,
        pentest_profile_id=effective_pentest_profile_id,
    )
    return retest


@router.post("/{vuln_id}/remediation-event")
async def record_vulnerability_remediation_event(
    vuln_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    event_type: str = Body(..., embed=True),
    source: str = Body(default="api", embed=True),
    external_ref: str | None = Body(default=None, embed=True),
    pentest_profile_id: str | None = Body(default=None, embed=True),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Record an external fix event and queue a safe scoped remediation retest."""
    account_id = payload.get("account_id")
    try:
        validated_event_type = _validate_remediation_event_type(event_type)
        validated_source = _validate_remediation_event_source(source)
        validated_external_ref = _validate_remediation_event_external_ref(external_ref)
        vulnerability = await _load_owned_vulnerability(db, account_id=account_id, vuln_id=vuln_id)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    redacted_event = {
        "event_type": validated_event_type,
        "source": Redactor.redact_text(validated_source),
        "external_ref": _redact_external_ref(validated_external_ref),
    }
    previous_status = vulnerability.status
    suppressed_reason = _suppressed_auto_retest_reason(vulnerability)
    if suppressed_reason is None:
        vulnerability.status = "IN_REMEDIATION"

    retest = None
    retest_template_ids: list[str] = []
    retest_endpoint_ids: list[str] = []
    retest_pentest_profile_id: str | None = None
    if suppressed_reason is not None:
        retest = await _record_auto_retest_skipped(
            db=db,
            account_id=account_id,
            vulnerability=vulnerability,
            request=request,
            user_id=payload.get("user_id"),
            reason=suppressed_reason,
            trigger_source=_FIX_EVENT_RETEST_TRIGGER,
        )
    else:
        existing_retest = await _find_active_vulnerability_retest(
            db,
            account_id=account_id,
            vulnerability_id=vulnerability.id,
        )
        if existing_retest is not None:
            retest = await _record_retest_deduped(
                db=db,
                account_id=account_id,
                vulnerability=vulnerability,
                request=request,
                user_id=payload.get("user_id"),
                existing_run=existing_retest,
                trigger_source=_FIX_EVENT_RETEST_TRIGGER,
            )
        else:
            try:
                (
                    retest,
                    retest_template_ids,
                    retest_endpoint_ids,
                    retest_pentest_profile_id,
                ) = await _prepare_vulnerability_retest_run(
                    db=db,
                    account_id=account_id,
                    vulnerability=vulnerability,
                    request=request,
                    user_id=payload.get("user_id"),
                    pentest_profile_id=pentest_profile_id,
                    trigger_source=_FIX_EVENT_RETEST_TRIGGER,
                )
            except (ValidationError, HTTPException) as exc:
                retest = await _record_auto_retest_skipped(
                    db=db,
                    account_id=account_id,
                    vulnerability=vulnerability,
                    request=request,
                    user_id=payload.get("user_id"),
                    reason=_retest_skip_reason(exc),
                    trigger_source=_FIX_EVENT_RETEST_TRIGGER,
                )

    event_evidence = {
        **redacted_event,
        "previous_status": previous_status,
        "new_status": vulnerability.status,
    }
    retest_decision = _retest_decision_evidence(retest)
    if retest_decision:
        event_evidence["retest_decision"] = retest_decision
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_REMEDIATION_EVENT_RECORDED",
        user_id=payload.get("user_id"),
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details=event_evidence,
        ip_address=tests_router._request_ip(request),
    )
    _append_remediation_event_evidence(vulnerability, event_evidence)

    await db.commit()
    if retest is not None and retest.get("status") != "not_queued":
        _schedule_retest_background_task(
            background_tasks=background_tasks,
            db=db,
            retest=retest,
            template_ids=retest_template_ids,
            endpoint_ids=retest_endpoint_ids,
            account_id=account_id,
            pentest_profile_id=retest_pentest_profile_id,
        )
    await db.refresh(vulnerability)
    return {
        "status": "success",
        "event": redacted_event,
        "vulnerability": _serialize_vulnerability(vulnerability),
        "retest": retest,
    }


@router.post("/{vuln_id}/status")
async def update_vulnerability_status(
    vuln_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    status: str = Body(..., embed=True),
    pentest_profile_id: str | None = Body(default=None, embed=True),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db)
):
    account_id = payload.get("account_id")
    try:
        validated_status = _validate_vulnerability_status(status)
        vulnerability = await _load_owned_vulnerability(db, account_id=account_id, vuln_id=vuln_id)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    previous_status = vulnerability.status
    if validated_status == "CLOSED":
        _enforce_closure_gate(vulnerability)
    vulnerability.status = validated_status
    retest = None
    retest_template_ids: list[str] = []
    retest_endpoint_ids: list[str] = []
    retest_pentest_profile_id: str | None = None
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_STATUS_UPDATED",
        user_id=payload.get("user_id"),
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details={"previous_status": previous_status, "new_status": validated_status},
    )
    if previous_status != validated_status and validated_status == "IN_REMEDIATION":
        existing_retest = await _find_active_vulnerability_retest(
            db,
            account_id=account_id,
            vulnerability_id=vulnerability.id,
        )
        if existing_retest is not None:
            retest = await _record_retest_deduped(
                db=db,
                account_id=account_id,
                vulnerability=vulnerability,
                request=request,
                user_id=payload.get("user_id"),
                existing_run=existing_retest,
                trigger_source=_AUTO_RETEST_TRIGGER,
            )
        else:
            try:
                (
                    retest,
                    retest_template_ids,
                    retest_endpoint_ids,
                    retest_pentest_profile_id,
                ) = await _prepare_vulnerability_retest_run(
                    db=db,
                    account_id=account_id,
                    vulnerability=vulnerability,
                    request=request,
                    user_id=payload.get("user_id"),
                    pentest_profile_id=pentest_profile_id,
                    trigger_source=_AUTO_RETEST_TRIGGER,
                )
            except (ValidationError, HTTPException) as exc:
                retest = await _record_auto_retest_skipped(
                    db=db,
                    account_id=account_id,
                    vulnerability=vulnerability,
                    request=request,
                    user_id=payload.get("user_id"),
                    reason=_retest_skip_reason(exc),
                )
    await db.commit()
    if retest is not None and retest.get("status") != "not_queued":
        _schedule_retest_background_task(
            background_tasks=background_tasks,
            db=db,
            retest=retest,
            template_ids=retest_template_ids,
            endpoint_ids=retest_endpoint_ids,
            account_id=account_id,
            pentest_profile_id=retest_pentest_profile_id,
        )
    await db.refresh(vulnerability)
    response = {"status": "success", "vulnerability": _serialize_vulnerability(vulnerability)}
    if retest is not None:
        response["retest"] = retest
    return response


@router.post("/{vuln_id}/false-positive")
async def mark_false_positive(
    vuln_id: str,
    is_fp: bool = Body(True, embed=True),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db)
):
    account_id = payload.get("account_id")
    try:
        vulnerability = await _load_owned_vulnerability(db, account_id=account_id, vuln_id=vuln_id)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    previous_status = vulnerability.status
    previous_false_positive = bool(vulnerability.false_positive)
    vulnerability.false_positive = bool(is_fp)
    if is_fp:
        vulnerability.status = "CLOSED"
    elif previous_status == "CLOSED":
        vulnerability.status = "OPEN"
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_FALSE_POSITIVE_UPDATED",
        user_id=payload.get("user_id"),
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details={
            "previous_false_positive": previous_false_positive,
            "new_false_positive": bool(is_fp),
            "previous_status": previous_status,
            "new_status": vulnerability.status,
        },
    )
    await db.commit()
    await db.refresh(vulnerability)
    return {"status": "success", "vulnerability": _serialize_vulnerability(vulnerability)}


@router.delete("/{vuln_id}")
async def delete_vulnerability(
    vuln_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db)
):
    account_id = payload.get("account_id")
    try:
        vulnerability = await _load_owned_vulnerability(db, account_id=account_id, vuln_id=vuln_id)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_DELETED",
        user_id=payload.get("user_id"),
        resource_type="vulnerability",
        resource_id=vulnerability.id,
        details={
            "template_id": vulnerability.template_id,
            "severity": vulnerability.severity,
            "status": vulnerability.status,
        },
    )
    await db.delete(vulnerability)
    await db.commit()
    return {"status": "success", "id": vulnerability.id}


@router.post("/bulk-status")
async def bulk_update_vulnerability_status(
    issue_ids: list[str] = Body(...),
    status: str = Body(...),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db)
):
    """Update status for multiple vulnerability IDs at once."""
    account_id = payload.get("account_id")
    try:
        validated_status = _validate_vulnerability_status(status)
        validated_issue_ids = [
            InputValidator.validate_uuid(issue_id, f"issue_ids[{index}]")
            for index, issue_id in enumerate(issue_ids)
        ]
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if validated_status == "CLOSED":
        result = await db.execute(
            select(Vulnerability).where(
                Vulnerability.id.in_(validated_issue_ids),
                Vulnerability.account_id == account_id,
            )
        )
        for vulnerability in result.scalars().all():
            _enforce_closure_gate(vulnerability)

    await db.execute(
        update(Vulnerability)
        .where(Vulnerability.id.in_(validated_issue_ids), Vulnerability.account_id == account_id)
        .values(status=validated_status)
    )
    await log_action(
        db=db,
        account_id=account_id,
        action="VULNERABILITY_BULK_STATUS_UPDATED",
        user_id=payload.get("user_id"),
        resource_type="vulnerability",
        resource_id="bulk",
        details={"issue_ids": validated_issue_ids, "new_status": validated_status},
    )
    await db.commit()
    return {"status": "success", "updated_count": len(validated_issue_ids), "new_status": validated_status}


