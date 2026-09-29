"""BOLA (Broken Object Level Authorization) testing endpoints."""

import uuid
from datetime import datetime, timezone
import json
from typing import Any
from urllib.parse import urlunparse

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import and_, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from server.models.core import APIEndpoint, SampleData, TestAccount, TestResult, TestRun, Vulnerability
from server.modules.auth.rbac import Permission, RBAC, can_run_tests
from server.modules.identity.authorization_replay import (
    authorization_identity_label,
    authorization_identity_summary,
    authorization_role_key,
    auth_headers_for_account,
    build_authorization_replay_evidence,
    build_replay_request,
    classify_authorization_issue,
    evaluate_authorization_replay,
    infer_victim_account,
)
from server.modules.persistence.database import get_db
from server.modules.pentest.target_policy import target_guard_policy_for_error
from server.modules.test_executor.kill_switch import (
    KILL_SWITCH_REASON,
    PentestKillSwitchError,
    guard_pentest_execution,
)
from server.modules.test_executor.state_change_guard import (
    StateChangeBlocked,
    StateChangeGuard,
    state_change_policy_for_request,
)
from server.modules.test_executor.target_guard import TargetGuard, TargetGuardError
from server.modules.utils.redactor import Redactor
from server.modules.vulnerability_detector.store import create_or_merge_vulnerability

router = APIRouter(tags=["bola"])


class AuthorizationReplayOptions(BaseModel):
    attacker_role_id: str | None = None
    attacker_role_ids: list[str] = Field(default_factory=list)
    allow_state_change: bool = False
    require_response_similarity: bool = True
    body_similarity_threshold: float = Field(default=70.0, ge=0, le=100)
    schema_similarity_threshold: float = Field(default=70.0, ge=0, le=100)


class AuthorizationReplayMatrixRequest(AuthorizationReplayOptions):
    endpoint_ids: list[str] = Field(default_factory=list)
    max_endpoints: int = Field(default=25, ge=1, le=200)


def _parse_options(body: Any, *, require_attacker: bool) -> AuthorizationReplayOptions:
    if isinstance(body, str):
        return AuthorizationReplayOptions(attacker_role_id=body)
    if isinstance(body, dict):
        return AuthorizationReplayOptions(**body)
    if body is None and not require_attacker:
        return AuthorizationReplayOptions()
    raise HTTPException(status_code=400, detail="request body must be an attacker id string or options object")


def _endpoint_url(endpoint: APIEndpoint, request: dict[str, Any]) -> str:
    if request.get("url"):
        return str(request["url"])
    host = endpoint.host
    if not host:
        raise HTTPException(status_code=400, detail="Captured request has no URL and endpoint host is missing")
    protocol = endpoint.protocol or "https"
    port = endpoint.port
    default_port = 443 if protocol == "https" else 80
    netloc = host if not port or port == default_port else f"{host}:{port}"
    return urlunparse((protocol, netloc, endpoint.path or "/", "", "", ""))


def _http_content(body: Any) -> str | bytes | None:
    if body in (None, ""):
        return None
    if isinstance(body, (str, bytes)):
        return body
    return json.dumps(body)


def _template_id(issue_type: str, victim: TestAccount | None, attacker: TestAccount) -> str:
    victim_role = authorization_role_key(victim) or "UNKNOWN"
    attacker_role = authorization_role_key(attacker) or "UNKNOWN"
    return f"{issue_type}_AUTHZ_REPLAY_{victim_role}_TO_{attacker_role}"[:100]


def _guard_authorization_replay_execution() -> None:
    try:
        guard_pentest_execution()
    except PentestKillSwitchError as exc:
        raise HTTPException(status_code=503, detail=KILL_SWITCH_REASON) from exc


def _target_guard_blocked_detail(
    exc: TargetGuardError,
    *,
    target_url: str,
    base_url: str | None = None,
) -> dict[str, Any]:
    return {
        "reason": "target_guard_blocked",
        "message": Redactor.redact_text(str(exc)),
        "target_guard_policy": target_guard_policy_for_error(
            exc,
            fallback_url=target_url,
            fallback_base_url=base_url or target_url,
        ),
    }


def _effective_state_change_method(request: dict[str, Any]) -> str:
    return StateChangeGuard.effective_state_change_method(request)


def _state_change_policy_for_request(
    request: dict[str, Any],
    guard: StateChangeGuard,
    *,
    reason: str,
) -> dict[str, Any]:
    return state_change_policy_for_request(request, guard, reason=reason)


def _state_change_blocked_detail(
    exc: StateChangeBlocked,
    *,
    request: dict[str, Any],
    guard: StateChangeGuard,
) -> dict[str, Any]:
    reason = str(exc)
    reason_code = "destructive_method_blocked" if reason.startswith("destructive_method_blocked:") else "state_change_blocked"
    return {
        "reason": reason_code,
        "message": Redactor.redact_text(reason),
        "state_change_policy": _state_change_policy_for_request(request, guard, reason=reason),
    }


async def _load_endpoint_and_sample(
    db: AsyncSession,
    *,
    account_id: int,
    ep_id: str,
) -> tuple[APIEndpoint, SampleData]:
    ep_result = await db.execute(
        select(APIEndpoint).where(
            APIEndpoint.id == ep_id,
            APIEndpoint.account_id == account_id,
        )
    )
    endpoint = ep_result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    sample_result = await db.execute(
        select(SampleData)
        .where(
            SampleData.endpoint_id == ep_id,
            SampleData.account_id == account_id,
        )
        .order_by(SampleData.created_at.desc())
        .limit(1)
    )
    sample = sample_result.scalar_one_or_none()
    if not sample:
        raise HTTPException(status_code=400, detail="No sample data found for this endpoint. Cannot replay.")
    return endpoint, sample


async def _load_test_accounts(
    db: AsyncSession,
    *,
    account_id: int,
    requested_ids: list[str],
) -> tuple[list[TestAccount], list[TestAccount]]:
    all_result = await db.execute(
        select(TestAccount)
        .where(TestAccount.account_id == account_id)
        .order_by(TestAccount.created_at.asc())
    )
    all_accounts = all_result.scalars().all()
    replayable_accounts = [account for account in all_accounts if auth_headers_for_account(account)]

    if not requested_ids:
        return all_accounts, replayable_accounts

    requested = [account for account in replayable_accounts if account.id in set(requested_ids)]
    missing = sorted(set(requested_ids) - {account.id for account in requested})
    if missing:
        raise HTTPException(status_code=400, detail=f"Attacker role not found or has no replayable auth: {missing[0]}")
    return all_accounts, requested


async def _load_matrix_endpoint_ids(
    db: AsyncSession,
    *,
    account_id: int,
    endpoint_ids: list[str],
    max_endpoints: int,
) -> list[str]:
    if endpoint_ids:
        result = await db.execute(
            select(APIEndpoint.id).where(
                APIEndpoint.account_id == account_id,
                APIEndpoint.id.in_(endpoint_ids),
            )
        )
        found = {str(item) for item in result.scalars().all()}
        missing = sorted(set(endpoint_ids) - set(found))
        if missing:
            raise HTTPException(status_code=403, detail="Some endpoints do not belong to your account")
        return [endpoint_id for endpoint_id in endpoint_ids if endpoint_id in found][:max_endpoints]

    result = await db.execute(
        select(SampleData.endpoint_id)
        .where(
            SampleData.account_id == account_id,
            SampleData.endpoint_id.is_not(None),
        )
        .order_by(SampleData.created_at.desc())
        .limit(max_endpoints * 3)
    )
    selected: list[str] = []
    seen: set[str] = set()
    for endpoint_id in result.scalars().all():
        endpoint_id = str(endpoint_id)
        if endpoint_id in seen:
            continue
        seen.add(endpoint_id)
        selected.append(endpoint_id)
        if len(selected) >= max_endpoints:
            break
    return selected


async def _run_authorization_replay_matrix(
    *,
    ep_id: str,
    options: AuthorizationReplayOptions,
    account_id: int,
    db: AsyncSession,
    run_id: str | None = None,
) -> dict[str, Any]:
    _guard_authorization_replay_execution()
    endpoint, sample = await _load_endpoint_and_sample(db, account_id=account_id, ep_id=ep_id)
    original_request = dict(sample.request or {})
    original_response = dict(sample.response or {})
    original_url = _endpoint_url(endpoint, original_request)
    original_request["url"] = original_url
    original_request["method"] = (original_request.get("method") or endpoint.method or "GET").upper()

    target_guard = TargetGuard.from_settings()
    state_guard = StateChangeGuard(allow_state_change=options.allow_state_change)
    try:
        target_guard.validate_url(original_url)
        state_guard.validate_request(original_request)
    except TargetGuardError as exc:
        raise HTTPException(
            status_code=400,
            detail=_target_guard_blocked_detail(exc, target_url=original_url),
        ) from exc
    except StateChangeBlocked as exc:
        raise HTTPException(
            status_code=400,
            detail=_state_change_blocked_detail(
                exc,
                request=original_request,
                guard=state_guard,
            ),
        ) from exc

    requested_ids = [
        id_
        for id_ in ([options.attacker_role_id] if options.attacker_role_id else []) + options.attacker_role_ids
        if id_
    ]
    all_accounts, attackers = await _load_test_accounts(db, account_id=account_id, requested_ids=requested_ids)

    victim = infer_victim_account(all_accounts, original_request)
    if not requested_ids and victim is not None:
        attackers = [attacker for attacker in attackers if attacker.id != victim.id]
    if not attackers:
        raise HTTPException(status_code=400, detail="No replayable non-victim attacker test accounts configured")
    results: list[dict[str, Any]] = []
    created_count = 0
    merged_count = 0
    vulnerable_count = 0

    async with httpx.AsyncClient(timeout=10.0) as client:
        for attacker in attackers:
            attacker_identity = authorization_identity_summary(attacker)
            victim_identity = authorization_identity_summary(victim)
            replay_request = build_replay_request(original_request, attacker)
            replay_request["method"] = (replay_request.get("method") or "GET").upper()
            replay_url = str(replay_request.get("url") or original_url)
            try:
                target_guard.validate_url(replay_url, base_url=original_url)
                state_guard.validate_request(replay_request)
                started_at = datetime.now(timezone.utc)
                response = await client.request(
                    method=replay_request["method"],
                    url=replay_url,
                    headers=replay_request.get("headers", {}),
                    content=_http_content(replay_request.get("body")),
                )
                finished_at = datetime.now(timezone.utc)
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
                    body_similarity_threshold=options.body_similarity_threshold,
                    schema_similarity_threshold=options.schema_similarity_threshold,
                    require_response_similarity=options.require_response_similarity,
                )
                issue_type = classify_authorization_issue(
                    victim=victim,
                    attacker=attacker,
                    assessment=assessment,
                    original_request=original_request,
                    replay_request=replay_request,
                )
                safe_request = Redactor.redact_http_message(replay_request)
                safe_response = Redactor.redact_http_message(attacker_response)
                evidence = build_authorization_replay_evidence(
                    endpoint_id=ep_id,
                    issue_type=issue_type,
                    victim=victim,
                    attacker=attacker,
                    original_request=original_request,
                    original_response=original_response,
                    replay_request=replay_request,
                    attacker_response=attacker_response,
                    assessment=assessment,
                    allow_state_change=options.allow_state_change,
                )
                identity_boundary = (evidence.get("matched_rule") or {}).get("identity_boundary")

                test_result = TestResult(
                    run_id=run_id,
                    endpoint_id=ep_id,
                    template_id=_template_id(issue_type or "AUTHZ", victim, attacker),
                    is_vulnerable=bool(issue_type),
                    severity="HIGH" if issue_type else "INFO",
                    sent_request=safe_request,
                    received_response=safe_response,
                    percentage_match=assessment["similarity_pct"],
                    evidence=json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str),
                )
                db.add(test_result)
                await db.flush()

                vulnerability_summary = None
                if issue_type:
                    vulnerable_count += 1
                    vulnerability, created, fingerprint = await create_or_merge_vulnerability(
                        db,
                        {
                            "account_id": account_id,
                            "template_id": test_result.template_id,
                            "endpoint_id": ep_id,
                            "url": Redactor.redact_url(replay_url),
                            "method": replay_request["method"],
                            "severity": "HIGH" if assessment["confidence"] == "HIGH" else "MEDIUM",
                            "type": issue_type,
                            "description": (
                                f"{issue_type} authorization replay succeeded for "
                                f"{authorization_identity_label(attacker)} against captured victim traffic."
                            ),
                            "confidence": assessment["confidence"],
                            "remediation": (
                                "Enforce object and function-level authorization on every request using server-side "
                                "ownership, tenant, and role checks. Deny by default when the authenticated principal "
                                "does not own the object or lacks the required role."
                            ),
                            "evidence": evidence,
                        },
                    )
                    if created:
                        created_count += 1
                    else:
                        merged_count += 1
                    vulnerability_summary = {
                        "id": vulnerability.id,
                        "created": created,
                        "fingerprint": fingerprint,
                        "template_id": vulnerability.template_id,
                        "severity": vulnerability.severity,
                        "type": vulnerability.type,
                        "occurrence_count": int(vulnerability.occurrence_count or 1),
                    }

                results.append(
                    {
                        "attacker_id": attacker_identity["id"],
                        "attacker_role": attacker_identity["role"],
                        "victim_id": victim_identity["id"],
                        "victim_role": victim_identity["role"],
                        "test_id": test_result.id,
                        "issue_type": issue_type,
                        "is_vulnerable": bool(issue_type),
                        "response_code": assessment["attacker_status_code"],
                        "similarity_pct": assessment["similarity_pct"],
                        "schema_match_pct": assessment["schema_match_pct"],
                        "confidence": assessment["confidence"],
                        "identity_boundary": identity_boundary if isinstance(identity_boundary, dict) else None,
                        "vulnerability": vulnerability_summary,
                    }
                )
            except TargetGuardError as exc:
                results.append(
                    {
                        "attacker_id": attacker_identity["id"],
                        "attacker_role": attacker_identity["role"],
                        "is_vulnerable": False,
                        "skip_reason": "target_guard",
                        "error": Redactor.redact_text(str(exc)),
                        "target_guard_policy": target_guard_policy_for_error(
                            exc,
                            fallback_url=replay_url,
                            fallback_base_url=original_url,
                        ),
                    }
                )
            except StateChangeBlocked as exc:
                results.append(
                    {
                        "attacker_id": attacker_identity["id"],
                        "attacker_role": attacker_identity["role"],
                        "is_vulnerable": False,
                        "skip_reason": "state_change_guard",
                        "error": Redactor.redact_text(str(exc)),
                        "state_change_policy": _state_change_policy_for_request(
                            replay_request,
                            state_guard,
                            reason=str(exc),
                        ),
                    }
                )

    return {
        "status": "completed",
        "endpoint_id": ep_id,
        "victim": authorization_identity_summary(victim),
        "attackers_tested": len(attackers),
        "vulnerable_count": vulnerable_count,
        "vulnerabilities_created": created_count,
        "vulnerabilities_merged": merged_count,
        "results": results,
    }


@router.post("/scan-endpoint/{ep_id}")
async def scan_endpoint_for_bola(
    ep_id: str,
    body: Any = Body(...),
    payload: dict = Depends(can_run_tests),
    db: AsyncSession = Depends(get_db),
):
    """
    Perform a BOLA test on a specific endpoint by swapping tokens.
    1. Load the tenant-scoped endpoint and its latest captured sample.
    2. Load the tenant-scoped attacker account context.
    3. Replay the victim request with the attacker's authorization context.
    4. Flag BOLA when the replay still succeeds.
    """

    account_id = int(payload["account_id"])
    _guard_authorization_replay_execution()

    options = _parse_options(body, require_attacker=True)
    if not options.attacker_role_id and not options.attacker_role_ids:
        raise HTTPException(status_code=400, detail="attacker_role_id is required")
    if options.attacker_role_ids and not options.attacker_role_id:
        options.attacker_role_id = options.attacker_role_ids[0]
        options.attacker_role_ids = []

    try:
        summary = await _run_authorization_replay_matrix(
            ep_id=ep_id,
            options=options,
            account_id=account_id,
            db=db,
        )
        await db.commit()
    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"BOLA replay failed: {exc}") from exc

    result = summary["results"][0]
    return {
        "status": "vulnerable" if result.get("is_vulnerable") else "secured",
        "response_code": result.get("response_code"),
        "test_id": result.get("test_id"),
        "issue_type": result.get("issue_type"),
        "similarity_pct": result.get("similarity_pct"),
        "schema_match_pct": result.get("schema_match_pct"),
        "confidence": result.get("confidence"),
        "vulnerability": result.get("vulnerability"),
    }


@router.post("/scan-endpoint/{ep_id}/matrix")
async def scan_endpoint_authorization_matrix(
    ep_id: str,
    body: Any = Body(default=None),
    payload: dict = Depends(can_run_tests),
    db: AsyncSession = Depends(get_db),
):
    """Replay captured endpoint traffic across configured identities for BOLA/BFLA coverage."""

    account_id = int(payload["account_id"])
    _guard_authorization_replay_execution()
    options = _parse_options(body, require_attacker=False)
    try:
        summary = await _run_authorization_replay_matrix(
            ep_id=ep_id,
            options=options,
            account_id=account_id,
            db=db,
        )
        await db.commit()
        return summary
    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Authorization replay matrix failed: {exc}") from exc


@router.post("/matrix")
async def scan_authorization_matrix(
    body: AuthorizationReplayMatrixRequest | None = Body(default=None),
    payload: dict = Depends(can_run_tests),
    db: AsyncSession = Depends(get_db),
):
    """Replay latest sampled traffic across multiple endpoints and identities for BOLA/BFLA coverage."""

    account_id = int(payload["account_id"])
    _guard_authorization_replay_execution()
    body = body or AuthorizationReplayMatrixRequest()
    run_id = str(uuid.uuid4())
    endpoint_ids = await _load_matrix_endpoint_ids(
        db,
        account_id=account_id,
        endpoint_ids=body.endpoint_ids,
        max_endpoints=body.max_endpoints,
    )
    if not endpoint_ids:
        raise HTTPException(status_code=400, detail="No sampled endpoints available for authorization replay")

    started_at = datetime.now(timezone.utc)
    run = TestRun(
        id=run_id,
        account_id=account_id,
        status="RUNNING",
        template_ids=["AUTHORIZATION_REPLAY_MATRIX"],
        endpoint_ids=endpoint_ids,
        trigger_source="authorization_replay_matrix",
        started_at=started_at,
    )
    db.add(run)
    await db.flush()

    endpoint_summaries: list[dict[str, Any]] = []
    total_attackers = 0
    total_vulnerable = 0
    created_count = 0
    merged_count = 0
    error_count = 0

    options = AuthorizationReplayOptions(**body.model_dump(exclude={"endpoint_ids", "max_endpoints"}))
    for endpoint_id in endpoint_ids:
        try:
            summary = await _run_authorization_replay_matrix(
                ep_id=endpoint_id,
                options=options,
                account_id=account_id,
                db=db,
                run_id=run_id,
            )
            endpoint_summaries.append(summary)
            total_attackers += int(summary.get("attackers_tested") or 0)
            total_vulnerable += int(summary.get("vulnerable_count") or 0)
            created_count += int(summary.get("vulnerabilities_created") or 0)
            merged_count += int(summary.get("vulnerabilities_merged") or 0)
        except HTTPException as exc:
            error_count += 1
            endpoint_summaries.append(
                {
                    "status": "skipped",
                    "endpoint_id": endpoint_id,
                    "reason": Redactor.redact_json(exc.detail),
                }
            )
        except Exception as exc:
            error_count += 1
            endpoint_summaries.append(
                {
                    "status": "failed",
                    "endpoint_id": endpoint_id,
                    "reason": Redactor.redact_text(str(exc)),
                }
            )

    completed_at = datetime.now(timezone.utc)
    await db.execute(
        update(TestRun)
        .where(TestRun.id == run_id)
        .values(
            status="COMPLETED",
            completed_at=completed_at,
            total_tests=total_attackers,
            vulnerable_count=total_vulnerable,
            error_count=error_count,
        )
    )
    await db.commit()

    return {
        "status": "completed" if error_count == 0 else "completed_with_errors",
        "run_id": run_id,
        "endpoints_requested": len(endpoint_ids),
        "endpoints_completed": len([item for item in endpoint_summaries if item.get("status") == "completed"]),
        "endpoints_skipped_or_failed": error_count,
        "attackers_tested": total_attackers,
        "vulnerable_count": total_vulnerable,
        "vulnerabilities_created": created_count,
        "vulnerabilities_merged": merged_count,
        "results": endpoint_summaries,
    }


@router.get("/vulnerabilities")
async def list_bola_vulns(
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List BOLA vulnerabilities for the authenticated tenant only."""

    account_id = int(payload["account_id"])
    result = await db.execute(
        select(Vulnerability).where(
            and_(Vulnerability.type.in_(["BOLA", "BFLA"]), Vulnerability.status != "CLOSED"),
            Vulnerability.account_id == account_id,
        )
    )
    vulnerabilities = result.scalars().all()
    return [
        {
            "id": vulnerability.id,
            "endpoint_id": vulnerability.endpoint_id,
            "url": vulnerability.url,
            "method": vulnerability.method,
            "type": vulnerability.type,
            "severity": vulnerability.severity,
            "description": vulnerability.description,
            "confidence": vulnerability.confidence,
            "status": vulnerability.status,
            "created_at": str(vulnerability.created_at),
        }
        for vulnerability in vulnerabilities
    ]


# ── Multi-Identity Test Account Management ────────────────────────────────────
# Used to configure admin/user/low-privilege/cross-tenant identity matrix for
# BOLA and BFLA replay testing.


class TestAccountCreateRequest(BaseModel):
    name: str
    role: str  # ADMIN | MEMBER | ATTACKER | VIEWER
    auth_token: str | None = None
    auth_headers: dict[str, str] | None = None


class TestAccountUpdateRequest(BaseModel):
    name: str | None = None
    role: str | None = None
    auth_token: str | None = None
    auth_headers: dict[str, str] | None = None


@router.get("/test-accounts")
async def list_test_accounts(
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List all configured test accounts (identity matrix) for BOLA/BFLA testing."""
    account_id = payload["account_id"]
    result = await db.execute(
        select(TestAccount).where(TestAccount.account_id == account_id)
        .order_by(TestAccount.created_at.desc())
    )
    accounts = result.scalars().all()
    return {
        "total": len(accounts),
        "test_accounts": [
            {
                "id": a.id,
                "name": a.name,
                "role": a.role,
                "has_auth_token": bool(a.auth_token),
                "has_auth_headers": bool(a.auth_headers),
                "created_at": str(a.created_at),
            }
            for a in accounts
        ],
        "identity_matrix": {
            "role_count": len({a.role for a in accounts if a.role}),
            "roles_present": sorted({(a.role or "").upper() for a in accounts if a.role}),
            "multi_identity_ready": len({a.role for a in accounts if a.role}) >= 2,
            "has_privileged_role": any(
                (a.role or "").upper() in {"ADMIN", "SECURITY_ENGINEER"} for a in accounts
            ),
            "has_low_privilege_role": any(
                (a.role or "").upper() in {"MEMBER", "ATTACKER", "VIEWER"} for a in accounts
            ),
        },
    }


@router.post("/test-accounts")
async def create_test_account(
    body: TestAccountCreateRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """
    Register an identity for BOLA/BFLA replay testing.

    The auth_token or auth_headers are stored encrypted and used during
    multi-identity scan runs to replay requests as different actors.
    """
    from server.modules.identity.test_account_secrets import TestAccountSecretCodec as _Codec
    import uuid as _uuid

    account_id = payload["account_id"]
    role_upper = (body.role or "MEMBER").upper()

    auth_headers_encrypted = None
    if body.auth_headers:
        auth_headers_encrypted = _Codec.encrypt_headers(body.auth_headers)
    elif body.auth_token:
        auth_headers_encrypted = _Codec.encrypt_headers({"Authorization": f"Bearer {body.auth_token}"})

    test_account = TestAccount(
        id=str(_uuid.uuid4()),
        account_id=account_id,
        name=body.name,
        role=role_upper,
        auth_headers=auth_headers_encrypted,
        auth_token=None,  # never store plaintext token
    )
    db.add(test_account)
    await db.commit()
    await db.refresh(test_account)
    return {
        "status": "created",
        "id": test_account.id,
        "name": test_account.name,
        "role": test_account.role,
    }


@router.delete("/test-accounts/{account_id_param}")
async def delete_test_account(
    account_id_param: str,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Remove a test account from the identity matrix."""
    account_id = payload["account_id"]
    result = await db.execute(
        select(TestAccount).where(
            and_(TestAccount.id == account_id_param, TestAccount.account_id == account_id)
        )
    )
    ta = result.scalar_one_or_none()
    if ta is None:
        raise HTTPException(status_code=404, detail="Test account not found")
    await db.delete(ta)
    await db.commit()
    return {"status": "deleted", "id": account_id_param}
