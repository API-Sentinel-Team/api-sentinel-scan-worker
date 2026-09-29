"""API workflow sequences - multi-step chained API testing."""

import base64
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import APIWorkflow, APIWorkflowRun, AuthProfile
from server.modules.auth.rbac import Permission, RBAC
from server.modules.pentest.auth_material import first_auth_header_value, present
from server.modules.pentest.auth_preflight import auth_profile_has_runtime_material
from server.modules.pentest.auth_profile_secrets import AuthProfileSecretCodec
from server.modules.pentest.auth_scope import AuthScopeError, auth_scope_policy_for_error, validate_auth_profile_scope
from server.modules.pentest.target_policy import target_guard_policy_for_error, validate_pentest_target
from server.modules.persistence.database import get_db
from server.modules.test_executor.kill_switch import KILL_SWITCH_REASON, kill_switch_enabled
from server.modules.test_executor.target_guard import TargetGuardError
from server.modules.utils.redactor import Redactor
from server.modules.workflows.executor import WorkflowExecutor

router = APIRouter(tags=["API Workflows"])
_executor = WorkflowExecutor()


def _plaintext_auth_headers_exception() -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "message": (
                "Workflow execution does not accept plaintext auth_headers. "
                "Create an encrypted auth profile and execute with auth_profile_id."
            ),
            "reason": "plaintext_auth_headers_not_allowed",
        },
    )


def _auth_profile_required_exception() -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "message": "Workflow execution requires an active encrypted auth profile.",
            "reason": "auth_profile_required",
        },
    )


def _auth_profile_missing_exception(auth_profile_id: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={
            "message": "Auth profile not found or inactive.",
            "reason": "auth_profile_missing_or_inactive",
            "auth_profile_id": auth_profile_id,
        },
    )


def _auth_profile_runtime_exception(auth_profile_id: str) -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "message": "Auth profile has no usable runtime credentials.",
            "reason": "auth_profile_missing_runtime_credentials",
            "auth_profile_id": auth_profile_id,
        },
    )


def _auth_scope_exception(
    exc: AuthScopeError,
    *,
    auth_profile: object | None,
    target_url: str,
    base_url: str | None = None,
) -> HTTPException:
    policy = getattr(exc, "auth_profile_scope_policy", None)
    if not isinstance(policy, dict):
        policy = auth_scope_policy_for_error(
            exc,
            auth_profile=auth_profile,
            target_url=target_url,
            base_url=base_url or target_url,
        )
    return HTTPException(
        status_code=400,
        detail={
            "message": str(exc),
            "reason": "auth_profile_scope_blocked",
            "auth_profile_scope_policy": policy,
        },
    )


def _target_guard_exception(exc: TargetGuardError, *, target_url: str) -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "message": str(exc),
            "reason": "target_guard_blocked",
            "target_guard_policy": target_guard_policy_for_error(exc, fallback_url=target_url),
        },
    )


async def _load_workflow_auth_profile(
    db: AsyncSession,
    *,
    account_id: int,
    auth_profile_id: str | None,
    steps: list[dict[str, Any]],
) -> tuple[object, dict[str, str]]:
    if not auth_profile_id:
        raise _auth_profile_required_exception()

    result = await db.execute(
        select(AuthProfile).where(
            AuthProfile.id == auth_profile_id,
            AuthProfile.account_id == account_id,
            AuthProfile.is_active == True,
        )
    )
    stored_profile = result.scalar_one_or_none()
    if stored_profile is None:
        raise _auth_profile_missing_exception(auth_profile_id)

    runtime_profile = AuthProfileSecretCodec.decrypted_view(stored_profile)
    if runtime_profile is None or not auth_profile_has_runtime_material(runtime_profile):
        raise _auth_profile_runtime_exception(auth_profile_id)

    _preflight_workflow_scope(runtime_profile, steps)
    return runtime_profile, _auth_headers_for_profile(runtime_profile, auth_profile_id=auth_profile_id)


def _preflight_workflow_scope(auth_profile: object, steps: list[dict[str, Any]]) -> None:
    workflow_base_url: str | None = None
    for step in steps or []:
        url = str((step or {}).get("url") or "").strip()
        if not url or "{{" in url or "}}" in url:
            continue
        base_url = workflow_base_url or url
        try:
            validate_pentest_target(url)
            validate_auth_profile_scope(auth_profile, url)
        except AuthScopeError as exc:
            raise _auth_scope_exception(exc, auth_profile=auth_profile, target_url=url, base_url=base_url) from exc
        except TargetGuardError as exc:
            raise _target_guard_exception(exc, target_url=url) from exc
        workflow_base_url = workflow_base_url or url


def _auth_headers_for_profile(auth_profile: object, *, auth_profile_id: str) -> dict[str, str]:
    mode = str(getattr(auth_profile, "auth_mode", "header") or "header").lower()
    headers: dict[str, str] = {}

    static_headers = getattr(auth_profile, "static_headers", None) or {}
    if isinstance(static_headers, dict):
        for key, value in static_headers.items():
            if present(key) and present(value):
                headers[str(key).strip()] = str(value).strip()

    if mode == "basic":
        username = getattr(auth_profile, "username", None)
        password = getattr(auth_profile, "password", None)
        if present(username) and present(password):
            token = base64.b64encode(f"{str(username).strip()}:{str(password).strip()}".encode()).decode()
            headers.setdefault("Authorization", f"Basic {token}")
    elif mode == "cookie":
        cookie_header = _cookie_header(auth_profile)
        if cookie_header:
            headers.setdefault("Cookie", cookie_header)
    else:
        raw_value = first_auth_header_value(getattr(auth_profile, "header_value", None), getattr(auth_profile, "token", None))
        if raw_value:
            header_name = str(getattr(auth_profile, "header_name", None) or "Authorization").strip()
            if mode in {"bearer", "oauth", "dynamic_bearer"} and not raw_value.lower().startswith(("bearer ", "basic ")):
                raw_value = f"Bearer {raw_value}"
            headers[header_name] = raw_value

    if not headers:
        raise _auth_profile_runtime_exception(auth_profile_id)
    return headers


def _cookie_header(auth_profile: object) -> str | None:
    cookies: list[str] = []
    for cookie in getattr(auth_profile, "cookies", None) or []:
        if isinstance(cookie, dict) and present(cookie.get("key")) and present(cookie.get("value")):
            cookies.append(f"{str(cookie['key']).strip()}={str(cookie['value']).strip()}")
    if present(getattr(auth_profile, "cookie_name", None)) and present(getattr(auth_profile, "cookie_value", None)):
        cookies.append(
            f"{str(getattr(auth_profile, 'cookie_name')).strip()}={str(getattr(auth_profile, 'cookie_value')).strip()}"
        )
    return "; ".join(cookies) if cookies else None


@router.get("/")
async def list_workflows(
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(select(APIWorkflow).where(APIWorkflow.account_id == account_id))
    workflows = result.scalars().all()
    return {
        "total": len(workflows),
        "workflows": [
            {
                "id": workflow.id,
                "name": workflow.name,
                "description": workflow.description,
                "step_count": len(workflow.steps or []),
                "enabled": workflow.enabled,
                "created_at": workflow.created_at,
            }
            for workflow in workflows
        ],
    }


@router.post("/")
async def create_workflow(
    name: str = Body(...),
    description: Optional[str] = Body(None),
    steps: List[dict] = Body(...),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a workflow.
    Each step: {name, method, url, headers, body, extract, assert, stop_on_failure}
    """
    account_id = payload["account_id"]
    workflow = APIWorkflow(
        id=str(uuid.uuid4()),
        account_id=account_id,
        name=name,
        description=description,
        steps=steps,
    )
    db.add(workflow)
    await db.commit()
    await db.refresh(workflow)
    return {"id": workflow.id, "name": workflow.name, "step_count": len(steps)}


@router.get("/{workflow_id}")
async def get_workflow(
    workflow_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(APIWorkflow).where(
            APIWorkflow.id == workflow_id,
            APIWorkflow.account_id == account_id,
        )
    )
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(404, "Workflow not found")
    return {
        "id": workflow.id,
        "name": workflow.name,
        "description": workflow.description,
        "steps": workflow.steps,
        "enabled": workflow.enabled,
        "created_at": workflow.created_at,
    }


@router.post("/{workflow_id}/execute")
async def execute_workflow(
    workflow_id: str,
    auth_headers: Optional[dict] = Body(None),
    auth_profile_id: Optional[str] = Body(None),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_EXECUTE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(APIWorkflow).where(
            APIWorkflow.id == workflow_id,
            APIWorkflow.account_id == account_id,
        )
    )
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(404, "Workflow not found")
    if not workflow.enabled:
        raise HTTPException(400, "Workflow is disabled")
    if kill_switch_enabled():
        raise HTTPException(status_code=503, detail=KILL_SWITCH_REASON)
    if auth_headers:
        raise _plaintext_auth_headers_exception()

    runtime_auth_profile, runtime_auth_headers = await _load_workflow_auth_profile(
        db,
        account_id=account_id,
        auth_profile_id=auth_profile_id,
        steps=workflow.steps or [],
    )

    run = APIWorkflowRun(
        id=str(uuid.uuid4()),
        workflow_id=workflow_id,
        account_id=account_id,
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    await db.commit()

    try:
        result_payload = await _executor.run(
            workflow.steps or [],
            auth_headers=runtime_auth_headers,
            auth_profile=runtime_auth_profile,
        )
        run.status = result_payload["status"]
        run.step_results = result_payload["step_results"]
        run.variables = result_payload.get("variables", {})
        run.error = result_payload.get("error")
    except Exception as exc:
        run.status = "FAILED"
        run.error = Redactor.redact_text(str(exc))
    finally:
        run.completed_at = datetime.now(timezone.utc)
        await db.commit()

    return {
        "run_id": run.id,
        "status": run.status,
        "step_results": run.step_results,
        "error": run.error,
    }


@router.get("/{workflow_id}/runs")
async def list_runs(
    workflow_id: str,
    limit: int = Query(20),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(APIWorkflowRun)
        .where(
            APIWorkflowRun.workflow_id == workflow_id,
            APIWorkflowRun.account_id == account_id,
        )
        .order_by(APIWorkflowRun.created_at.desc())
        .limit(limit)
    )
    runs = result.scalars().all()
    return {
        "total": len(runs),
        "runs": [
            {
                "id": run.id,
                "status": run.status,
                "started_at": run.started_at,
                "completed_at": run.completed_at,
                "error": run.error,
            }
            for run in runs
        ],
    }


@router.delete("/{workflow_id}")
async def delete_workflow(
    workflow_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(APIWorkflow).where(
            APIWorkflow.id == workflow_id,
            APIWorkflow.account_id == account_id,
        )
    )
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(404, "Workflow not found")
    await db.delete(workflow)
    await db.commit()
    return {"deleted": workflow_id}
