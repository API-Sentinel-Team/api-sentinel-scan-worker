"""Test suite endpoints - list and execute built-in suites."""
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import and_, select

import server.api.routers.tests as tests_router
from server.models.core import APIEndpoint, TestRun
from server.modules.auth.rbac import Permission, RBAC, can_run_tests
from server.modules.persistence.database import get_db
from server.modules.pentest.auth_preflight import active_scan_auth_audit_context
from server.modules.suites.suite_manager import SuiteManager
from server.modules.validation.input_validator import InputValidator, ValidationError

router = APIRouter()
_suite_manager = SuiteManager()


async def _parse_run_suite_body(request: Request) -> tuple[list[str], str | None]:
    try:
        body: Any = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Request body must be JSON") from exc

    if isinstance(body, list):
        endpoint_ids = body
        pentest_profile_id = None
    elif isinstance(body, dict):
        endpoint_ids = body.get("endpoint_ids")
        pentest_profile_id = body.get("pentest_profile_id")
    else:
        raise HTTPException(
            status_code=400,
            detail="Request body must be an endpoint id list or an object with endpoint_ids",
        )

    try:
        InputValidator.validate_collection_size(endpoint_ids, "endpoint_ids", max_size=1000)
        validated_endpoint_ids = [
            InputValidator.validate_uuid(endpoint_id, "endpoint_id")
            for endpoint_id in endpoint_ids
        ]
        validated_pentest_profile_id = (
            InputValidator.validate_uuid(pentest_profile_id, "pentest_profile_id")
            if pentest_profile_id
            else None
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return validated_endpoint_ids, validated_pentest_profile_id


@router.get("/")
async def list_suites(payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ))):
    """List all built-in test suites with template counts."""
    return {"suites": _suite_manager.list_suites()}


@router.get("/{suite_name}/templates")
async def get_suite_templates(
    suite_name: str,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
):
    """List templates in a suite."""
    templates = _suite_manager.get_suite_templates(validated_suite_name)
    return {
        "suite": suite_name,
        "count": len(templates),
        "templates": [
            {"id": t.get("id"), "name": t.get("info", {}).get("name"),
             "severity": t.get("info", {}).get("severity"),
             "category": t.get("info", {}).get("category", {}).get("name")}
            for t in templates
        ],
    }


@router.post("/{suite_name}/run")
async def run_suite(
    suite_name: str,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(can_run_tests),
):
    """Queue a suite through the guarded active-scan execution pipeline."""
    account_id = payload["account_id"]
    try:
        validated_suite_name = InputValidator.validate_string(
            suite_name,
            "suite_name",
            max_length=100,
            allow_empty=False,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    templates = _suite_manager.get_suite_templates(suite_name)
    if not templates:
        raise HTTPException(
            status_code=404,
            detail=f"Suite '{validated_suite_name}' not found or has no templates",
        )

    endpoint_ids, pentest_profile_id = await _parse_run_suite_body(request)
    template_ids = [
        InputValidator.validate_string(
            template["id"],
            "template_id",
            max_length=256,
            allow_empty=False,
        )
        for template in templates
        if template.get("id")
    ]
    if not template_ids:
        raise HTTPException(
            status_code=404,
            detail=f"Suite '{validated_suite_name}' has no runnable templates",
        )

    if tests_router.kill_switch_enabled():
        raise HTTPException(status_code=503, detail=tests_router.KILL_SWITCH_REASON)
    tests_router._validate_scan_budget(template_ids, endpoint_ids)

    result = await db.execute(
        select(APIEndpoint).where(
            and_(APIEndpoint.id.in_(endpoint_ids), APIEndpoint.account_id == account_id)
        )
    )
    endpoints = result.scalars().all()
    valid_ids = {str(endpoint.id) for endpoint in endpoints}
    if len(valid_ids) < len(endpoint_ids):
        raise HTTPException(status_code=403, detail="Some endpoints do not belong to your account")
    tests_router._validate_scan_endpoint_targets(endpoints)

    pentest_profile, auth_profile = await tests_router._load_scan_profile_for_execution(
        db,
        account_id=account_id,
        pentest_profile_id=pentest_profile_id,
    )
    tests_router._validate_scan_auth_scope(endpoints, auth_profile)
    effective_pentest_profile_id = pentest_profile.id if pentest_profile is not None else pentest_profile_id
    execution_mode = tests_router._scan_execution_mode()

    run_id = str(uuid.uuid4())
    run = TestRun(
        id=run_id,
        account_id=account_id,
        status="PENDING",
        template_ids=template_ids,
        endpoint_ids=endpoint_ids,
        pentest_profile_id=effective_pentest_profile_id,
        trigger_source="suite",
    )
    db.add(run)
    await tests_router._audit_scan_event(
        db,
        action="SCAN_RUN_QUEUED",
        account_id=account_id,
        run_id=run_id,
        user_id=payload.get("user_id"),
        details={
            "source": "suite",
            "suite_name": validated_suite_name,
            "template_count": len(template_ids),
            "endpoint_count": len(endpoint_ids),
            "planned_tests": tests_router._planned_test_count(template_ids, endpoint_ids),
            "pentest_profile_id": effective_pentest_profile_id,
            **active_scan_auth_audit_context(pentest_profile, auth_profile),
            "execution_mode": execution_mode,
            "trigger_source": run.trigger_source,
        },
        ip_address=tests_router._request_ip(request),
    )
    await db.commit()

    if execution_mode == "background":
        background_tasks.add_task(
            tests_router._run_security_tasks,
            run_id,
            template_ids,
            endpoint_ids,
            account_id,
            effective_pentest_profile_id,
            db.bind,
        )

    return {
        "status": "scan_started" if execution_mode == "background" else "scan_queued",
        "suite": validated_suite_name,
        "run_id": run_id,
        "template_count": len(template_ids),
        "endpoint_count": len(endpoint_ids),
        "pentest_profile_id": effective_pentest_profile_id,
        "execution_mode": execution_mode,
        "trigger_source": run.trigger_source,
    }
