"""CRUD endpoints for test schedules (cron-based)."""
from fastapi import APIRouter, Depends, Body, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import and_, delete, select, update
from server.modules.auth.rbac import Permission, RBAC
from server.modules.persistence.database import get_db
from server.modules.scheduler.test_scheduler import ScheduleValidationError, TestScheduler
from server.modules.validation.input_validator import InputValidator, ValidationError
from server.models.core import TestSchedule
from server.config import settings

router = APIRouter()
_scheduler = TestScheduler()


@router.get("/")
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(TestSchedule)
        .where(TestSchedule.account_id == account_id)
        .order_by(TestSchedule.created_at.desc())
    )
    schedules = result.scalars().all()
    return {
        "total": len(schedules),
        "schedules": [
            {"id": s.id, "name": s.name, "cron_expression": s.cron_expression,
             "template_ids": s.template_ids, "endpoint_ids": s.endpoint_ids,
             "pentest_profile_id": s.pentest_profile_id,
             "enabled": s.enabled, "created_at": str(s.created_at),
             "continuous_workflow": _continuous_workflow_summary(s)}
            for s in schedules
        ],
    }


@router.post("/")
async def create_schedule(
    name: str = Body(...),
    cron_expression: str = Body(..., description="Cron expression such as 0 2 * * *"),
    template_ids: list[str] = Body(...),
    endpoint_ids: list[str] = Body(...),
    pentest_profile_id: str | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
):
    account_id = payload["account_id"]
    try:
        validated_name = InputValidator.validate_string(name, "name", max_length=255, allow_empty=False)
        validated_cron = InputValidator.validate_string(
            cron_expression,
            "cron_expression",
            max_length=100,
            allow_empty=False,
        )
        InputValidator.validate_collection_size(template_ids, "template_ids", max_size=1000)
        InputValidator.validate_collection_size(endpoint_ids, "endpoint_ids", max_size=1000)
        validated_template_ids = [
            InputValidator.validate_string(t_id, "template_id", max_length=256, allow_empty=False)
            for t_id in template_ids
        ]
        validated_endpoint_ids = [
            InputValidator.validate_uuid(e_id, "endpoint_id")
            for e_id in endpoint_ids
        ]
        validated_pentest_profile_id = (
            InputValidator.validate_uuid(pentest_profile_id, "pentest_profile_id")
            if pentest_profile_id
            else None
        )
        schedule_id = await _scheduler.schedule(
            validated_name,
            validated_cron,
            validated_template_ids,
            validated_endpoint_ids,
            account_id,
            db,
            pentest_profile_id=validated_pentest_profile_id,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ScheduleValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc
    return {
        "status": "created",
        "id": schedule_id,
        "name": validated_name,
        "cron": validated_cron,
        "pentest_profile_id": validated_pentest_profile_id,
        "continuous_workflow": _continuous_workflow_summary(
            pentest_profile_id=validated_pentest_profile_id,
        ),
    }


@router.patch("/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: str,
    enabled: bool = True,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
):
    account_id = payload["account_id"]
    result = await db.execute(
        update(TestSchedule)
        .where(and_(TestSchedule.id == schedule_id, TestSchedule.account_id == account_id))
        .values(enabled=enabled)
    )
    if not result.rowcount:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.commit()
    return {"status": "updated", "id": schedule_id, "enabled": enabled}


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
):
    account_id = payload["account_id"]
    result = await db.execute(
        delete(TestSchedule).where(and_(TestSchedule.id == schedule_id, TestSchedule.account_id == account_id))
    )
    if not result.rowcount:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.commit()
    return {"status": "deleted", "id": schedule_id}


def _continuous_workflow_summary(
    schedule: TestSchedule | None = None,
    *,
    pentest_profile_id: str | None = None,
) -> dict[str, object]:
    profile_id = pentest_profile_id if pentest_profile_id is not None else getattr(schedule, "pentest_profile_id", None)
    execution_mode = (settings.PENTEST_SCAN_EXECUTION_MODE or "background").strip().lower()
    if execution_mode not in {"background", "queued"}:
        execution_mode = "background"
    return {
        "scheduled": True,
        "authenticated": bool(profile_id),
        "target_guard_enforced": True,
        "auth_scope_guard_enforced": True,
        "execution_mode": execution_mode,
    }
