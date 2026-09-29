"""Response playbooks API."""
from __future__ import annotations

import json
import uuid
from typing import Any, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import ResponseActionLog, ResponsePlaybook
from server.modules.auth.rbac import Permission, RBAC
from server.modules.integrations.destination_guard import (
    IntegrationDestinationError,
    validate_integration_destination_config,
)
from server.modules.persistence.database import get_db
from server.modules.response.playbook_secrets import PlaybookActionSecretCodec
from server.modules.utils.redactor import Redactor
from server.modules.validation.input_validator import InputValidator, ValidationError

router = APIRouter(tags=["Response Playbooks"])

ALLOWED_ACTION_TYPES = {
    "NOTIFY",
    "WEBHOOK",
    "BLOCK_IP_LIST",
    "WAF_RULE_PUSH",
    "RATE_LIMIT_OVERRIDE",
    "TOKEN_INVALIDATION",
    "CIRCUIT_BREAKER",
    "CREATE_TICKET",
}
ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _bad_request(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def _validate_uuid(value: str, field_name: str) -> str:
    try:
        return InputValidator.validate_uuid(value, field_name)
    except ValidationError as exc:
        raise _bad_request(exc) from exc


def _validate_name(value: str) -> str:
    try:
        return InputValidator.validate_string(value, "name", max_length=255, allow_empty=False)
    except ValidationError as exc:
        raise _bad_request(exc) from exc


def _validate_trigger(value: str) -> str:
    try:
        return InputValidator.validate_string(
            value,
            "trigger",
            max_length=100,
            allow_empty=False,
            pattern=r"^[A-Za-z0-9_.:-]+$",
        )
    except ValidationError as exc:
        raise _bad_request(exc) from exc


def _validate_severity(value: str) -> str:
    try:
        severity = InputValidator.validate_string(
            value,
            "severity_threshold",
            max_length=20,
            allow_empty=False,
        ).upper()
    except ValidationError as exc:
        raise _bad_request(exc) from exc
    if severity not in ALLOWED_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"severity_threshold: Must be one of {sorted(ALLOWED_SEVERITIES)}",
        )
    return severity


def _validate_actions(actions: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if actions is None:
        return []
    try:
        InputValidator.validate_collection_size(actions, "actions", max_size=25)
    except ValidationError as exc:
        raise _bad_request(exc) from exc
    if not InputValidator.validate_json_depth(actions, max_depth=8):
        raise HTTPException(status_code=400, detail="actions: Exceeds maximum JSON depth")
    try:
        serialized = json.dumps(actions)
    except TypeError as exc:
        raise HTTPException(status_code=400, detail="actions: Must be JSON serializable") from exc
    if len(serialized) > 65536:
        raise HTTPException(status_code=400, detail="actions: Exceeds max size of 65536 bytes")

    validated: list[dict[str, Any]] = []
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            raise HTTPException(status_code=400, detail=f"actions[{index}]: Must be an object")
        try:
            action_type = InputValidator.validate_string(
                str(action.get("type") or ""),
                f"actions[{index}].type",
                max_length=100,
                allow_empty=False,
                pattern=r"^[A-Za-z0-9_:-]+$",
            ).upper()
        except ValidationError as exc:
            raise _bad_request(exc) from exc
        if action_type not in ALLOWED_ACTION_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"actions[{index}].type: Unsupported action type",
            )
        safe_action = dict(action)
        safe_action["type"] = action_type

        integration_id = safe_action.get("integration_id")
        if integration_id:
            safe_action["integration_id"] = _validate_uuid(str(integration_id), f"actions[{index}].integration_id")

        if action_type == "WEBHOOK":
            url = safe_action.get("url")
            if not url:
                raise HTTPException(status_code=400, detail=f"actions[{index}].url: Required for WEBHOOK")
            try:
                validate_integration_destination_config("webhook", {"url": str(url)})
            except IntegrationDestinationError as exc:
                raise HTTPException(
                    status_code=400,
                    detail={"message": "Playbook action destination blocked", "reason": str(exc)},
                ) from exc

        if action_type == "CREATE_TICKET" and isinstance(safe_action.get("config"), dict):
            system = str(safe_action.get("system") or "jira").lower()
            if system == "jira":
                try:
                    validate_integration_destination_config("jira", safe_action["config"])
                except IntegrationDestinationError as exc:
                    raise HTTPException(
                        status_code=400,
                        detail={"message": "Playbook action destination blocked", "reason": str(exc)},
                    ) from exc
        validated.append(safe_action)
    return validated


def _serialize_playbook(playbook: ResponsePlaybook) -> dict[str, Any]:
    return {
        "id": playbook.id,
        "name": playbook.name,
        "trigger": playbook.trigger,
        "severity_threshold": playbook.severity_threshold,
        "enabled": playbook.enabled,
        "actions": PlaybookActionSecretCodec.redact_actions(playbook.actions),
        "created_at": playbook.created_at,
    }


def _serialize_action_log(row: ResponseActionLog) -> dict[str, Any]:
    return {
        "id": row.id,
        "playbook_id": row.playbook_id,
        "alert_id": row.alert_id,
        "action_type": row.action_type,
        "status": row.status,
        "details": Redactor.redact_json(row.details or {}),
        "created_at": row.created_at,
    }


@router.get("/")
async def list_playbooks(
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_READ)),
):
    account_id = payload.get("account_id")
    result = await db.execute(select(ResponsePlaybook).where(ResponsePlaybook.account_id == account_id))
    items = result.scalars().all()
    return {"total": len(items), "playbooks": [_serialize_playbook(item) for item in items]}


@router.post("/")
async def create_playbook(
    name: str = Body(...),
    trigger: str = Body(default="alert.created"),
    severity_threshold: str = Body(default="MEDIUM"),
    enabled: bool = Body(default=True),
    actions: List[dict] = Body(default=[]),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    account_id = payload.get("account_id")
    validated_actions = _validate_actions(actions)
    playbook = ResponsePlaybook(
        id=str(uuid.uuid4()),
        account_id=account_id,
        name=_validate_name(name),
        trigger=_validate_trigger(trigger),
        severity_threshold=_validate_severity(severity_threshold),
        enabled=enabled,
        actions=PlaybookActionSecretCodec.encrypt_actions(validated_actions),
    )
    db.add(playbook)
    await db.commit()
    await db.refresh(playbook)
    return {"id": playbook.id, "status": "created", "playbook": _serialize_playbook(playbook)}


@router.get("/actions/logs")
async def list_action_logs(
    playbook_id: str | None = Query(None),
    alert_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_READ)),
):
    account_id = payload.get("account_id")
    query = select(ResponseActionLog).where(ResponseActionLog.account_id == account_id)
    if playbook_id:
        query = query.where(ResponseActionLog.playbook_id == _validate_uuid(playbook_id, "playbook_id"))
    if alert_id:
        query = query.where(ResponseActionLog.alert_id == _validate_uuid(alert_id, "alert_id"))
    query = query.order_by(ResponseActionLog.created_at.desc()).limit(limit)
    result = await db.execute(query)
    rows = result.scalars().all()
    return {"total": len(rows), "logs": [_serialize_action_log(row) for row in rows]}


@router.get("/{playbook_id}")
async def get_playbook(
    playbook_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_READ)),
):
    account_id = payload.get("account_id")
    validated_playbook_id = _validate_uuid(playbook_id, "playbook_id")
    result = await db.execute(
        select(ResponsePlaybook).where(
            and_(ResponsePlaybook.id == validated_playbook_id, ResponsePlaybook.account_id == account_id)
        )
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    return _serialize_playbook(playbook)


@router.patch("/{playbook_id}")
async def update_playbook(
    playbook_id: str,
    name: Optional[str] = Body(None),
    trigger: Optional[str] = Body(None),
    severity_threshold: Optional[str] = Body(None),
    enabled: Optional[bool] = Body(None),
    actions: Optional[List[dict]] = Body(None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    account_id = payload.get("account_id")
    validated_playbook_id = _validate_uuid(playbook_id, "playbook_id")
    updates: dict[str, Any] = {}
    if name is not None:
        updates["name"] = _validate_name(name)
    if trigger is not None:
        updates["trigger"] = _validate_trigger(trigger)
    if severity_threshold is not None:
        updates["severity_threshold"] = _validate_severity(severity_threshold)
    if enabled is not None:
        updates["enabled"] = enabled
    if actions is not None:
        updates["actions"] = PlaybookActionSecretCodec.encrypt_actions(_validate_actions(actions))
    if not updates:
        raise HTTPException(400, "No updates provided")

    result = await db.execute(
        select(ResponsePlaybook).where(
            and_(ResponsePlaybook.id == validated_playbook_id, ResponsePlaybook.account_id == account_id)
        )
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    for key, value in updates.items():
        setattr(playbook, key, value)
    await db.commit()
    await db.refresh(playbook)
    return {"id": playbook.id, "updated": list(updates.keys()), "playbook": _serialize_playbook(playbook)}


@router.delete("/{playbook_id}")
async def delete_playbook(
    playbook_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    account_id = payload.get("account_id")
    validated_playbook_id = _validate_uuid(playbook_id, "playbook_id")
    result = await db.execute(
        select(ResponsePlaybook).where(
            and_(ResponsePlaybook.id == validated_playbook_id, ResponsePlaybook.account_id == account_id)
        )
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    await db.delete(playbook)
    await db.commit()
    return {"deleted": validated_playbook_id}
