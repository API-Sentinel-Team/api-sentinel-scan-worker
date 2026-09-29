"""Evidence API for policy, PII, and threat artifacts."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from server.models.core import EvidenceRecord
from server.modules.auth.rbac import Permission, RBAC
from server.modules.persistence.database import get_read_db
from server.modules.utils.redactor import Redactor
from server.modules.validation.input_validator import InputValidator, ValidationError

router = APIRouter()


def _validate_optional_uuid(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    try:
        return InputValidator.validate_uuid(value, field_name)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _validate_optional_filter(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    try:
        return InputValidator.validate_string(
            value,
            field_name,
            max_length=50,
            allow_empty=False,
            pattern=r"^[A-Za-z0-9_.:-]+$",
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _serialize_evidence_record(record: EvidenceRecord) -> dict:
    return {
        "id": record.id,
        "type": record.evidence_type,
        "endpoint_id": record.endpoint_id,
        "severity": record.severity,
        "summary": Redactor.redact_text(record.summary or "") if record.summary else None,
        "details": _redacted_evidence_details(record.details),
        "created_at": str(record.created_at),
    }


def _redacted_evidence_details(details: Any) -> Any:
    if details is None:
        return None
    redacted = Redactor.redact_json(details)
    if isinstance(details, dict) and isinstance(redacted, dict):
        scan_redacted = Redactor.redact_scan_result(details)
        safety_policies = scan_redacted.get("safety_policies")
        if isinstance(safety_policies, dict):
            redacted["safety_policies"] = safety_policies
    return redacted


@router.get("")
@router.get("/")
async def list_evidence(
    endpoint_id: str | None = Query(None),
    evidence_type: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
):
    account_id = payload.get("account_id")
    endpoint_id = _validate_optional_uuid(endpoint_id, "endpoint_id")
    evidence_type = _validate_optional_filter(evidence_type, "evidence_type")
    filters = [EvidenceRecord.account_id == account_id]
    if endpoint_id:
        filters.append(EvidenceRecord.endpoint_id == endpoint_id)
    if evidence_type:
        filters.append(EvidenceRecord.evidence_type == evidence_type)

    result = await db.execute(
        select(EvidenceRecord)
        .where(and_(*filters))
        .order_by(EvidenceRecord.created_at.desc())
        .limit(limit)
    )
    records = result.scalars().all()
    return {
        "total": len(records),
        "evidence": [_serialize_evidence_record(record) for record in records],
    }
