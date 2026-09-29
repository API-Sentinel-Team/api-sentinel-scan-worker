"""Business logic graph APIs."""
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from server.modules.auth.rbac import Permission, RBAC
from server.modules.persistence.database import get_db, get_read_db
from server.modules.business_logic.graph_builder import build_graph, get_latest_graph
from server.modules.utils.redactor import Redactor
from server.models.core import BusinessLogicViolation

router = APIRouter(tags=["Business Logic"])


@router.post("/rebuild")
async def rebuild_graph(
    request: Request,
    window_days: int = Query(14, ge=1, le=90),
    min_transitions: int = Query(3, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
):
    account_id = payload.get("account_id")
    graph = await build_graph(db, account_id, window_days=window_days, min_transitions=min_transitions)
    await db.commit()
    return {"graph_id": graph.id, "version": graph.version, "nodes": len(graph.nodes_json), "edges": len(graph.edges_json)}


@router.get("/graph/latest")
async def latest_graph(
    request: Request,
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_permission(Permission.COMPLIANCE_READ)),
):
    account_id = payload.get("account_id")
    graph = await get_latest_graph(db, account_id)
    if not graph:
        raise HTTPException(status_code=404, detail="No graph available")
    return {
        "id": graph.id,
        "version": graph.version,
        "built_at": str(graph.built_at),
        "nodes": Redactor.redact_json(graph.nodes_json or []),
        "edges": Redactor.redact_json(graph.edges_json or []),
    }


@router.get("/violations")
async def list_violations(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_permission(Permission.COMPLIANCE_READ)),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(BusinessLogicViolation)
        .where(BusinessLogicViolation.account_id == account_id)
        .order_by(BusinessLogicViolation.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return {
        "total": len(rows),
        "violations": [_serialize_violation(v) for v in rows],
    }


def _serialize_violation(violation: BusinessLogicViolation) -> dict:
    return {
        "id": violation.id,
        "actor_id": Redactor.redact_text(violation.actor_id or "") if violation.actor_id else None,
        "from_path": Redactor.redact_text(violation.from_path or "") if violation.from_path else None,
        "to_path": Redactor.redact_text(violation.to_path or "") if violation.to_path else None,
        "type": violation.violation_type,
        "confidence": violation.confidence,
        "created_at": str(violation.created_at),
    }
