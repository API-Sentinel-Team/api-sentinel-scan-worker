"""Agentic MCP telemetry APIs."""
from fastapi import APIRouter, Depends, Body, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from server.modules.auth.rbac import Permission, RBAC
from server.modules.persistence.database import get_db, get_read_db
from server.modules.agentic.mcp_security import record_tool_invocation
from server.models.core import AgentIdentity, MCPToolInvocation, AgenticViolation
from server.modules.utils.redactor import Redactor

router = APIRouter(tags=["Agentic"])


@router.post("/invocations")
async def ingest_invocation(
    agent_id: str = Body(...),
    tool_name: str = Body(...),
    parameters: dict = Body(default={}),
    result_text: str = Body(default=""),
    declared_scope: list = Body(default=[]),
    effective_scope: list = Body(default=[]),
    parent_agent_id: str | None = Body(default=None),
    human_principal: str | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_INSPECT)),
):
    account_id = payload.get("account_id")
    await record_tool_invocation(
        db=db,
        account_id=account_id,
        agent_id=agent_id,
        tool_name=tool_name,
        parameters=parameters,
        result_text=result_text,
        declared_scope=declared_scope,
        effective_scope=effective_scope,
        parent_agent_id=parent_agent_id,
        human_principal=human_principal,
    )
    await db.commit()
    return {"status": "recorded"}


@router.get("/identities")
async def list_identities(
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_READ)),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(AgentIdentity)
        .where(AgentIdentity.account_id == account_id)
        .order_by(AgentIdentity.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return {
        "total": len(rows),
        "identities": [
            {
                "agent_id": r.agent_id,
                "agent_type": r.agent_type,
                "parent_agent_id": r.parent_agent_id,
                "declared_scope": Redactor.redact_json(r.declared_scope or []),
                "effective_scope": Redactor.redact_json(r.effective_scope or []),
                "human_principal": Redactor.redact_text(r.human_principal or ""),
                "created_at": str(r.created_at),
            }
            for r in rows
        ],
    }


@router.get("/invocations")
async def list_invocations(
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_READ)),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(MCPToolInvocation)
        .where(MCPToolInvocation.account_id == account_id)
        .order_by(MCPToolInvocation.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return {
        "total": len(rows),
        "invocations": [
            {
                "agent_id": r.agent_id,
                "tool_name": r.tool_name,
                "parameters": Redactor.redact_json(r.parameters or {}),
                "status": r.status,
                "created_at": str(r.created_at),
            }
            for r in rows
        ],
    }


@router.get("/violations")
async def list_violations(
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_READ)),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(AgenticViolation)
        .where(AgenticViolation.account_id == account_id)
        .order_by(AgenticViolation.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return {
        "total": len(rows),
        "violations": [
            {
                "agent_id": r.agent_id,
                "type": r.violation_type,
                "severity": r.severity,
                "details": Redactor.redact_json(r.details or {}),
                "created_at": str(r.created_at),
            }
            for r in rows
        ],
    }
