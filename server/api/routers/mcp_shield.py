"""MCP endpoint shield - protect Model Context Protocol endpoints from abuse."""

import re
import time
import uuid
from collections import defaultdict
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import MCPEndpoint, WAFEvent
from server.modules.auth.rbac import Permission, RBAC
from server.modules.persistence.database import get_db

router = APIRouter(tags=["MCP Shield"])

# In-memory RPM tracker: {endpoint_id: [timestamp, ...]}
_rpm_tracker: dict = defaultdict(list)


def _mcp_transport(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme in {"ws", "wss", "sse"}:
        return "sse"
    if parsed.scheme == "stdio":
        return "stdio"
    return parsed.scheme or "http"


def _mcp_status(endpoint: MCPEndpoint) -> str:
    return "trusted" if endpoint.shield_enabled else "untrusted"


def _mcp_risk_score(endpoint: MCPEndpoint) -> float:
    base = 0.15 if endpoint.shield_enabled else 0.55
    pattern_weight = min(len(endpoint.blocked_patterns or []) * 0.1, 0.25)
    open_scope_weight = 0.1 if not endpoint.allowed_tools else 0.0
    return round(min(base + pattern_weight + open_scope_weight, 0.99), 2)


@router.get("/endpoints")
async def list_mcp_endpoints(
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(select(MCPEndpoint).where(MCPEndpoint.account_id == account_id))
    endpoints = result.scalars().all()
    return {
        "total": len(endpoints),
        "endpoints": [
            {
                "id": endpoint.id,
                "name": endpoint.name,
                "url": endpoint.url,
                "shield_enabled": endpoint.shield_enabled,
                "allowed_tools": endpoint.allowed_tools,
                "blocked_patterns": endpoint.blocked_patterns,
                "rate_limit_rpm": endpoint.rate_limit_rpm,
                "created_at": endpoint.created_at,
            }
            for endpoint in endpoints
        ],
    }


@router.get("/servers")
async def list_mcp_servers(
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(select(MCPEndpoint).where(MCPEndpoint.account_id == account_id))
    endpoints = result.scalars().all()
    return {
        "total": len(endpoints),
        "servers": [
            {
                "server_id": endpoint.id,
                "name": endpoint.name,
                "transport": _mcp_transport(endpoint.url),
                "tool_count": len(endpoint.allowed_tools or []),
                "status": _mcp_status(endpoint),
                "last_seen": endpoint.created_at.isoformat() if endpoint.created_at else None,
                "risk_score": _mcp_risk_score(endpoint),
            }
            for endpoint in endpoints
        ],
    }


@router.post("/endpoints")
async def register_mcp_endpoint(
    name: str = Body(...),
    url: str = Body(...),
    allowed_tools: List[str] = Body(default=[]),
    blocked_patterns: List[str] = Body(default=[]),
    rate_limit_rpm: int = Body(60),
    payload: dict = Depends(RBAC.require_permission(Permission.MCP_SHIELD_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    endpoint = MCPEndpoint(
        id=str(uuid.uuid4()),
        account_id=account_id,
        name=name,
        url=url,
        allowed_tools=allowed_tools,
        blocked_patterns=blocked_patterns,
        rate_limit_rpm=rate_limit_rpm,
    )
    db.add(endpoint)
    await db.commit()
    return {"id": endpoint.id, "name": name, "url": url}


@router.post("/endpoints/{endpoint_id}/inspect")
async def inspect_mcp_request(
    endpoint_id: str,
    tool_name: str = Body(...),
    parameters: dict = Body(default={}),
    source_ip: str = Body("unknown"),
    payload: dict = Depends(RBAC.require_permission(Permission.MCP_SHIELD_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Inspect an MCP tool call for policy violations. Returns ALLOW or BLOCK."""
    account_id = payload["account_id"]
    result = await db.execute(
        select(MCPEndpoint).where(
            MCPEndpoint.id == endpoint_id,
            MCPEndpoint.account_id == account_id,
        )
    )
    endpoint = result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(404, "MCP endpoint not found")

    if not endpoint.shield_enabled:
        return {"action": "ALLOW", "reason": "Shield disabled"}

    now = time.time()
    window = _rpm_tracker[endpoint_id]
    _rpm_tracker[endpoint_id] = [ts for ts in window if now - ts < 60]
    _rpm_tracker[endpoint_id].append(now)
    if len(_rpm_tracker[endpoint_id]) > endpoint.rate_limit_rpm:
        db.add(
            WAFEvent(
                id=str(uuid.uuid4()),
                account_id=account_id,
                source_ip=source_ip,
                endpoint_id=endpoint_id,
                rule_id="MCP_RATE_LIMIT_EXCEEDED",
                action="BLOCKED",
                method="MCP",
                path=f"/mcp/{tool_name}",
                payload_snippet="rate_limit",
                severity="MEDIUM",
            )
        )
        await db.commit()
        return {
            "action": "BLOCK",
            "reason": f"Rate limit exceeded ({endpoint.rate_limit_rpm} rpm)",
            "retry_after_seconds": 60,
        }

    if endpoint.allowed_tools and tool_name not in endpoint.allowed_tools:
        db.add(
            WAFEvent(
                id=str(uuid.uuid4()),
                account_id=account_id,
                source_ip=source_ip,
                endpoint_id=endpoint_id,
                rule_id="MCP_TOOL_NOT_ALLOWED",
                action="BLOCKED",
                method="MCP",
                path=f"/mcp/{tool_name}",
                payload_snippet=str(parameters)[:200],
                severity="HIGH",
            )
        )
        await db.commit()
        return {
            "action": "BLOCK",
            "reason": f"Tool '{tool_name}' not in allowed list",
            "allowed_tools": endpoint.allowed_tools,
        }

    parameter_string = str(parameters)
    for pattern in endpoint.blocked_patterns or []:
        try:
            if re.search(pattern, parameter_string, re.IGNORECASE):
                db.add(
                    WAFEvent(
                        id=str(uuid.uuid4()),
                        account_id=account_id,
                        source_ip=source_ip,
                        endpoint_id=endpoint_id,
                        rule_id="MCP_BLOCKED_PATTERN",
                        action="BLOCKED",
                        method="MCP",
                        path=f"/mcp/{tool_name}",
                        payload_snippet=parameter_string[:200],
                        severity="CRITICAL",
                    )
                )
                await db.commit()
                return {
                    "action": "BLOCK",
                    "reason": f"Parameters match blocked pattern: {pattern}",
                }
        except re.error:
            continue

    return {"action": "ALLOW", "tool_name": tool_name, "endpoint_id": endpoint_id}


@router.patch("/endpoints/{endpoint_id}")
async def update_mcp_endpoint(
    endpoint_id: str,
    shield_enabled: Optional[bool] = Body(None),
    allowed_tools: Optional[List[str]] = Body(None),
    blocked_patterns: Optional[List[str]] = Body(None),
    rate_limit_rpm: Optional[int] = Body(None),
    payload: dict = Depends(RBAC.require_permission(Permission.MCP_SHIELD_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    updates = {}
    if shield_enabled is not None:
        updates["shield_enabled"] = shield_enabled
    if allowed_tools is not None:
        updates["allowed_tools"] = allowed_tools
    if blocked_patterns is not None:
        updates["blocked_patterns"] = blocked_patterns
    if rate_limit_rpm is not None:
        updates["rate_limit_rpm"] = rate_limit_rpm
    if not updates:
        raise HTTPException(400, "No updates provided")

    result = await db.execute(
        update(MCPEndpoint)
        .where(MCPEndpoint.id == endpoint_id, MCPEndpoint.account_id == account_id)
        .values(**updates)
    )
    if not result.rowcount:
        raise HTTPException(404, "MCP endpoint not found")
    await db.commit()
    return {"endpoint_id": endpoint_id, "updated": list(updates.keys())}


@router.delete("/endpoints/{endpoint_id}")
async def delete_mcp_endpoint(
    endpoint_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.MCP_SHIELD_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(MCPEndpoint).where(
            MCPEndpoint.id == endpoint_id,
            MCPEndpoint.account_id == account_id,
        )
    )
    endpoint = result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(404, "Not found")
    await db.delete(endpoint)
    await db.commit()
    return {"deleted": endpoint_id}
