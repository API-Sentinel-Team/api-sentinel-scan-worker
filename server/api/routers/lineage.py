"""API lineage / call-graph router."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.auth.rbac import RBAC
from server.modules.api_inventory.call_graph import api_lineage_graph
from server.modules.persistence.database import get_db

router = APIRouter(tags=["lineage"])


@router.get("/graph")
async def get_lineage_graph(
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    """Return the API call graph (nodes + edges) for the current account."""
    graph = await api_lineage_graph.get_graph(int(payload["account_id"]))
    return graph


@router.get("/paths")
async def get_top_paths(
    limit: int = 20,
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    """Return top N most-traveled API paths for the current account."""
    paths = await api_lineage_graph.get_top_paths(int(payload["account_id"]), limit=min(limit, 100))
    return {"paths": paths, "total": len(paths)}
