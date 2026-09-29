from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.auth.rbac import RBAC
from server.modules.detection.pipeline import unified_detection_pipeline
from server.modules.persistence.database import get_db

router = APIRouter(tags=["Detection Engine"])

_OFFICIAL_REFERENCES = [
    {"name": "FastAPI Middleware", "url": "https://fastapi.tiangolo.com/tutorial/middleware/"},
    {"name": "Starlette Middleware", "url": "https://www.starlette.io/middleware/"},
    {"name": "SQLAlchemy AsyncIO", "url": "https://docs.sqlalchemy.org/20/orm/extensions/asyncio.html"},
    {"name": "Redis INCR", "url": "https://redis.io/docs/latest/commands/incr/"},
    {"name": "Redis EXPIRE", "url": "https://redis.io/docs/latest/commands/expire/"},
    {"name": "PyOD", "url": "https://pyod.readthedocs.io/en/latest/index.html"},
    {"name": "OWASP API Security Top 10 2023", "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"},
]


@router.get("/meta")
async def detection_meta(
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = int(payload.get("account_id") or 0)
    db_ready = False
    try:
        await db.execute(text("SELECT 1"))
        db_ready = True
    except Exception:
        db_ready = False

    data = unified_detection_pipeline.meta()
    data["account_id"] = account_id
    data["health"] = {
        "db_ready": db_ready,
        "pipeline_enabled": data["mode"] in {"shadow", "active"},
        "pipeline_active": data["mode"] == "active",
    }
    data["official_references"] = _OFFICIAL_REFERENCES
    return data
