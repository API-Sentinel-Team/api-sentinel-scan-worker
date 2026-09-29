"""Storage and archival endpoints."""
import os
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.auth.rbac import Permission, RBAC
from server.modules.persistence.database import get_db
from server.modules.storage.archiver import archive_once
from server.config import settings

router = APIRouter(tags=["Storage"])


@router.post("/archive")
async def run_archive(
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
):
    account_id = payload.get("account_id")
    return await archive_once(account_id)


@router.get("/archives")
async def list_archives(
    payload: dict = Depends(RBAC.require_permission(Permission.AUDIT_READ)),
):
    account_id = payload.get("account_id")
    base = os.path.join(settings.ARCHIVE_DIR, f"account_{account_id}")
    results = []
    if not os.path.isdir(base):
        return {"total": 0, "archives": []}
    for root, _, files in os.walk(base):
        for f in files:
            if f.endswith(".jsonl.gz"):
                path = os.path.join(root, f)
                relative_path = os.path.relpath(path, settings.ARCHIVE_DIR).replace(os.sep, "/")
                results.append({"path": relative_path, "size": os.path.getsize(path)})
    return {"total": len(results), "archives": results}
