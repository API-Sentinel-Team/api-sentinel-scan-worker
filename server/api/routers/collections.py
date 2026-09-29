"""API Collections — group endpoints by host/service."""
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from sqlalchemy.future import select
from sqlalchemy import update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession
from server.modules.persistence.database import get_db
from server.modules.auth.rbac import Permission, RBAC
from server.models.core import APICollection, APIEndpoint, SampleData
from server.modules.parsers.postman import PostmanParser
from server.modules.utils.redactor import Redactor

router = APIRouter()


@router.get("/")
async def list_collections(
    payload: dict = Depends(RBAC.require_permission(Permission.ENDPOINTS_READ)),
    db: AsyncSession = Depends(get_db)
):
    account_id = payload.get("account_id")
    result = await db.execute(select(APICollection).where(APICollection.account_id == account_id))
    collections = result.scalars().all()
    count_result = await db.execute(
        select(APIEndpoint.collection_id, func.count(APIEndpoint.id))
        .where(APIEndpoint.account_id == account_id, APIEndpoint.collection_id.isnot(None))
        .group_by(APIEndpoint.collection_id)
    )
    counts = {row[0]: row[1] for row in count_result.all()}
    return {
        "total": len(collections),
        "collections": [
            _serialize_collection(c, counts.get(c.id, 0))
            for c in collections
        ],
    }


@router.post("/")
async def create_collection(
    name: str = Body(...),
    host: str = Body(None),
    type: str = Body("MIRRORING"),
    payload: dict = Depends(RBAC.require_permission(Permission.ENDPOINTS_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    coll = APICollection(
        account_id=account_id,
        name=Redactor.redact_text(name),
        host=Redactor.redact_text(host or "") if host else None,
        type=type.upper(),
    )
    db.add(coll)
    await db.commit()
    assigned = 0
    if host:
        r = await db.execute(
            update(APIEndpoint)
            .where(APIEndpoint.account_id == account_id, APIEndpoint.host == host, APIEndpoint.collection_id.is_(None))
            .values(collection_id=coll.id)
        )
        assigned = r.rowcount or 0
        await db.commit()
    return {"status": "created", "id": coll.id, "name": coll.name, "auto_assigned_endpoints": assigned}


@router.get("/{coll_id}/endpoints")
async def get_collection_endpoints(
    coll_id: str,
    limit: int = Query(200),
    payload: dict = Depends(RBAC.require_permission(Permission.ENDPOINTS_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    collection = await _get_collection(db, account_id, coll_id)
    result = await db.execute(
        select(APIEndpoint)
        .where(APIEndpoint.account_id == account_id, APIEndpoint.collection_id == collection.id)
        .limit(limit)
    )
    endpoints = result.scalars().all()
    return {
        "collection_id": coll_id,
        "total": len(endpoints),
        "endpoints": [_serialize_endpoint(endpoint) for endpoint in endpoints],
    }


@router.post("/{coll_id}/add-endpoint/{ep_id}")
async def add_to_collection(
    coll_id: str,
    ep_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.ENDPOINTS_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    collection = await _get_collection(db, account_id, coll_id)
    result = await db.execute(select(APIEndpoint).where(APIEndpoint.id == ep_id, APIEndpoint.account_id == account_id))
    ep = result.scalar_one_or_none()
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    ep.collection_id = collection.id
    await db.commit()
    return {"status": "added", "endpoint_id": ep_id, "collection_id": coll_id}


@router.delete("/{coll_id}")
async def delete_collection(
    coll_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.ENDPOINTS_DELETE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    collection = await _get_collection(db, account_id, coll_id)
    await db.execute(
        update(APIEndpoint)
        .where(APIEndpoint.account_id == account_id, APIEndpoint.collection_id == collection.id)
        .values(collection_id=None)
    )
    await db.execute(delete(APICollection).where(APICollection.id == collection.id, APICollection.account_id == account_id))
    await db.commit()
    return {"status": "deleted", "id": coll_id}


@router.post("/postman-import")
async def import_postman_collection(
    collection_json: str = Body(..., media_type="application/json"),
    payload: dict = Depends(RBAC.require_permission(Permission.ENDPOINTS_WRITE)),
    db: AsyncSession = Depends(get_db)
):
    account_id = payload.get("account_id")
    try:
        parser = PostmanParser(collection_json)
        requests = parser.fetch_apis_recursively()
        
        # Create a default collection for this import if one doesn't exist
        collection_name = parser.data.get("info", {}).get("name", "Postman Import")
        coll = APICollection(account_id=account_id, name=Redactor.redact_text(collection_name), type="POSTMAN")
        db.add(coll)
        await db.commit()
        await db.refresh(coll)
        
        imported_count = 0
        for item in requests:
            endpoint_meta, sample_data = parser.convert_to_akto_format(item)
            
            # Save Endpoint
            ep = APIEndpoint(
                account_id=account_id,
                collection_id=coll.id,
                method=endpoint_meta["method"],
                path=Redactor.redact_text(endpoint_meta["path"]),
                api_type=endpoint_meta["api_type"]
            )
            db.add(ep)
            await db.commit()
            await db.refresh(ep)
            
            # Save Sample Data
            sample = SampleData(
                endpoint_id=ep.id,
                request=sample_data["request"],
                response=sample_data["response"]
            )
            db.add(sample)
            imported_count += 1
            
        await db.commit()
        return {"status": "success", "collection_id": coll.id, "imported_endpoints": imported_count}
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to parse Postman collection: {Redactor.redact_text(str(e))}")


async def _get_collection(db: AsyncSession, account_id: int, coll_id: str) -> APICollection:
    result = await db.execute(
        select(APICollection).where(APICollection.id == coll_id, APICollection.account_id == account_id)
    )
    collection = result.scalar_one_or_none()
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    return collection


def _serialize_collection(collection: APICollection, endpoint_count: int) -> dict:
    return {
        "id": collection.id,
        "name": Redactor.redact_text(collection.name or ""),
        "host": Redactor.redact_text(collection.host or "") if collection.host else None,
        "type": collection.type,
        "endpoint_count": endpoint_count,
        "created_at": str(collection.created_at),
    }


def _serialize_endpoint(endpoint: APIEndpoint) -> dict:
    return {
        "id": endpoint.id,
        "method": endpoint.method,
        "path": Redactor.redact_text(endpoint.path or "") if endpoint.path else None,
        "host": Redactor.redact_text(endpoint.host or "") if endpoint.host else None,
        "last_response_code": endpoint.last_response_code,
    }
