"""Sensor management - register log-shipper agents, heartbeat, status monitoring."""

import datetime
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import Sensor
from server.modules.auth.rbac import Permission, RBAC, require_admin
from server.modules.persistence.database import AsyncSessionLocal, get_db
from server.modules.sensors.keys import generate_sensor_key, hash_sensor_key, resolve_sensor_by_key

router = APIRouter()
OFFLINE_SECS = 120


class SensorRegister(BaseModel):
    name: str
    host: str | None = None
    log_path: str | None = "/var/log/nginx/access.log"
    version: str | None = "1.0.0"


class HeartbeatBody(BaseModel):
    lines_shipped: int | None = None
    events_detected: int | None = None


def _sensor_key_from_request(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip() or None
    return (
        request.headers.get("x-sensor-key", "").strip()
        or request.headers.get("x-api-key", "").strip()
        or None
    )


async def _resolve_sensor_from_request(request: Request, db: AsyncSession) -> Sensor:
    sensor_key = _sensor_key_from_request(request)
    if not sensor_key:
        raise HTTPException(status_code=401, detail="Sensor key required")
    sensor = await resolve_sensor_by_key(db, sensor_key)
    if not sensor:
        raise HTTPException(status_code=401, detail="Invalid sensor key")
    return sensor


def _apply_heartbeat(sensor: Sensor, body: HeartbeatBody) -> None:
    sensor.status = "ONLINE"
    sensor.last_heartbeat = datetime.datetime.now(datetime.timezone.utc)
    if body.lines_shipped is not None:
        sensor.lines_shipped = body.lines_shipped
    if body.events_detected is not None:
        sensor.events_detected = body.events_detected


async def _mark_stale_offline(db: AsyncSession, account_id: int) -> None:
    """Mark sensors OFFLINE if no heartbeat arrived within OFFLINE_SECS."""
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=OFFLINE_SECS)
    result = await db.execute(
        select(Sensor).where(
            Sensor.account_id == account_id,
            Sensor.status == "ONLINE",
            Sensor.last_heartbeat < cutoff,
        )
    )
    stale = result.scalars().all()
    for sensor in stale:
        sensor.status = "OFFLINE"
    if stale:
        await db.commit()


async def _mark_stale_offline_for_account(account_id: int) -> None:
    async with AsyncSessionLocal() as db:
        await _mark_stale_offline(db, account_id)


@router.get("/")
async def list_sensors(
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    await _mark_stale_offline(db, account_id)
    result = await db.execute(
        select(Sensor).where(Sensor.account_id == account_id).order_by(Sensor.created_at.desc())
    )
    rows = result.scalars().all()
    return [_serialize(row) for row in rows]


@router.get("/summary")
async def sensor_summary(
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    await _mark_stale_offline(db, account_id)
    result = await db.execute(select(Sensor).where(Sensor.account_id == account_id))
    rows = result.scalars().all()
    return {
        "total": len(rows),
        "online": sum(1 for row in rows if row.status == "ONLINE"),
        "offline": sum(1 for row in rows if row.status == "OFFLINE"),
        "degraded": sum(1 for row in rows if row.status == "DEGRADED"),
        "total_lines": sum(row.lines_shipped for row in rows),
        "total_events": sum(row.events_detected for row in rows),
    }


@router.post("/register")
async def register_sensor(
    body: SensorRegister,
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    sensor_key = generate_sensor_key()
    sensor = Sensor(
        id=str(uuid.uuid4()),
        account_id=account_id,
        name=body.name,
        host=body.host,
        log_path=body.log_path,
        version=body.version,
        sensor_key=hash_sensor_key(sensor_key),
        status="OFFLINE",
    )
    db.add(sensor)
    await db.commit()
    await db.refresh(sensor)
    return {
        "sensor_id": sensor.id,
        "sensor_key": sensor_key,
        "ingest_url": "/api/stream/ingest",
        "heartbeat_url": "/api/sensors/heartbeat",
        "status_url": "/api/sensors/status",
        "usage": (
            f"python log_shipper.py --key {sensor_key} "
            f"--log {body.log_path} --endpoint http://YOUR_SOC_HOST/api/stream/ingest"
        ),
    }


@router.post("/heartbeat")
async def heartbeat_with_header(
    body: HeartbeatBody,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    sensor = await _resolve_sensor_from_request(request, db)
    _apply_heartbeat(sensor, body)

    await db.commit()
    background_tasks.add_task(_mark_stale_offline_for_account, sensor.account_id)
    return {"status": "ok", "sensor_id": sensor.id}


@router.post("/{sensor_key}/heartbeat")
async def heartbeat(
    sensor_key: str,
    body: HeartbeatBody,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    sensor = await resolve_sensor_by_key(db, sensor_key)
    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor not found")

    _apply_heartbeat(sensor, body)

    await db.commit()
    background_tasks.add_task(_mark_stale_offline_for_account, sensor.account_id)
    return {"status": "ok", "sensor_id": sensor.id}


@router.get("/status")
async def sensor_status_with_header(request: Request, db: AsyncSession = Depends(get_db)):
    sensor = await _resolve_sensor_from_request(request, db)
    return _serialize(sensor)


@router.get("/{sensor_key}/status")
async def sensor_status(sensor_key: str, db: AsyncSession = Depends(get_db)):
    sensor = await resolve_sensor_by_key(db, sensor_key)
    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor not found")
    return _serialize(sensor)


@router.delete("/{sensor_id}")
async def deregister_sensor(
    sensor_id: str,
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(Sensor).where(Sensor.id == sensor_id, Sensor.account_id == account_id)
    )
    sensor = result.scalar_one_or_none()
    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor not found")
    await db.delete(sensor)
    await db.commit()
    return {"status": "deregistered", "id": sensor_id}


def _serialize(sensor: Sensor) -> dict:
    return {
        "id": sensor.id,
        "name": sensor.name,
        "host": sensor.host,
        "log_path": sensor.log_path,
        "version": sensor.version,
        "status": sensor.status,
        "lines_shipped": sensor.lines_shipped,
        "events_detected": sensor.events_detected,
        "last_heartbeat": sensor.last_heartbeat.isoformat() if sensor.last_heartbeat else None,
        "created_at": sensor.created_at.isoformat() if sensor.created_at else None,
    }
