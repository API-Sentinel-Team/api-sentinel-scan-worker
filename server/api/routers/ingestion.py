"""Ingestion status + job tracking endpoints."""
import datetime
import re
import uuid
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.rate_limiter import limiter
from server.api.websocket.manager import ws_manager
from server.models.core import Alert, APICollection, APIEndpoint, IngestionJob, MaliciousEventRecord, RequestLog, Sensor, ThreatActor
from server.modules.api_inventory.path_normalizer import PathNormalizer

_path_normalizer = PathNormalizer()


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _datetime_from_sensor_ts(ts_raw: Any | None) -> datetime.datetime:
    if ts_raw is None:
        return _utc_now()
    ts_int = int(ts_raw)
    seconds = ts_int / 1000 if ts_int > 9_999_999_999 else ts_int
    return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)


async def _upsert_endpoint(db, account_id: int, method: str, path: str, host: str,
                            protocol: str, status: int, ts):
    """Auto-discover API endpoint from traffic — upsert by (account, method, path_pattern)."""
    clean_path = path.split('?')[0]
    if any(c in clean_path for c in ['<', '>', "'", '"', '..']):
        return  # skip attack/noise paths
    pattern = _path_normalizer.normalize(clean_path)

    res = await db.execute(
        select(APIEndpoint).where(
            APIEndpoint.account_id == account_id,
            APIEndpoint.method == method,
            APIEndpoint.path_pattern == pattern,
        )
    )
    ep = res.scalar_one_or_none()
    if ep:
        ep.last_seen = ts
        ep.last_response_code = status
    else:
        # Get or create default collection
        col_res = await db.execute(
            select(APICollection).where(
                APICollection.account_id == account_id,
                APICollection.name == "Default Inventory",
            )
        )
        col = col_res.scalar_one_or_none()
        if not col:
            col = APICollection(account_id=account_id, name="Default Inventory", host="all-hosts", type="MIRRORING")
            db.add(col)
            await db.flush()

        db.add(APIEndpoint(
            account_id=account_id,
            collection_id=col.id,
            method=method,
            path=clean_path,
            path_pattern=pattern,
            host=host or "unknown",
            protocol=protocol or "HTTP/1.1",
            last_response_code=status,
            last_seen=ts,
            status="ACTIVE",
            api_type="REST",
        ))
from server.modules.auth.rbac import RBAC
from server.modules.ingestion.queue import ingestion_queue
from server.modules.persistence.database import get_read_db
from server.modules.quotas.tenant_quota import peek_ingest_quota, check_ingest_quota
from server.config import settings
from server.modules.ingestion.schema import EventBatch, APITrafficEvent
from server.modules.ingestion.queue import IngestionJobItem
from server.modules.persistence.database import get_db
from server.modules.auth.audit import log_action
from server.modules.detection.pipeline import unified_detection_pipeline
from server.modules.ingestion.redaction import redact_ingestion_path
from server.modules.sensors.keys import resolve_sensor_by_key

# ── Shared attack signatures (same as stream router) ─────────────────────────
_ATTACK_SIGS = [
    (re.compile(r"union\s+select|drop\s+table|insert\s+into|or\s+'1'\s*=\s*'1|;\s*--", re.I), "SQL Injection", "HIGH"),
    (re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(", re.I), "XSS", "HIGH"),
    (re.compile(r"\.\./|%2e%2e%2f|%252e%252e", re.I), "Path Traversal", "MEDIUM"),
    (re.compile(r"\$\{jndi:|log4j", re.I), "Log4Shell", "CRITICAL"),
    (re.compile(r"etc/passwd|etc/shadow|/proc/self", re.I), "LFI", "HIGH"),
    (re.compile(r"cmd\.exe|powershell|/bin/sh|/bin/bash", re.I), "Command Injection", "CRITICAL"),
    (re.compile(r"sleep\s*\(\d+\)|benchmark\s*\(", re.I), "Blind SQLi", "HIGH"),
    (re.compile(r"base64_decode\s*\(|eval\s*\(|exec\s*\(", re.I), "Code Injection", "CRITICAL"),
    (re.compile(r"x-forwarded-for.*127\.0\.0\.1|localhost", re.I), "SSRF", "MEDIUM"),
    (re.compile(r"\.xml|xxe|<!entity", re.I), "XXE", "HIGH"),
]

SEV_SCORE = {"CRITICAL": 1.0, "HIGH": 0.5, "MEDIUM": 0.1, "LOW": 0.05}


async def _resolve_sensor_auth(request: Request, db: AsyncSession):
    """
    Try to resolve a sensor API key from the request.
    Checks: Authorization: Bearer <key>, X-API-Key: <key>
    Returns (sensor, account_id) or (None, None).
    """
    key = None
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        key = auth[7:].strip()
    if not key:
        key = request.headers.get("x-api-key", "").strip() or None

    if not key:
        return None, None

    sensor = await resolve_sensor_by_key(db, key)
    if sensor:
        return sensor, sensor.account_id
    return None, None

router = APIRouter()


@router.post("/v2/heartbeat")
@limiter.limit("120/minute")
async def sensor_heartbeat(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Lightweight heartbeat endpoint — sensor pings this every 30 s.
    Updates last_heartbeat + status=ONLINE so dashboard stays green
    even when no traffic is captured.
    Accepts: X-API-Key: <sensor_key>  or  Authorization: Bearer <sensor_key>
    Body (optional): {"metrics": {"events_captured": N, "drops": N, "uptime_s": N}}
    """
    sensor, account_id = await _resolve_sensor_auth(request, db)
    if not sensor:
        raise HTTPException(status_code=401, detail="Invalid sensor API key")

    body: dict = {}
    try:
        body = await request.json()
    except Exception:
        pass

    sensor.last_heartbeat = _utc_now()
    sensor.status = "ONLINE"

    metrics = body.get("metrics", {})
    if "events_captured" in metrics:
        sensor.lines_shipped = metrics["events_captured"]

    await db.commit()
    return {"status": "ok", "sensor": sensor.name}


@router.get("/status")
@limiter.limit("60/minute")
async def get_ingestion_status(
    request: Request,
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    quota = await peek_ingest_quota(account_id)

    recent = await db.execute(
        select(IngestionJob)
        .where(IngestionJob.account_id == account_id)
        .order_by(IngestionJob.created_at.desc())
        .limit(5)
    )
    jobs = recent.scalars().all()

    return {
        "queue": {
            "size": ingestion_queue.size(),
            "max_size": ingestion_queue.max_size(),
        },
        "quota": {
            "limit_per_minute": settings.INGESTION_RATE_LIMIT_RPM,
            "used": max(0, settings.INGESTION_RATE_LIMIT_RPM - quota.remaining),
            "remaining": quota.remaining,
            "reset_at": quota.reset_at,
        },
        "recent_jobs": [
            {
                "id": j.id,
                "type": j.job_type,
                "status": j.status,
                "accepted": j.accepted_count,
                "processed": j.processed_count,
                "threats_detected": j.threats_detected,
                "created_at": str(j.created_at),
            }
            for j in jobs
        ],
    }


@router.get("/jobs/{job_id}")
@limiter.limit("120/minute")
async def get_ingestion_job(
    request: Request,
    job_id: str,
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(IngestionJob).where(
            IngestionJob.id == job_id,
            IngestionJob.account_id == account_id,
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": job.id,
        "type": job.job_type,
        "status": job.status,
        "accepted": job.accepted_count,
        "processed": job.processed_count,
        "threats_detected": job.threats_detected,
        "error_count": job.error_count,
        "error_message": job.error_message,
        "created_at": str(job.created_at),
        "started_at": str(job.started_at) if job.started_at else None,
        "completed_at": str(job.completed_at) if job.completed_at else None,
    }


@router.post("/v2/events")
@limiter.limit("120/minute")
async def ingest_events_v2(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Canonical event ingestion (v2).

    Accepts two authentication modes:
      1. JWT (dashboard users)  — Authorization: Bearer <jwt>
      2. Sensor API key         — Authorization: Bearer <sensor_key>  or  X-API-Key: <sensor_key>

    Accepts two event formats:
      A. Sensor flat format (eBPF sensor native):
           {"version":"v1","events":[{"ts":...,"src_ip":...,"method":...,"path":...,...}]}
      B. Structured EventBatch (existing schema):
           {"version":"v1","events":[{"event_type":"api_traffic","account_id":...,"request":{...},...}]}

    Flat-format events are processed synchronously with attack detection + WS broadcast.
    Structured EventBatch events are queued for async processing (existing behaviour).
    """
    body: Any = await request.json()
    raw_events: list = body.get("events", [])
    schema_version: str = body.get("version", "v1")

    if not raw_events:
        raise HTTPException(status_code=400, detail="No events provided")
    if len(raw_events) > settings.INGESTION_MAX_EVENTS:
        raise HTTPException(status_code=413, detail="Too many events in one batch")

    # ── Authenticate: sensor key first, fall back to JWT ─────────────────────
    sensor, sensor_account_id = await _resolve_sensor_auth(request, db)
    jwt_payload: dict | None = None
    account_id: int

    if sensor:
        account_id = sensor_account_id
    else:
        # Try JWT
        try:
            jwt_payload = await RBAC.require_auth(request)
            account_id = jwt_payload.get("account_id")
        except HTTPException:
            raise HTTPException(status_code=401, detail="Invalid credentials — provide JWT or sensor API key")

    quota = await check_ingest_quota(account_id, cost=len(raw_events))
    if not quota.allowed:
        raise HTTPException(status_code=429, detail="Ingestion rate limit exceeded")

    # ── Detect format: flat (sensor) vs structured (EventBatch) ──────────────
    first = raw_events[0] if raw_events else {}
    is_sensor_flat = "event_type" not in first  # structured always has event_type

    if is_sensor_flat:
        # ── SENSOR FLAT FORMAT — process inline with attack detection ─────────
        if sensor:
            sensor.last_heartbeat = _utc_now()
            sensor.lines_shipped = (sensor.lines_shipped or 0) + len(raw_events)
            sensor.status = "ONLINE"

        pipeline_mode = unified_detection_pipeline.mode()
        threats_detected = 0
        ws_batch = []
        new_actors: dict[str, ThreatActor] = {}

        for ev in raw_events:
            req  = ev.get("request")  or {}
            resp = ev.get("response") or {}
            method    = (req.get("method")  or ev.get("method")  or "GET").upper()
            path      = req.get("path")     or ev.get("path")     or "/"
            safe_path = redact_ingestion_path(path)
            host      = req.get("host")     or ev.get("host")     or ""
            headers   = req.get("headers")  or ev.get("headers")  or {}
            status    = int(resp.get("status") or ev.get("status_code") or ev.get("status") or 0)
            source_ip = ev.get("source_ip") or ev.get("src_ip")   or ""
            protocol  = ev.get("protocol")  or "HTTP/1.1"
            container = ev.get("container") or {}
            has_inj   = ev.get("has_injection", False)
            dest_port = ev.get("dest_port")  or ev.get("dst_port") or 443

            ts_raw = ev.get("observed_at") or ev.get("ts")
            ts = _datetime_from_sensor_ts(ts_raw)

            await _upsert_endpoint(db, account_id, method, path, host, protocol, status, ts)
            attacks = []
            if pipeline_mode == "active":
                result = await unified_detection_pipeline.process(
                    db,
                    account_id=account_id,
                    source_type="sensor_flat",
                    raw_event=ev,
                    persist_request_log=True,
                    context_source="EBPF_SENSOR",
                )
                attacks = [
                    {"category": signal.category, "severity": signal.severity}
                    for signal in result["signals"]
                ]
                threats_detected += len(attacks)
            else:
                if pipeline_mode == "shadow":
                    await unified_detection_pipeline.process(
                        db,
                        account_id=account_id,
                        source_type="sensor_flat",
                        raw_event=ev,
                        persist_request_log=False,
                        context_source="EBPF_SENSOR",
                        shadow=True,
                    )

                log = RequestLog(
                    account_id=account_id,
                    source_ip=source_ip,
                    method=method,
                    path=safe_path,
                    response_code=status,
                    created_at=ts,
                )
                db.add(log)

                # If sensor already flagged injection, trust it; otherwise run local sigs
                if has_inj:
                    attacks.append({"category": "Injection (Sensor)", "severity": "HIGH"})
                target = path + " " + headers.get("user-agent", "")
                for pattern, cat, sev in _ATTACK_SIGS:
                    if pattern.search(target):
                        attacks.append({"category": cat, "severity": sev})

                for atk in attacks:
                    threats_detected += 1
                    cat, sev = atk["category"], atk["severity"]
                    score_inc = SEV_SCORE.get(sev, 0.1)

                    db.add(MaliciousEventRecord(
                        account_id=account_id,
                        ip=source_ip,
                        actor=source_ip,
                        url=f"{host}{safe_path}",
                        method=method,
                        category=cat,
                        severity=sev,
                        status="OPEN",
                        context_source="EBPF_SENSOR",
                        detected_at=int(ts.timestamp() * 1000),
                    ))

                    if source_ip in new_actors:
                        ta = new_actors[source_ip]
                        ta.event_count = (ta.event_count or 0) + 1
                        ta.risk_score  = min(10.0, (ta.risk_score or 0) + score_inc)
                        ta.last_seen   = ts
                    else:
                        ta_res = await db.execute(
                            select(ThreatActor).where(
                                ThreatActor.source_ip == source_ip,
                                ThreatActor.account_id == account_id,
                            )
                        )
                        ta = ta_res.scalar_one_or_none()
                        if ta:
                            ta.event_count = (ta.event_count or 0) + 1
                            ta.risk_score  = min(10.0, (ta.risk_score or 0) + score_inc)
                            ta.last_seen   = ts
                        else:
                            ta = ThreatActor(
                                account_id=account_id,
                                source_ip=source_ip,
                                event_count=1,
                                risk_score=score_inc,
                                status="MONITORING",
                                last_seen=ts,
                            )
                            db.add(ta)
                            new_actors[source_ip] = ta

                    db.add(Alert(
                        account_id=account_id,
                        title=f"{cat} from {source_ip}",
                        message=f"{sev} {cat} on {method} {safe_path}",
                        severity=sev,
                        source_ip=source_ip,
                        endpoint=safe_path,
                        status="OPEN",
                    ))

            ws_batch.append({
                "ip":        source_ip,
                "method":    method,
                "path":      safe_path,
                "status":    status,
                "timestamp": ts.isoformat(),
                "attacks":   attacks,
                "blocked":   False,
                "protocol":  protocol,
                "container": container,
                "dest_port": dest_port,
            })

        await db.commit()
        for entry in ws_batch:
            await ws_manager.broadcast({"type": "log_entry", "data": entry}, account_id=account_id)

        return {
            "status": "ok",
            "events_processed": len(raw_events),
            "threats_detected": threats_detected,
        }

    # ── STRUCTURED EventBatch FORMAT — queue for async processing ─────────────
    try:
        batch = EventBatch.model_validate(body)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid event batch: {e}")

    for ev in batch.events:
        if isinstance(ev, APITrafficEvent) and ev.account_id != account_id:
            raise HTTPException(status_code=403, detail="Event account_id mismatch")

    job_id = str(uuid.uuid4())
    job = IngestionJob(
        id=job_id,
        account_id=account_id,
        job_type="event_batch",
        status="QUEUED",
        accepted_count=len(batch.events),
        job_metadata={"schema_version": batch.version},
    )
    db.add(job)
    await db.commit()

    queued = await ingestion_queue.enqueue(
        IngestionJobItem(
            job_id=job_id,
            account_id=account_id,
            job_type="event_batch",
            payload={"events": [e.model_dump() for e in batch.events]},
        )
    )
    if not queued:
        job.status = "FAILED"
        job.error_message = "Queue full"
        await db.commit()
        raise HTTPException(status_code=429, detail="Ingestion queue is full")

    await log_action(
        db=db,
        account_id=account_id,
        action="INGESTION_V2_ENQUEUED",
        user_id=jwt_payload.get("user_id") if jwt_payload else None,
        resource_type="ingestion_job",
        resource_id=job_id,
        details={"accepted": len(batch.events), "schema_version": batch.version},
    )
    await db.commit()
    return {"status": "queued", "job_id": job_id, "accepted": len(batch.events)}
