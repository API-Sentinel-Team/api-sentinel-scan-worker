"""Real-time log stream ingestion + WebSocket live feed gateway."""

from __future__ import annotations

import datetime
import gzip
import json
import re
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.websocket.manager import ws_manager
from server.config import settings
from server.models.core import Alert, IngestionJob, MaliciousEventRecord, RequestLog, Sensor, ThreatActor
from server.modules.api_inventory.endpoint_discovery import EndpointDiscovery, inventory_path
from server.modules.auth.audit import log_action
from server.modules.auth.rbac import RBAC
from server.modules.cache.redis_cache import bump_cache_version
from server.modules.detection.pipeline import unified_detection_pipeline
from server.modules.ingestion.queue import IngestionJobItem, ingestion_queue
from server.modules.ingestion.redaction import redact_ingestion_path
from server.modules.ingestion.self_traffic import excluded_hosts, is_self_traffic
from server.modules.ingestion.sensor_time import clamp_sensor_ts_ms, coerce_sensor_ts_ms
from server.modules.persistence.database import AsyncSessionLocal, get_db
from server.modules.quotas.tenant_quota import check_ingest_quota
from server.modules.sensors.keys import resolve_sensor_by_key
from server.modules.utils.redactor import Redactor

router = APIRouter()

# WebSocket opcodes the eBPF sensor used to emit as fake HTTP (TEXT /ws).
_NON_HTTP_LIVE_METHODS = frozenset({
    "TEXT", "PING", "PONG", "BINARY", "CLOSE", "CONTINUATION",
})


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _datetime_from_sensor_ts(ts_raw: object | None) -> datetime.datetime:
    ms = clamp_sensor_ts_ms(coerce_sensor_ts_ms(ts_raw))
    return datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)


def _is_http_live_method(method: str) -> bool:
    return method.upper() not in _NON_HTTP_LIVE_METHODS


def normalize_sensor_events(data: dict) -> list:
    """Accept v1 `{events:[...]}` and session-4 `{MsgHeader, Batch}` envelopes."""
    events = data.get("events")
    if isinstance(events, list) and events:
        return events
    batch = data.get("Batch") or data.get("batch")
    if not isinstance(batch, list):
        return []
    normalized: list[dict] = []
    for item in batch:
        if not isinstance(item, dict):
            continue
        if "request" in item or "method" in item or "path" in item:
            normalized.append(item)
            continue
        method = item.get("HTTPReq.Method") or "GET"
        path = item.get("HTTPReq.Uri") or "/"
        query = item.get("HTTPReq.Query") or ""
        if query and "?" not in str(path):
            path = f"{path}?{query}"
        host = item.get("Req.Header.host") or ""
        headers = {}
        for key, value in item.items():
            if key.startswith("Req.Header.") and key != "Req.Header.extra":
                headers[key.split(".", 2)[-1].lower()] = value
        status = int(item.get("HTTPResp.ResponseCode") or 0)
        source_ip = (
            item.get("DownstreamL3L4.SourceIP")
            or item.get("SrcInfo.RemoteAddress")
            or ""
        )
        protocol = item.get("L7Protocol") or "HTTP/1.1"
        latency_ms = int(item.get("SessionStats.TimeToLastDownstreamTxByte") or 0)
        normalized.append(
            {
                "method": method,
                "path": path,
                "host": host,
                "source_ip": source_ip,
                "protocol": protocol,
                "latency_ms": latency_ms or None,
                "observed_at": clamp_sensor_ts_ms(coerce_sensor_ts_ms(item.get("SessionStats.StartTime"))),
                "request": {
                    "method": method,
                    "path": path,
                    "host": host,
                    "headers": headers,
                },
                "response": {"status": status, "status_code": status, "latency_ms": latency_ms or None},
            }
        )
    return normalized


_ATTACK_SIGS = [
    (re.compile(r"union\s+select|drop\s+table|insert\s+into|or\s+'1'\s*=\s*'1|;\s*--", re.I), "SQL Injection", "HIGH"),
    (re.compile(r"sleep\s*\(|waitfor\s+delay|benchmark\s*\(", re.I), "Blind SQLi", "CRITICAL"),
    (re.compile(r"<script|onerror\s*=|onload\s*=|javascript:|alert\s*\(", re.I), "XSS", "HIGH"),
    (re.compile(r"\.\./|\.\.\\|/etc/passwd|/proc/self|/windows/system32", re.I), "Path Traversal", "CRITICAL"),
    (re.compile(r"[;&|`]\s*\+?(cat|id|whoami|bash|sh|wget|curl)[\s+]", re.I), "Command Injection", "CRITICAL"),
    (re.compile(r"\beval\s*\(|base64_decode|system\s*\(|exec\s*\(", re.I), "Code Injection", "CRITICAL"),
    (re.compile(r"nikto|sqlmap|nmap|dirbuster|masscan|nuclei|burpsuite", re.I), "Scanning Tool", "MEDIUM"),
    (re.compile(r"(?:^|/)\.env(?:/|$)|(?:^|/)\.git/config|phpMyAdmin|wp-admin|\.htaccess", re.I), "Sensitive File Access", "HIGH"),
    (re.compile(r"ldap://|CN=|DC=|ou=", re.I), "LDAP Injection", "HIGH"),
    (re.compile(r"file://|gopher://|ftp://|dict://|sftp://", re.I), "SSRF", "CRITICAL"),
]


def _malicious_record_path(record: MaliciousEventRecord) -> str:
    url = record.url or ""
    host = record.host or ""
    if url.startswith("/"):
        return url.split("?", 1)[0] or "/"
    if host and url.startswith(host):
        rest = url[len(host):]
        return (rest or "/").split("?", 1)[0]
    return url.split("?", 1)[0] or "/"


def _threat_overlay(events: list[MaliciousEventRecord]) -> dict[tuple[str, str], dict[str, str]]:
    """Map (ip, path) → threat. Never paint a whole ingress IP with one hit."""
    overlay: dict[tuple[str, str], dict[str, str]] = {}
    for event in events:
        if not event.ip or not event.category:
            continue
        overlay[(event.ip, _malicious_record_path(event))] = {
            "category": event.category,
            "severity": event.severity or "MEDIUM",
        }
    return overlay


def _attacks_for_log(
    overlay: dict[tuple[str, str], dict[str, str]],
    log: RequestLog,
) -> list[dict[str, str]]:
    path = redact_ingestion_path(log.path or "/").split("?", 1)[0]
    hit = overlay.get((log.source_ip or "", path))
    return [hit] if hit else []


def _detect_attacks(path: str, headers: dict) -> list[dict]:
    target = path + " " + headers.get("user-agent", "")
    hits = []
    for pattern, category, severity in _ATTACK_SIGS:
        if pattern.search(target):
            hits.append({"category": category, "severity": severity})
    return hits


class IngestPayload(BaseModel):
    lines: list[str]
    sensor_key: str | None = None


def _sensor_identity(sensor: Sensor) -> dict[str, str | int | None]:
    return {
        "sensor_id": sensor.id,
        "sensor_name": Redactor.redact_text(sensor.name or ""),
    }


@router.post("/ingest")
async def ingest_lines(
    body: IngestPayload,
    x_sensor_key: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """Receive log lines from log shipper and enqueue them."""
    sensor_key = body.sensor_key or x_sensor_key
    if len(body.lines) > settings.INGESTION_MAX_LINES:
        raise HTTPException(status_code=413, detail="Too many lines in one request")
    for line in body.lines:
        if len(line.encode("utf-8")) > settings.INGESTION_MAX_LINE_BYTES:
            raise HTTPException(status_code=413, detail="Log line exceeds size limit")

    if not sensor_key:
        raise HTTPException(status_code=403, detail="Sensor key required")

    sensor = await resolve_sensor_by_key(db, sensor_key)
    if not sensor:
        raise HTTPException(status_code=403, detail="Invalid sensor key")
    account_id = sensor.account_id
    sensor_identity = _sensor_identity(sensor)

    quota = await check_ingest_quota(account_id, cost=len(body.lines))
    if not quota.allowed:
        raise HTTPException(
            status_code=429,
            detail="Ingestion rate limit exceeded",
            headers={"Retry-After": str(max(1, quota.reset_at - int(_utc_now().timestamp())))},
        )

    job_id = str(uuid.uuid4())
    job = IngestionJob(
        id=job_id,
        account_id=account_id,
        job_type="stream_lines",
        status="QUEUED",
        accepted_count=len(body.lines),
        job_metadata={**sensor_identity, "source": "stream_lines"},
    )
    db.add(job)
    await db.commit()

    queued = await ingestion_queue.enqueue(
        IngestionJobItem(
            job_id=job_id,
            account_id=account_id,
            job_type="stream_lines",
            payload={"lines": body.lines, "sensor_id": sensor.id},
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
        action="INGESTION_STREAM_ENQUEUED",
        resource_type="ingestion_job",
        resource_id=job_id,
        details={"accepted": len(body.lines), **sensor_identity},
    )
    await db.commit()

    return {
        "status": "queued",
        "job_id": job_id,
        "lines_processed": len(body.lines),
        "threats_detected": 0,
    }


async def handle_ebpf_ingest_request(request: Request, db: AsyncSession) -> dict:
    """
    Process JSON sensor payloads: {"version":"v1","events":[...]}.
    Auth: Authorization: Bearer <sensor_key>.

    Used by POST /api/stream/ingest/ebpf and POST /v1/events (Argus / api-sentinel-sensor).
    """
    raw = await request.body()
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid gzip body") from exc

    try:
        data = json.loads(raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    events = normalize_sensor_events(data)
    if not events:
        return {"status": "ok", "events_processed": 0, "threats_detected": 0}

    auth = request.headers.get("authorization", "")
    sensor_key = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else None
    if not sensor_key:
        raise HTTPException(status_code=403, detail="Sensor key required")

    sensor = await resolve_sensor_by_key(db, sensor_key)
    if not sensor:
        raise HTTPException(status_code=403, detail="Invalid sensor key")

    account_id = sensor.account_id
    sensor.last_heartbeat = _utc_now()
    sensor.lines_shipped = (sensor.lines_shipped or 0) + len(events)
    sensor.status = "ONLINE"

    pipeline_mode = unified_detection_pipeline.mode()
    threats_detected = 0
    ws_batch = []
    new_actors: dict[str, ThreatActor] = {}
    discovery = EndpointDiscovery(db)
    inventoried = 0
    self_hosts = excluded_hosts()

    for ev in events:
        req = ev.get("request") or {}
        resp = ev.get("response") or {}
        method = (req.get("method") or ev.get("method") or "GET").upper()
        if not _is_http_live_method(method):
            continue
        path = req.get("path") or ev.get("path") or "/"
        host = (req.get("host") or ev.get("host") or "").strip()
        if is_self_traffic(host, path, self_hosts=self_hosts):
            continue
        safe_path = redact_ingestion_path(path)
        headers = req.get("headers") or ev.get("headers") or {}
        status = int(resp.get("status") or ev.get("status") or 0)
        source_ip = ev.get("source_ip") or ev.get("src_ip") or ""
        protocol = ev.get("protocol") or "HTTP/1.1"
        latency_raw = resp.get("latency_ms") or ev.get("latency_ms")
        try:
            latency_ms = int(latency_raw) if latency_raw not in (None, "") else None
        except (TypeError, ValueError):
            latency_ms = None
        ts_raw = ev.get("observed_at") or ev.get("ts")
        ts = _datetime_from_sensor_ts(ts_raw)

        endpoint_id = None
        catalogue_path = inventory_path(path)
        if catalogue_path:
            query = path.split("?", 1)[1] if "?" in path else None
            auth_types: list[str] = []
            auth_header_value = ""
            for _hk, _hv in (headers or {}).items():
                if str(_hk).lower() == "authorization":
                    auth_header_value = str(_hv or "")
                    break
            if auth_header_value.lower().startswith("bearer "):
                tok = auth_header_value.split(" ", 1)[1]
                auth_types = ["JWT"] if tok.count(".") == 2 else ["BEARER"]
            elif auth_header_value.lower().startswith("basic "):
                auth_types = ["BASIC"]
            endpoint = await discovery.discover(
                {
                    "account_id": account_id,
                    "source": "ebpf",
                    "method": method,
                    "host": host or "unknown",
                    "path": catalogue_path,
                    "scheme": "https",
                    "status": status,
                    "last_seen": ts,
                    "query_string": query,
                    "auth_types_found": auth_types,
                    "auth_required": bool(auth_types),
                },
                commit=False,
            )
            endpoint_id = endpoint.id
            inventoried += 1

        if pipeline_mode == "active":
            result = await unified_detection_pipeline.process(
                db,
                account_id=account_id,
                source_type="stream_ebpf",
                raw_event=ev,
                persist_request_log=True,
                existing_endpoint_id=endpoint_id,
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
                    source_type="stream_ebpf",
                    raw_event=ev,
                    persist_request_log=False,
                    existing_endpoint_id=endpoint_id,
                    context_source="EBPF_SENSOR",
                    shadow=True,
                )

            db.add(RequestLog(
                account_id=account_id,
                endpoint_id=endpoint_id,
                source_ip=source_ip,
                method=method,
                path=safe_path,
                host=host or None,
                response_code=status,
                response_time_ms=latency_ms,
                created_at=ts,
            ))

            attacks = _detect_attacks(path, headers)
            for attack in attacks:
                threats_detected += 1
                category = attack["category"]
                severity = attack["severity"]

                db.add(MaliciousEventRecord(
                    account_id=account_id,
                    ip=source_ip,
                    actor=source_ip,
                    url=f"{host}{safe_path}",
                    method=method,
                    category=category,
                    severity=severity,
                    status="OPEN",
                    context_source="EBPF_SENSOR",
                    detected_at=int(ts.timestamp() * 1000),
                ))

                score_inc = {"CRITICAL": 1.0, "HIGH": 0.5, "MEDIUM": 0.1, "LOW": 0.05}.get(severity, 0.1)
                if source_ip in new_actors:
                    actor = new_actors[source_ip]
                    actor.event_count = (actor.event_count or 0) + 1
                    actor.risk_score = min(10.0, (actor.risk_score or 0) + score_inc)
                    actor.last_seen = ts
                else:
                    actor_result = await db.execute(select(ThreatActor).where(
                        ThreatActor.source_ip == source_ip,
                        ThreatActor.account_id == account_id,
                    ))
                    actor = actor_result.scalar_one_or_none()
                    if actor:
                        actor.event_count = (actor.event_count or 0) + 1
                        actor.risk_score = min(10.0, (actor.risk_score or 0) + score_inc)
                        actor.last_seen = ts
                    else:
                        actor = ThreatActor(
                            account_id=account_id,
                            source_ip=source_ip,
                            event_count=1,
                            risk_score=score_inc,
                            status="MONITORING",
                            last_seen=ts,
                        )
                        db.add(actor)
                        new_actors[source_ip] = actor

                if severity in {"HIGH", "CRITICAL"}:
                    db.add(Alert(
                        account_id=account_id,
                        title=f"{category} detected from {source_ip}",
                        message=f"{severity} {category} on {method} {safe_path} (status {status})",
                        severity=severity,
                        category=category,
                        source_ip=source_ip,
                        endpoint=safe_path,
                        status="OPEN",
                    ))

        ws_batch.append({
            "ip": source_ip,
            "method": method,
            "path": safe_path,
            "host": host,
            "status": status,
            "protocol": protocol,
            "latency_ms": latency_ms,
            "timestamp": ts.isoformat(),
            "attacks": attacks,
            "blocked": False,
            "source": "ebpf",
        })

    await db.commit()
    if inventoried:
        await bump_cache_version(account_id)

    for entry in ws_batch:
        await ws_manager.broadcast({"type": "log_entry", "data": entry}, account_id=account_id)
    if inventoried:
        await ws_manager.broadcast(
            {"type": "TRAFFIC_INGESTED", "data": {"endpoints": inventoried}},
            account_id=account_id,
        )

    return {
        "status": "ok",
        "events_processed": len(events),
        "threats_detected": threats_detected,
    }


@router.post("/ingest/ebpf")
async def ingest_ebpf_events(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Receive structured events from the eBPF kernel sensor."""
    return await handle_ebpf_ingest_request(request, db)


@router.get("/recent")
async def recent_events(
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_auth),
):
    """REST fallback: recent tenant-scoped request logs with threat overlays."""
    account_id = payload.get("account_id")
    logs_result = await db.execute(
        select(RequestLog)
        .where(
            RequestLog.account_id == account_id,
            RequestLog.method.notin_(_NON_HTTP_LIVE_METHODS),
        )
        .order_by(RequestLog.created_at.desc())
        .limit(min(max(limit * 4, limit), 400))
    )
    logs = [
        row for row in logs_result.scalars().all()
        if not is_self_traffic(row.host, row.path)
    ][:limit]

    evt_result = await db.execute(
        select(MaliciousEventRecord)
        .where(MaliciousEventRecord.account_id == account_id)
        .order_by(MaliciousEventRecord.created_at.desc())
        .limit(200)
    )
    overlay = _threat_overlay(evt_result.scalars().all())

    return [
        {
            "id": r.id,
            "ip": r.source_ip,
            "method": r.method,
            "path": redact_ingestion_path(r.path),
            "host": r.host or "",
            "status": r.response_code,
            "latency_ms": r.response_time_ms,
            "timestamp": r.created_at.isoformat() if r.created_at else None,
            "attacks": _attacks_for_log(overlay, r),
        }
        for r in logs
    ]


@router.websocket("/live")
async def websocket_live(websocket: WebSocket):
    """WebSocket endpoint for live tenant-scoped events."""
    # Prefer cookie (httpOnly, not logged) then Authorization header.
    # Query-param tokens are NOT accepted — they appear in access logs.
    token = websocket.cookies.get("access_token")
    if not token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    connected = await ws_manager.connect(websocket, token=token)
    if not connected:
        return

    try:
        metadata = ws_manager.active_connections.get(websocket, {})
        account_id = metadata.get("account_id")
        async with AsyncSessionLocal() as db:
            logs_stmt = select(RequestLog).order_by(RequestLog.created_at.desc()).limit(80)
            events_stmt = select(MaliciousEventRecord).order_by(MaliciousEventRecord.created_at.desc()).limit(100)
            if account_id is not None:
                logs_stmt = logs_stmt.where(
                    RequestLog.account_id == account_id,
                    RequestLog.method.notin_(_NON_HTTP_LIVE_METHODS),
                )
                events_stmt = events_stmt.where(MaliciousEventRecord.account_id == account_id)
            else:
                logs_stmt = logs_stmt.where(RequestLog.method.notin_(_NON_HTTP_LIVE_METHODS))

            recent = [
                row for row in (await db.execute(logs_stmt)).scalars().all()
                if not is_self_traffic(row.host, row.path)
            ][:20]
            overlay = _threat_overlay((await db.execute(events_stmt)).scalars().all())

        for request_log in reversed(recent):
            await websocket.send_json({
                "type": "log_entry",
                "data": {
                    "id": request_log.id,
                    "ip": request_log.source_ip,
                    "method": request_log.method,
                    "path": redact_ingestion_path(request_log.path),
                    "host": request_log.host or "",
                    "status": request_log.response_code,
                    "latency_ms": request_log.response_time_ms,
                    "timestamp": request_log.created_at.isoformat() if request_log.created_at else None,
                    "attacks": _attacks_for_log(overlay, request_log),
                    "blocked": False,
                },
            })

        while True:
            try:
                await websocket.receive_text()
            except WebSocketDisconnect:
                break
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(websocket)
