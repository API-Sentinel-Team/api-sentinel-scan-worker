"""
Threat Detection — full implementation of Akto's protobuf threat_detection service.

Maps every proto RPC operation to a REST endpoint:
  malicious_alert_service  → POST /record
  dashboard_service        → POST /events, /actors, /apis, /analytics/*, /config, /sessions
  http_response_param      → POST /http-traffic  (Kafka-alternative ingestion)
  agentic_session_service  → POST /sessions/bulk-update
"""
import time
import json
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from sqlalchemy.future import select
from sqlalchemy import func, update, delete, and_, or_, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.persistence.database import get_db
from server.modules.auth.rbac import Permission, RBAC
from server.modules.ingestion.queue import ingestion_queue, IngestionJobItem
from server.modules.quotas.tenant_quota import check_ingest_quota
from server.modules.utils.redactor import Redactor
from server.models.core import (
    IngestionJob, MaliciousEventRecord, AgenticSession, ThreatConfig,
    ThreatActor, MaliciousEvent, RequestLog,
)
from server.modules.threat_detection.schemas import (
    # Ingest
    RecordMaliciousEventRequest, RecordMaliciousEventResponse,
    # Events / requests
    ListMaliciousRequestsRequest, ListMaliciousRequestsResponse,
    FetchAlertFiltersRequest, FetchAlertFiltersResponse,
    FetchMaliciousEventsRequest, FetchMaliciousEventsResponse,
    MaliciousPayloadsResponse,
    UpdateMaliciousEventStatusRequest, UpdateMaliciousEventStatusResponse,
    DeleteMaliciousEventsRequest, DeleteMaliciousEventsResponse,
    # Actors
    ListThreatActorsRequest, ListThreatActorResponse,
    ThreatActorEntry, ThreatActorActivityData,
    ModifyThreatActorStatusRequest, ModifyThreatActorStatusResponse,
    BulkModifyThreatActorStatusRequest, BulkModifyThreatActorStatusResponse,
    ThreatActorFilterRequest, ThreatActorFilterResponse,
    FetchThreatsForActorRequest, FetchThreatsForActorResponse,
    ActorCountsFromActorInfoRequest, ActorCountsFromActorInfoResponse,
    # Threat APIs
    ListThreatApiRequest, ListThreatApiResponse, ThreatApiEntry,
    # Analytics
    ThreatActorByCountryRequest, ThreatActorByCountryResponse, CountryCount,
    ThreatCategoryWiseCountRequest, ThreatCategoryWiseCountResponse, SubCategoryCount,
    ThreatSeverityWiseCountRequest, ThreatSeverityWiseCountResponse, SeverityCount,
    DailyActorsCountRequest, DailyActorsCountResponse, DailyActorsCount,
    ThreatActivityTimelineRequest, ThreatActivityTimelineResponse,
    ActivityTimeline, SubCategoryData,
    FetchTopNDataRequest, FetchTopNDataResponse, TopApiData, TopHostData,
    # Configuration
    ThreatConfiguration, GetThreatConfigurationRequest,
    ToggleArchivalEnabledRequest, ToggleArchivalEnabledResponse,
    # Agentic sessions
    BulkUpdateAgenticSessionContextRequest, BulkUpdateAgenticSessionContextResponse,
    SessionDocumentMessage,
    # Event list entries
    MaliciousEventEntry, EventType,
)

router = APIRouter()


def _redact_payload(value) -> str:
    if value is None:
        return ""
    return Redactor.redact_text(str(value))


def _redact_metadata(value) -> str:
    if not value:
        return ""
    return json.dumps(Redactor.redact_json(value))


def _redact_config(value):
    return Redactor.redact_json(value) if value is not None else None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_ms() -> int:
    return int(time.time() * 1000)


def _rec_to_entry(r: MaliciousEventRecord) -> MaliciousEventEntry:
    return MaliciousEventEntry(
        id=r.id,
        actor=r.actor or "",
        filter_id=r.filter_id or "",
        detected_at=r.detected_at,
        ip=r.ip or "",
        endpoint=Redactor.redact_text(r.url or ""),
        method=r.method or "",
        api_collection_id=r.api_collection_id,
        payload=_redact_payload(r.payload),
        country=r.country_code or "",
        event_type=EventType(r.event_type) if r.event_type else EventType.UNSPECIFIED,
        category=r.category or "",
        sub_category=r.sub_category or "",
        type=r.type or "",
        severity=r.severity or "",
        label=r.label or "",
        host=r.host or "",
        status=r.status or "OPEN",
        successful_exploit=r.successful_exploit,
        jira_ticket_url=Redactor.redact_text(r.jira_ticket_url or ""),
        dest_country=r.dest_country_code or "",
        session_id=r.session_id or "",
        metadata=_redact_metadata(r.event_metadata),
    )


def _apply_event_filter(stmt, f):
    """Apply MaliciousRequestFilter fields to a SQLAlchemy statement."""
    if f.actors:
        stmt = stmt.where(MaliciousEventRecord.actor.in_(f.actors))
    if f.ips:
        stmt = stmt.where(MaliciousEventRecord.ip.in_(f.ips))
    if f.hosts:
        stmt = stmt.where(MaliciousEventRecord.host.in_(f.hosts))
    if f.types:
        stmt = stmt.where(MaliciousEventRecord.type.in_(f.types))
    if f.sub_category:
        stmt = stmt.where(MaliciousEventRecord.sub_category.in_(f.sub_category))
    if f.method:
        stmt = stmt.where(MaliciousEventRecord.method.in_(f.method))
    if f.status_filter:
        stmt = stmt.where(MaliciousEventRecord.status == f.status_filter)
    if f.successful_exploit is not None:
        stmt = stmt.where(MaliciousEventRecord.successful_exploit == f.successful_exploit)
    if f.label:
        stmt = stmt.where(MaliciousEventRecord.label == f.label)
    if f.api_collection_id:
        stmt = stmt.where(MaliciousEventRecord.api_collection_id.in_(f.api_collection_id))
    if f.detected_at_time_range:
        tr = f.detected_at_time_range
        if tr.start:
            stmt = stmt.where(MaliciousEventRecord.detected_at >= tr.start)
        if tr.end:
            stmt = stmt.where(MaliciousEventRecord.detected_at <= tr.end)
    return stmt


# ═══════════════════════════════════════════════════════════════════════════════
# malicious_alert_service — RecordMaliciousEvent
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/record", response_model=RecordMaliciousEventResponse)
async def record_malicious_event(
    req: RecordMaliciousEventRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest a malicious event (proto: RecordMaliciousEventRequest).
    Creates MaliciousEventRecord + upserts ThreatActor.
    """
    account_id = payload.get("account_id")
    ev = req.malicious_event
    if not ev:
        raise HTTPException(status_code=422, detail="malicious_event is required")

    detected_at = ev.detected_at or _now_ms()

    actor_result = await db.execute(
        select(ThreatActor).where(
            ThreatActor.source_ip == ev.actor,
            ThreatActor.account_id == account_id,
        )
    )
    actor = actor_result.scalar_one_or_none()
    if not actor:
        actor = ThreatActor(
            account_id=account_id,
            source_ip=ev.actor,
            status="MONITORING",
            event_count=0,
            risk_score=0.0,
        )
        db.add(actor)
        await db.flush()
    actor.event_count = (actor.event_count or 0) + 1

    # Create MaliciousEventRecord
    rec = MaliciousEventRecord(
        account_id=account_id,
        actor=ev.actor,
        filter_id=ev.filter_id,
        detected_at=detected_at,
        ip=ev.latest_api_ip,
        url=Redactor.redact_text(ev.latest_api_endpoint),
        method=ev.latest_api_method,
        host=ev.host,
        api_collection_id=ev.latest_api_collection_id,
        payload=_redact_payload(ev.latest_api_payload),
        event_type=ev.event_type.value if hasattr(ev.event_type, 'value') else str(ev.event_type),
        category=ev.category,
        sub_category=ev.sub_category,
        severity=ev.severity,
        type=ev.type,
        label=ev.label,
        context_source=ev.context_source,
        session_id=ev.session_id,
        successful_exploit=ev.successful_exploit,
        status=ev.status or "OPEN",
        event_metadata=Redactor.redact_json(ev.metadata.model_dump()) if ev.metadata else None,
    )
    db.add(rec)

    # Also persist each sample request
    for sr in req.sample_requests:
        sr_rec = MaliciousEventRecord(
            account_id=account_id,
            actor=req.malicious_event.actor if req.malicious_event else sr.ip,
            filter_id=sr.filter_id,
            detected_at=sr.timestamp or detected_at,
            ip=sr.ip,
            url=Redactor.redact_text(sr.url),
            method=sr.method,
            api_collection_id=sr.api_collection_id,
            payload=_redact_payload(sr.payload),
            event_type="EVENT_TYPE_SINGLE",
            status=sr.status or "OPEN",
            successful_exploit=sr.successful_exploit,
            event_metadata=Redactor.redact_json(sr.metadata.model_dump()) if sr.metadata else None,
        )
        db.add(sr_rec)

    await db.commit()
    return RecordMaliciousEventResponse()


# ═══════════════════════════════════════════════════════════════════════════════
# dashboard_service — Malicious Events
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/events", response_model=ListMaliciousRequestsResponse)
async def list_malicious_events(
    req: ListMaliciousRequestsRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List malicious events with rich filtering (proto: ListMaliciousRequestsRequest)."""
    account_id = payload.get("account_id")
    stmt = select(MaliciousEventRecord).where(MaliciousEventRecord.account_id == account_id)
    stmt = _apply_event_filter(stmt, req.filter)

    total_stmt = select(func.count()).select_from(stmt.subquery())
    total = await db.scalar(total_stmt) or 0

    stmt = stmt.offset(req.skip or 0).limit(req.limit)
    result = await db.execute(stmt)
    records = result.scalars().all()

    return ListMaliciousRequestsResponse(
        malicious_events=[_rec_to_entry(r) for r in records],
        total=total,
    )


@router.post("/events/filters", response_model=FetchAlertFiltersResponse)
async def fetch_alert_filters(
    req: FetchAlertFiltersRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Return distinct filter values for the events UI (proto: FetchAlertFiltersRequest)."""
    account_id = payload.get("account_id")
    base = select(MaliciousEventRecord).where(MaliciousEventRecord.account_id == account_id)
    if req.detected_at_time_range:
        tr = req.detected_at_time_range
        if tr.start:
            base = base.where(MaliciousEventRecord.detected_at >= tr.start)
        if tr.end:
            base = base.where(MaliciousEventRecord.detected_at <= tr.end)

    actors = await db.execute(select(distinct(MaliciousEventRecord.actor)).select_from(base.subquery()))
    urls = await db.execute(select(distinct(MaliciousEventRecord.url)).select_from(base.subquery()))
    subcats = await db.execute(select(distinct(MaliciousEventRecord.sub_category)).select_from(base.subquery()))
    hosts = await db.execute(select(distinct(MaliciousEventRecord.host)).select_from(base.subquery()))

    return FetchAlertFiltersResponse(
        actors=[r[0] for r in actors.all() if r[0]],
        urls=[Redactor.redact_text(r[0]) for r in urls.all() if r[0]],
        sub_category=[r[0] for r in subcats.all() if r[0]],
        hosts=[r[0] for r in hosts.all() if r[0]],
    )


@router.post("/events/fetch", response_model=FetchMaliciousEventsResponse)
async def fetch_malicious_event_payloads(
    req: FetchMaliciousEventsRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Fetch malicious request payloads for a specific actor+filter (proto: FetchMaliciousEventsRequest)."""
    account_id = payload.get("account_id")
    stmt = select(MaliciousEventRecord).where(MaliciousEventRecord.account_id == account_id)
    if req.actor:
        stmt = stmt.where(MaliciousEventRecord.actor == req.actor)
    if req.filter_id:
        stmt = stmt.where(MaliciousEventRecord.filter_id == req.filter_id)
    stmt = stmt.limit(50)
    result = await db.execute(stmt)
    records = result.scalars().all()
    return FetchMaliciousEventsResponse(
        malicious_payloads_response=[
            MaliciousPayloadsResponse(
                orig=_redact_payload(r.payload),
                ts=r.detected_at,
                metadata=_redact_metadata(r.event_metadata),
            )
            for r in records
        ]
    )


@router.post("/events/status", response_model=UpdateMaliciousEventStatusResponse)
async def update_event_status(
    req: UpdateMaliciousEventStatusRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Update status / Jira ticket for events (proto: UpdateMaliciousEventStatusRequest)."""
    account_id = payload.get("account_id")
    event_ids = list(req.event_ids)
    if req.event_id:
        event_ids.append(req.event_id)

    updates = {}
    if req.status:
        updates["status"] = req.status
    if req.jira_ticket_url:
        updates["jira_ticket_url"] = Redactor.redact_text(req.jira_ticket_url)

    if not updates:
        return UpdateMaliciousEventStatusResponse(success=True, message="Nothing to update", updated_count=0)

    if event_ids:
        r = await db.execute(
            update(MaliciousEventRecord)
            .where(MaliciousEventRecord.id.in_(event_ids), MaliciousEventRecord.account_id == account_id)
            .values(**updates)
        )
        updated = r.rowcount or 0
    elif req.filter:
        stmt = select(MaliciousEventRecord).where(MaliciousEventRecord.account_id == account_id)
        stmt = _apply_event_filter(stmt, req.filter)
        result = await db.execute(stmt)
        recs = result.scalars().all()
        for rec in recs:
            for k, v in updates.items():
                setattr(rec, k, v)
        updated = len(recs)
    else:
        return UpdateMaliciousEventStatusResponse(success=False, message="No target specified", updated_count=0)

    await db.commit()
    return UpdateMaliciousEventStatusResponse(success=True, message="Updated", updated_count=updated)


@router.post("/events/delete", response_model=DeleteMaliciousEventsResponse)
async def delete_malicious_events(
    req: DeleteMaliciousEventsRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Delete malicious events by ID or filter (proto: DeleteMaliciousEventsRequest)."""
    account_id = payload.get("account_id")
    if req.event_ids:
        r = await db.execute(
            delete(MaliciousEventRecord)
            .where(MaliciousEventRecord.id.in_(req.event_ids), MaliciousEventRecord.account_id == account_id)
        )
        deleted = r.rowcount or 0
    elif req.filter:
        stmt = select(MaliciousEventRecord.id).where(MaliciousEventRecord.account_id == account_id)
        stmt = _apply_event_filter(stmt, req.filter)
        ids = [row[0] for row in (await db.execute(stmt)).all()]
        r = await db.execute(delete(MaliciousEventRecord).where(MaliciousEventRecord.id.in_(ids)))
        deleted = r.rowcount or 0
    else:
        return DeleteMaliciousEventsResponse(success=False, message="No target specified", deleted_count=0)

    await db.commit()
    return DeleteMaliciousEventsResponse(success=True, message="Deleted", deleted_count=deleted)


# ═══════════════════════════════════════════════════════════════════════════════
# dashboard_service — Threat Actors
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/actors", response_model=ListThreatActorResponse)
async def list_threat_actors_proto(
    req: ListThreatActorsRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List threat actors with rich filtering (proto: ListThreatActorsRequest)."""
    account_id = payload.get("account_id")
    # Aggregate from MaliciousEventRecord grouped by actor
    stmt = (
        select(
            MaliciousEventRecord.actor,
            MaliciousEventRecord.ip,
            MaliciousEventRecord.url,
            MaliciousEventRecord.method,
            MaliciousEventRecord.host,
            MaliciousEventRecord.sub_category,
            MaliciousEventRecord.severity,
            func.min(MaliciousEventRecord.detected_at).label("discovered_at"),
            func.count(MaliciousEventRecord.id).label("event_count"),
            MaliciousEventRecord.country_code,
        )
        .where(MaliciousEventRecord.account_id == account_id)
        .group_by(MaliciousEventRecord.actor)
        .offset(req.skip or 0)
        .limit(req.limit)
    )
    f = req.filter
    if f.actors:
        stmt = stmt.where(MaliciousEventRecord.actor.in_(f.actors))
    if f.latest_ips:
        stmt = stmt.where(MaliciousEventRecord.ip.in_(f.latest_ips))
    if f.country:
        stmt = stmt.where(MaliciousEventRecord.country_code.in_(f.country))
    if f.hosts:
        stmt = stmt.where(MaliciousEventRecord.host.in_(f.hosts))
    if req.start_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at >= req.start_ts)
    if req.end_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at <= req.end_ts)

    result = await db.execute(stmt)
    rows = result.all()

    total = await db.scalar(
        select(func.count(distinct(MaliciousEventRecord.actor)))
        .where(MaliciousEventRecord.account_id == account_id)
    ) or 0

    actors = [
        ThreatActorEntry(
            id=row.actor or "",
            latest_api_ip=row.ip or "",
            latest_api_endpoint=Redactor.redact_text(row.url or ""),
            latest_api_method=row.method or "",
            discovered_at=row.discovered_at or 0,
            country=row.country_code or "",
            latest_subcategory=row.sub_category or "",
            latest_api_host=row.host or "",
        )
        for row in rows
    ]
    return ListThreatActorResponse(actors=actors, total=total)


@router.post("/actors/status", response_model=ModifyThreatActorStatusResponse)
async def modify_actor_status(
    req: ModifyThreatActorStatusRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Update a single actor's status (proto: ModifyThreatActorStatusRequest)."""
    account_id = payload.get("account_id")
    result = await db.execute(
        select(ThreatActor).where(
            ThreatActor.source_ip == req.ip,
            ThreatActor.account_id == account_id,
        )
    )
    actor = result.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    actor.status = req.status.upper()
    await db.commit()
    return ModifyThreatActorStatusResponse()


@router.post("/actors/bulk-status", response_model=BulkModifyThreatActorStatusResponse)
async def bulk_modify_actor_status(
    req: BulkModifyThreatActorStatusRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Bulk-update actor statuses (proto: BulkModifyThreatActorStatusRequest)."""
    account_id = payload.get("account_id")
    await db.execute(
        update(ThreatActor)
        .where(
            ThreatActor.source_ip.in_(req.ips),
            ThreatActor.account_id == account_id,
        )
        .values(status=req.status.upper())
    )
    await db.commit()
    return BulkModifyThreatActorStatusResponse()


@router.post("/actors/filter", response_model=ThreatActorFilterResponse)
async def get_actor_filter_options(
    req: ThreatActorFilterRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Return distinct filter values for the actors UI (proto: ThreatActorFilterRequest)."""
    account_id = payload.get("account_id")
    subcats = await db.execute(
        select(distinct(MaliciousEventRecord.sub_category))
        .where(MaliciousEventRecord.account_id == account_id)
    )
    countries = await db.execute(
        select(distinct(MaliciousEventRecord.country_code))
        .where(MaliciousEventRecord.account_id == account_id)
    )
    actors = await db.execute(
        select(distinct(MaliciousEventRecord.actor))
        .where(MaliciousEventRecord.account_id == account_id)
    )
    hosts = await db.execute(
        select(distinct(MaliciousEventRecord.host))
        .where(MaliciousEventRecord.account_id == account_id)
    )
    return ThreatActorFilterResponse(
        sub_categories=[r[0] for r in subcats.all() if r[0]],
        countries=[r[0] for r in countries.all() if r[0]],
        actor_id=[r[0] for r in actors.all() if r[0]],
        host=[r[0] for r in hosts.all() if r[0]],
    )


@router.post("/actors/threats", response_model=FetchThreatsForActorResponse)
async def fetch_threats_for_actor(
    req: FetchThreatsForActorRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Fetch all threat activities for a specific actor (proto: FetchThreatsForActorRequest)."""
    account_id = payload.get("account_id")
    result = await db.execute(
        select(MaliciousEventRecord)
        .where(
            MaliciousEventRecord.account_id == account_id,
            MaliciousEventRecord.actor == req.actor,
        )
        .limit(req.limit)
    )
    records = result.scalars().all()
    return FetchThreatsForActorResponse(
        activities=[
            ThreatActorActivityData(
                url=Redactor.redact_text(r.url or ""),
                sub_category=r.sub_category or "",
                detected_at=r.detected_at,
                severity=r.severity or "",
                method=r.method or "",
                host=r.host or "",
                metadata=_redact_metadata(r.event_metadata),
            )
            for r in records
        ]
    )


@router.post("/actors/counts", response_model=ActorCountsFromActorInfoResponse)
async def actor_counts(
    req: ActorCountsFromActorInfoRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Critical vs active actor counts (proto: ActorCountsFromActorInfoRequest)."""
    account_id = payload.get("account_id")
    stmt = select(MaliciousEventRecord.actor).where(MaliciousEventRecord.account_id == account_id).distinct()
    if req.start_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at >= req.start_ts)
    if req.end_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at <= req.end_ts)

    critical = await db.scalar(
        select(func.count(distinct(MaliciousEventRecord.actor)))
        .where(MaliciousEventRecord.account_id == account_id, MaliciousEventRecord.severity == "CRITICAL")
    ) or 0
    active = await db.scalar(
        select(func.count(distinct(MaliciousEventRecord.actor)))
        .where(MaliciousEventRecord.account_id == account_id, MaliciousEventRecord.status == "OPEN")
    ) or 0
    return ActorCountsFromActorInfoResponse(critical_actors=critical, active_actors=active)


# ═══════════════════════════════════════════════════════════════════════════════
# dashboard_service — Threat APIs
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/apis", response_model=ListThreatApiResponse)
async def list_threat_apis(
    req: ListThreatApiRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List APIs that have been attacked (proto: ListThreatApiRequest)."""
    account_id = payload.get("account_id")
    stmt = (
        select(
            MaliciousEventRecord.url,
            MaliciousEventRecord.method,
            MaliciousEventRecord.host,
            func.min(MaliciousEventRecord.detected_at).label("discovered_at"),
            func.count(distinct(MaliciousEventRecord.actor)).label("actors_count"),
            func.count(MaliciousEventRecord.id).label("requests_count"),
        )
        .where(MaliciousEventRecord.account_id == account_id)
        .group_by(MaliciousEventRecord.url, MaliciousEventRecord.method, MaliciousEventRecord.host)
    )
    f = req.filter
    if f.urls:
        stmt = stmt.where(MaliciousEventRecord.url.in_(f.urls))
    if f.methods:
        stmt = stmt.where(MaliciousEventRecord.method.in_(f.methods))
    if f.detected_at_time_range:
        tr = f.detected_at_time_range
        if tr.start:
            stmt = stmt.where(MaliciousEventRecord.detected_at >= tr.start)
        if tr.end:
            stmt = stmt.where(MaliciousEventRecord.detected_at <= tr.end)

    total_stmt = select(func.count()).select_from(stmt.subquery())
    total = await db.scalar(total_stmt) or 0
    stmt = stmt.offset(req.skip or 0).limit(req.limit)
    result = await db.execute(stmt)
    rows = result.all()
    return ListThreatApiResponse(
        apis=[
            ThreatApiEntry(
                endpoint=Redactor.redact_text(row.url or ""),
                method=row.method or "",
                discovered_at=row.discovered_at or 0,
                actors_count=row.actors_count,
                requests_count=row.requests_count,
                host=row.host or "",
            )
            for row in rows
        ],
        total=total,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# dashboard_service — Analytics
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/analytics/country", response_model=ThreatActorByCountryResponse)
async def actors_by_country(
    req: ThreatActorByCountryRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Threat actor count by country (proto: ThreatActorByCountryRequest)."""
    account_id = payload.get("account_id")
    stmt = (
        select(MaliciousEventRecord.country_code, func.count(distinct(MaliciousEventRecord.actor)))
        .where(MaliciousEventRecord.account_id == account_id)
        .group_by(MaliciousEventRecord.country_code)
    )
    if req.start_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at >= req.start_ts)
    if req.end_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at <= req.end_ts)
    result = await db.execute(stmt)
    return ThreatActorByCountryResponse(
        countries=[CountryCount(code=row[0] or "XX", count=row[1]) for row in result.all()]
    )


@router.post("/analytics/category", response_model=ThreatCategoryWiseCountResponse)
async def category_wise_count(
    req: ThreatCategoryWiseCountRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Threat count by category+subcategory (proto: ThreatCategoryWiseCountRequest)."""
    account_id = payload.get("account_id")
    stmt = (
        select(
            MaliciousEventRecord.category,
            MaliciousEventRecord.sub_category,
            func.count(MaliciousEventRecord.id),
        )
        .where(MaliciousEventRecord.account_id == account_id)
        .group_by(MaliciousEventRecord.category, MaliciousEventRecord.sub_category)
    )
    if req.start_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at >= req.start_ts)
    if req.end_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at <= req.end_ts)
    result = await db.execute(stmt)
    return ThreatCategoryWiseCountResponse(
        category_wise_counts=[
            SubCategoryCount(category=row[0] or "", sub_category=row[1] or "", count=row[2])
            for row in result.all()
        ]
    )


@router.post("/analytics/severity", response_model=ThreatSeverityWiseCountResponse)
async def severity_wise_count(
    req: ThreatSeverityWiseCountRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Threat count by severity (proto: ThreatSeverityWiseCountRequest)."""
    account_id = payload.get("account_id")
    stmt = (
        select(MaliciousEventRecord.severity, func.count(MaliciousEventRecord.id))
        .where(MaliciousEventRecord.account_id == account_id)
        .group_by(MaliciousEventRecord.severity)
    )
    if req.start_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at >= req.start_ts)
    if req.end_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at <= req.end_ts)
    result = await db.execute(stmt)
    return ThreatSeverityWiseCountResponse(
        category_wise_counts=[SeverityCount(severity=row[0] or "UNKNOWN", count=row[1]) for row in result.all()]
    )


@router.post("/analytics/daily", response_model=DailyActorsCountResponse)
async def daily_actors_count(
    req: DailyActorsCountRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Daily actor activity summary (proto: DailyActorsCountRequest)."""
    account_id = payload.get("account_id")
    stmt = select(
        func.count(distinct(MaliciousEventRecord.actor)),
        func.count(MaliciousEventRecord.id),
    ).where(MaliciousEventRecord.account_id == account_id)
    if req.start_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at >= req.start_ts)
    if req.end_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at <= req.end_ts)
    row = (await db.execute(stmt)).one()

    critical_count = await db.scalar(
        select(func.count(distinct(MaliciousEventRecord.actor)))
        .where(MaliciousEventRecord.account_id == account_id, MaliciousEventRecord.severity == "CRITICAL")
    ) or 0
    ignored_count = await db.scalar(
        select(func.count(MaliciousEventRecord.id))
        .where(MaliciousEventRecord.account_id == account_id, MaliciousEventRecord.status == "IGNORED")
    ) or 0

    return DailyActorsCountResponse(
        actors_counts=[],          # Per-day breakdown omitted (SQLite lacks TRUNC(day))
        total_analysed=row[0],
        total_attacks=row[1],
        critical_actors_count=critical_count,
        total_active=row[0],
        total_ignored=ignored_count,
        total_under_review=0,
    )


@router.post("/analytics/timeline", response_model=ThreatActivityTimelineResponse)
async def activity_timeline(
    req: ThreatActivityTimelineRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Sub-category activity timeline (proto: ThreatActivityTimelineRequest)."""
    account_id = payload.get("account_id")
    stmt = (
        select(MaliciousEventRecord.detected_at, MaliciousEventRecord.sub_category)
        .where(MaliciousEventRecord.account_id == account_id)
    )
    if req.start_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at >= req.start_ts)
    if req.end_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at <= req.end_ts)
    result = await db.execute(stmt)
    rows = result.all()

    # Bucket by hour (3600000 ms)
    buckets: dict[int, dict[str, int]] = {}
    for row in rows:
        bucket_ts = (row[0] // 3_600_000) * 3_600_000 if row[0] else 0
        sub = row[1] or "UNKNOWN"
        buckets.setdefault(bucket_ts, {}).setdefault(sub, 0)
        buckets[bucket_ts][sub] += 1

    timeline = [
        ActivityTimeline(
            ts=ts,
            sub_category_wise_data=[
                SubCategoryData(sub_category=sc, activity_count=cnt)
                for sc, cnt in sub_dict.items()
            ],
        )
        for ts, sub_dict in sorted(buckets.items())
    ]
    return ThreatActivityTimelineResponse(threat_activity_timeline=timeline)


@router.post("/analytics/top-n", response_model=FetchTopNDataResponse)
async def fetch_top_n(
    req: FetchTopNDataRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Top-N attacked APIs and hosts (proto: FetchTopNDataRequest)."""
    account_id = payload.get("account_id")
    stmt = (
        select(
            MaliciousEventRecord.url,
            MaliciousEventRecord.method,
            MaliciousEventRecord.severity,
            func.count(MaliciousEventRecord.id).label("attacks"),
        )
        .where(MaliciousEventRecord.account_id == account_id)
        .group_by(MaliciousEventRecord.url, MaliciousEventRecord.method, MaliciousEventRecord.severity)
        .order_by(func.count(MaliciousEventRecord.id).desc())
        .limit(req.limit)
    )
    if req.start_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at >= req.start_ts)
    if req.end_ts:
        stmt = stmt.where(MaliciousEventRecord.detected_at <= req.end_ts)
    api_rows = await db.execute(stmt)

    host_stmt = (
        select(MaliciousEventRecord.host, func.count(MaliciousEventRecord.id).label("attacks"))
        .where(MaliciousEventRecord.account_id == account_id)
        .group_by(MaliciousEventRecord.host)
        .order_by(func.count(MaliciousEventRecord.id).desc())
        .limit(req.limit)
    )
    host_rows = await db.execute(host_stmt)

    return FetchTopNDataResponse(
        top_apis=[
            TopApiData(endpoint=Redactor.redact_text(r.url or ""), method=r.method or "", attacks=r.attacks, severity=r.severity or "")
            for r in api_rows.all()
        ],
        top_hosts=[TopHostData(host=r.host or "", attacks=r.attacks) for r in host_rows.all()],
    )


# ═══════════════════════════════════════════════════════════════════════════════
# dashboard_service — Threat Configuration
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/config", response_model=ThreatConfiguration)
async def get_threat_config(
    req: GetThreatConfigurationRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve threat configuration (proto: GetThreatConfigurationRequest)."""
    account_id = payload.get("account_id")
    result = await db.execute(select(ThreatConfig).where(ThreatConfig.account_id == account_id))
    cfg = result.scalar_one_or_none()
    if not cfg:
        return ThreatConfiguration()
    return ThreatConfiguration(
        actor=_redact_config(cfg.actor_config),
        ratelimit_config=_redact_config(cfg.ratelimit_config),
        param_enumeration_config=_redact_config(cfg.param_enumeration_config),
        archival_days=cfg.archival_days,
        archival_enabled=cfg.archival_enabled,
    )


@router.put("/config")
async def save_threat_config(
    config: ThreatConfiguration,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Save full threat configuration."""
    account_id = payload.get("account_id")
    result = await db.execute(select(ThreatConfig).where(ThreatConfig.account_id == account_id))
    cfg = result.scalar_one_or_none()
    if not cfg:
        cfg = ThreatConfig(account_id=account_id)
        db.add(cfg)
    cfg.actor_config = config.actor.model_dump() if config.actor else None
    cfg.ratelimit_config = config.ratelimit_config.model_dump() if config.ratelimit_config else None
    cfg.param_enumeration_config = config.param_enumeration_config.model_dump() if config.param_enumeration_config else None
    cfg.archival_days = config.archival_days
    cfg.archival_enabled = config.archival_enabled
    await db.commit()
    return {"status": "saved"}


@router.post("/config/archival", response_model=ToggleArchivalEnabledResponse)
async def toggle_archival(
    req: ToggleArchivalEnabledRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Toggle archival setting (proto: ToggleArchivalEnabledRequest)."""
    account_id = payload.get("account_id")
    result = await db.execute(select(ThreatConfig).where(ThreatConfig.account_id == account_id))
    cfg = result.scalar_one_or_none()
    if not cfg:
        cfg = ThreatConfig(account_id=account_id, archival_enabled=req.enabled)
        db.add(cfg)
    else:
        cfg.archival_enabled = req.enabled
    await db.commit()
    return ToggleArchivalEnabledResponse(enabled=req.enabled)


# ═══════════════════════════════════════════════════════════════════════════════
# agentic_session_service — BulkUpdateAgenticSessionContext
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/sessions/bulk-update", response_model=BulkUpdateAgenticSessionContextResponse)
async def bulk_update_sessions(
    req: BulkUpdateAgenticSessionContextRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_INSPECT)),
    db: AsyncSession = Depends(get_db),
):
    """Upsert agentic session documents (proto: BulkUpdateAgenticSessionContextRequest)."""
    account_id = payload.get("account_id")
    updated = 0
    for doc in req.session_documents:
        result = await db.execute(
            select(AgenticSession).where(
                AgenticSession.session_identifier == doc.session_identifier,
                AgenticSession.account_id == account_id,
            )
        )
        session = result.scalar_one_or_none()
        if not session:
            session = AgenticSession(
                account_id=account_id,
                session_identifier=doc.session_identifier,
            )
            db.add(session)
        session.session_summary = Redactor.redact_text(doc.session_summary)
        session.conversation_info = Redactor.redact_json([c.model_dump() for c in doc.conversation_info])
        session.is_malicious = doc.is_malicious
        session.blocked_reason = Redactor.redact_text(doc.blocked_reason)
        session.created_at_ts = doc.created_at
        session.updated_at_ts = doc.updated_at
        updated += 1
    await db.commit()
    return BulkUpdateAgenticSessionContextResponse(success=True, updated_count=updated)


@router.get("/sessions")
async def list_sessions(
    malicious_only: bool = False,
    limit: int = 50,
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List agentic sessions."""
    account_id = payload.get("account_id")
    stmt = select(AgenticSession).where(AgenticSession.account_id == account_id).limit(limit)
    if malicious_only:
        stmt = stmt.where(AgenticSession.is_malicious == True)
    result = await db.execute(stmt)
    sessions = result.scalars().all()
    return {
        "total": len(sessions),
        "sessions": [
            {
                "id": s.id,
                "session_identifier": s.session_identifier,
                "session_summary": Redactor.redact_text(s.session_summary or ""),
                "is_malicious": s.is_malicious,
                "blocked_reason": Redactor.redact_text(s.blocked_reason or ""),
                "conversation_count": len(s.conversation_info or []),
                "created_at": str(s.created_at),
            }
            for s in sessions
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# http_response_param — Traffic ingestion (Kafka-alternative REST endpoint)
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/http-traffic")
async def ingest_http_traffic(
    body: dict = Body(...),
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest an HttpResponseParam protobuf-equivalent JSON payload.
    This is the REST alternative to Akto's Kafka-based traffic mirroring.

    Expected fields (mirrors http_response_param.proto):
      method, path, requestHeaders, responseHeaders, requestPayload,
      responsePayload, statusCode, sourceIp, destIp, time, apiCollectionId
    """
    account_id = payload.get("account_id")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")
    if "method" not in body or "path" not in body:
        raise HTTPException(status_code=422, detail="method and path are required")

    quota = await check_ingest_quota(account_id, cost=1)
    if not quota.allowed:
        raise HTTPException(
            status_code=429,
            detail="Ingestion rate limit exceeded",
        )

    job_id = str(uuid.uuid4())
    job = IngestionJob(
        id=job_id,
        account_id=account_id,
        job_type="http_traffic",
        status="QUEUED",
        accepted_count=1,
    )
    db.add(job)
    await db.commit()

    queued = await ingestion_queue.enqueue(
        IngestionJobItem(
            job_id=job_id,
            account_id=account_id,
            job_type="http_traffic",
            payload=Redactor.redact_json(body),
        )
    )
    if not queued:
        job.status = "FAILED"
        job.error_message = "Queue full"
        await db.commit()
        raise HTTPException(status_code=429, detail="Ingestion queue is full")

    return {
        "status": "queued",
        "job_id": job_id,
    }
