from __future__ import annotations

import datetime
import json
import re
import uuid
from typing import Any
from urllib.parse import parse_qsl, urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import APICollection, APIEndpoint, RequestLog
from server.modules.api_inventory.path_normalizer import PathNormalizer
from server.modules.ingestion.redaction import redact_ingestion_path
from server.modules.ingestion.sensor_time import coerce_sensor_ts_ms

from .models import DetectionEnvelope, NormalizationResult
from .state_store import state_store

_path_normalizer = PathNormalizer()
_BEARER_RE = re.compile(r"bearer\s+(?P<token>.+)", re.I)


def _lower_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _body_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def _query_params_from_path(path: str) -> dict[str, Any]:
    try:
        parsed = urlparse(path)
        return {k: v for k, v in parse_qsl(parsed.query, keep_blank_values=True)}
    except Exception:
        return {}


def _utc_now_ms() -> int:
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)


def _datetime_from_ms(timestamp_ms: int) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(timestamp_ms / 1000, tz=datetime.timezone.utc)


class NormalizationAgent:
    async def normalize(
        self,
        db: AsyncSession,
        account_id: int,
        source_type: str,
        raw_event: dict[str, Any],
        *,
        persist_request_log: bool = True,
        existing_endpoint_id: str | None = None,
        existing_actor_id: str | None = None,
        context_source: str | None = None,
    ) -> NormalizationResult:
        source_type = source_type.lower()
        if source_type == "api_traffic":
            envelope = await self._from_api_traffic(db, account_id, raw_event, persist_request_log, existing_endpoint_id, existing_actor_id, context_source or "EVENT_BATCH")
        elif source_type in {"sensor_flat", "stream_ebpf"}:
            envelope = await self._from_sensor_flat(db, account_id, raw_event, persist_request_log, existing_endpoint_id, context_source or "EBPF_SENSOR")
        elif source_type in {"gateway_log", "stream_line", "nginx_log"}:
            envelope = await self._from_log_entry(db, account_id, raw_event, persist_request_log, existing_endpoint_id, context_source or "GATEWAY_LOG")
        elif source_type == "stream_enriched":
            envelope = self._from_stream_enriched(account_id, raw_event, context_source or "STREAM_ENRICHED")
        elif source_type == "auth_failure_aggregate":
            envelope = self._from_auth_failure_aggregate(account_id, raw_event, context_source or "STREAM_AGGREGATE")
        elif source_type == "http_traffic":
            envelope = await self._from_http_traffic(db, account_id, raw_event, persist_request_log, context_source or "HTTP_TRAFFIC")
        else:
            raise ValueError(f"Unsupported source_type '{source_type}'")

        object_key, object_key_hash = state_store.extract_object_reference(envelope)
        envelope.object_key = object_key
        envelope.object_key_hash = object_key_hash
        envelope.request_size = state_store.normalize_request_size(envelope)
        envelope.response_size = state_store.normalize_response_size(envelope)
        return NormalizationResult(
            envelope=envelope,
            persisted_request_log=bool(envelope.request_log_id),
            persisted_endpoint=bool(envelope.endpoint_id),
        )

    async def _from_api_traffic(self, db: AsyncSession, account_id: int, raw_event: dict[str, Any], persist_request_log: bool, existing_endpoint_id: str | None, existing_actor_id: str | None, context_source: str) -> DetectionEnvelope:
        request = raw_event.get("request") or {}
        response = raw_event.get("response") or {}
        headers = _lower_headers(request.get("headers"))
        method = str(request.get("method") or "GET").upper()
        path = str(request.get("path") or "/")
        host = str(request.get("host") or "unknown")
        protocol = str(raw_event.get("protocol") or request.get("scheme") or "HTTP/1.1")
        observed_at_ms = int(raw_event.get("observed_at") or raw_event.get("timestamp_ms") or _utc_now_ms())
        actor_id = existing_actor_id or self._resolve_actor_id(raw_event, headers)
        payload = raw_event.get("jwt_payload") or {}
        envelope = DetectionEnvelope(
            source_type="api_traffic",
            account_id=account_id,
            observed_at_ms=observed_at_ms,
            actor_id=actor_id,
            source_ip=str(raw_event.get("source_ip") or headers.get("x-forwarded-for") or actor_id or ""),
            method=method,
            path=path,
            host=host,
            protocol=protocol,
            endpoint_id=existing_endpoint_id,
            endpoint_scope=_path_normalizer.normalize(path.split("?")[0]),
            status_code=int(response.get("status_code") or response.get("status") or 200),
            latency_ms=response.get("latency_ms"),
            request_headers=headers,
            response_headers=_lower_headers(response.get("headers")),
            query_params=request.get("query") or _query_params_from_path(path),
            request_body_text=_body_text(request.get("body")),
            response_body_text=_body_text(response.get("body")),
            role=payload.get("role"),
            session_id=headers.get("x-session-id") or headers.get("cookie"),
            token_jti=payload.get("jti"),
            user_id=payload.get("user_id"),
            geo_country=raw_event.get("geo_country"),
            context_source=context_source,
            raw_ref=raw_event,
            metadata={"quality_score": raw_event.get("quality_score")},
        )
        if persist_request_log:
            await self._persist_request_log(db, envelope)
        return envelope

    async def _from_sensor_flat(self, db: AsyncSession, account_id: int, raw_event: dict[str, Any], persist_request_log: bool, existing_endpoint_id: str | None, context_source: str) -> DetectionEnvelope:
        request = raw_event.get("request") or {}
        response = raw_event.get("response") or {}
        headers = _lower_headers(request.get("headers") or raw_event.get("headers"))
        method = str(request.get("method") or raw_event.get("method") or "GET").upper()
        path = str(request.get("path") or raw_event.get("path") or "/")
        host = str(request.get("host") or raw_event.get("host") or "unknown")
        ts_raw = raw_event.get("observed_at") or raw_event.get("ts")
        observed_at_ms = coerce_sensor_ts_ms(ts_raw)
        actor_id = str(raw_event.get("source_ip") or raw_event.get("src_ip") or headers.get("x-forwarded-for") or "anonymous")
        envelope = DetectionEnvelope(
            source_type="sensor_flat",
            account_id=account_id,
            observed_at_ms=observed_at_ms,
            actor_id=actor_id,
            source_ip=actor_id,
            method=method,
            path=path,
            host=host,
            protocol=str(raw_event.get("protocol") or "HTTP/1.1"),
            endpoint_id=existing_endpoint_id,
            endpoint_scope=_path_normalizer.normalize(path.split("?")[0]),
            status_code=int(response.get("status") or raw_event.get("status_code") or raw_event.get("status") or 0),
            latency_ms=response.get("latency_ms"),
            request_headers=headers,
            response_headers=_lower_headers(response.get("headers")),
            query_params=_query_params_from_path(path),
            request_body_text=_body_text(request.get("body")),
            response_body_text=_body_text(response.get("body")),
            session_id=headers.get("x-session-id") or headers.get("cookie"),
            context_source=context_source,
            raw_ref=raw_event,
            metadata={"sensor_flagged_injection": bool(raw_event.get("has_injection")), "container": raw_event.get("container") or {}, "dest_port": raw_event.get("dest_port") or raw_event.get("dst_port")},
        )
        if persist_request_log:
            await self._persist_request_log(db, envelope)
        return envelope

    async def _from_log_entry(self, db: AsyncSession, account_id: int, raw_event: dict[str, Any], persist_request_log: bool, existing_endpoint_id: str | None, context_source: str) -> DetectionEnvelope:
        ts = raw_event.get("time") or raw_event.get("ts")
        observed_at_ms = int(ts.timestamp() * 1000) if isinstance(ts, datetime.datetime) else _utc_now_ms()
        envelope = DetectionEnvelope(
            source_type="gateway_log",
            account_id=account_id,
            observed_at_ms=observed_at_ms,
            actor_id=str(raw_event.get("ip") or raw_event.get("source_ip") or "anonymous"),
            source_ip=str(raw_event.get("ip") or raw_event.get("source_ip") or ""),
            method=str(raw_event.get("method") or "GET").upper(),
            path=str(raw_event.get("path") or "/"),
            host=str(raw_event.get("host") or "unknown"),
            endpoint_id=existing_endpoint_id,
            endpoint_scope=_path_normalizer.normalize(str(raw_event.get("path") or "/").split("?")[0]),
            status_code=int(raw_event.get("status") or 0),
            request_headers={"user-agent": str(raw_event.get("ua") or "")},
            query_params=_query_params_from_path(str(raw_event.get("path") or "/")),
            context_source=context_source,
            raw_ref=raw_event,
            metadata={"bytes": raw_event.get("bytes")},
        )
        if persist_request_log:
            await self._persist_request_log(db, envelope)
        return envelope

    def _from_stream_enriched(self, account_id: int, raw_event: dict[str, Any], context_source: str) -> DetectionEnvelope:
        return DetectionEnvelope(
            source_type="stream_enriched",
            account_id=account_id,
            observed_at_ms=int(raw_event.get("timestamp_ms") or _utc_now_ms()),
            actor_id=str(raw_event.get("actor_id") or "anonymous"),
            source_ip=str(raw_event.get("actor_id") or ""),
            method=str(raw_event.get("method") or "GET").upper(),
            path=str(raw_event.get("path") or "/"),
            host="unknown",
            protocol=str(raw_event.get("protocol") or "HTTP/1.1"),
            endpoint_id=raw_event.get("endpoint_id"),
            endpoint_scope=_path_normalizer.normalize(str(raw_event.get("path") or "/").split("?")[0]),
            status_code=int(raw_event.get("response_code") or 200),
            latency_ms=raw_event.get("latency_ms"),
            context_source=context_source,
            raw_ref=raw_event,
            metadata={"quality_score": raw_event.get("quality_score")},
        )

    def _from_auth_failure_aggregate(self, account_id: int, raw_event: dict[str, Any], context_source: str) -> DetectionEnvelope:
        path = str(raw_event.get("path") or "/auth")
        return DetectionEnvelope(
            source_type="auth_failure_aggregate",
            event_type="auth_aggregate",
            account_id=account_id,
            observed_at_ms=int(raw_event.get("timestamp_ms") or _utc_now_ms()),
            actor_id=str(raw_event.get("actor_id") or "multiple"),
            source_ip=str(raw_event.get("source_ip") or "multiple"),
            method=str(raw_event.get("method") or "POST").upper(),
            path=path,
            host="unknown",
            endpoint_id=raw_event.get("endpoint_id"),
            endpoint_scope=_path_normalizer.normalize(path),
            status_code=int(raw_event.get("status_code") or 401),
            context_source=context_source,
            raw_ref=raw_event,
            metadata={"auth_failure_count": raw_event.get("count", 0), "distinct_actors": raw_event.get("distinct_actors", 0)},
        )

    async def _from_http_traffic(self, db: AsyncSession, account_id: int, raw_event: dict[str, Any], persist_request_log: bool, context_source: str) -> DetectionEnvelope:
        method = str(raw_event.get("method") or "GET").upper()
        path = str(raw_event.get("path") or "/")
        request_headers = _lower_headers(raw_event.get("requestHeaders") or raw_event.get("request_headers"))
        response_headers = _lower_headers(raw_event.get("responseHeaders") or raw_event.get("response_headers"))
        envelope = DetectionEnvelope(
            source_type="http_traffic",
            account_id=account_id,
            observed_at_ms=_utc_now_ms(),
            actor_id=str(raw_event.get("sourceIp") or raw_event.get("source_ip") or "anonymous"),
            source_ip=str(raw_event.get("sourceIp") or raw_event.get("source_ip") or ""),
            method=method,
            path=path,
            host=str(raw_event.get("host") or "unknown"),
            endpoint_scope=_path_normalizer.normalize(path.split("?")[0]),
            status_code=int(raw_event.get("statusCode") or raw_event.get("status_code") or 200),
            request_headers=request_headers,
            response_headers=response_headers,
            query_params=_query_params_from_path(path),
            request_body_text=_body_text(raw_event.get("requestPayload") or raw_event.get("request_payload")),
            response_body_text=_body_text(raw_event.get("responsePayload") or raw_event.get("response_payload")),
            context_source=context_source,
            raw_ref=raw_event,
        )
        if persist_request_log:
            await self._persist_request_log(db, envelope)
        return envelope

    async def _persist_request_log(self, db: AsyncSession, envelope: DetectionEnvelope) -> None:
        log = RequestLog(
            id=str(uuid.uuid4()),
            account_id=envelope.account_id,
            endpoint_id=envelope.endpoint_id,
            source_ip=envelope.source_ip or envelope.actor_id,
            method=envelope.method,
            path=redact_ingestion_path(envelope.path),
            response_code=envelope.status_code,
            response_time_ms=envelope.latency_ms,
            created_at=_datetime_from_ms(envelope.observed_at_ms),
        )
        db.add(log)
        await db.flush()
        envelope.request_log_id = log.id

    def _resolve_actor_id(self, raw_event: dict[str, Any], headers: dict[str, str]) -> str:
        payload = raw_event.get("jwt_payload") or {}
        auth_header = headers.get("authorization") or ""
        match = _BEARER_RE.match(auth_header)
        bearer_hint = match.group("token")[:12] if match else None
        return str(payload.get("user_id") or headers.get("x-api-client-id") or headers.get("x-api-key") or headers.get("x-forwarded-for") or raw_event.get("source_ip") or bearer_hint or "anonymous")

    async def ensure_endpoint(self, db: AsyncSession, account_id: int, method: str, path: str, host: str, protocol: str, status_code: int, observed_at_ms: int) -> str:
        clean_path = path.split("?")[0]
        path_pattern = _path_normalizer.normalize(clean_path)
        result = await db.execute(
            select(APIEndpoint).where(
                APIEndpoint.account_id == account_id,
                APIEndpoint.method == method,
                APIEndpoint.path_pattern == path_pattern,
                APIEndpoint.host == host,
            )
        )
        endpoint = result.scalar_one_or_none()
        if endpoint:
            endpoint.last_seen = _datetime_from_ms(observed_at_ms)
            endpoint.last_response_code = status_code
            return endpoint.id

        collection_result = await db.execute(
            select(APICollection).where(
                APICollection.account_id == account_id,
                APICollection.name == "Default Inventory",
            )
        )
        collection = collection_result.scalar_one_or_none()
        if collection is None:
            collection = APICollection(account_id=account_id, name="Default Inventory", host="all-hosts", type="MIRRORING")
            db.add(collection)
            await db.flush()

        endpoint = APIEndpoint(
            id=str(uuid.uuid4()),
            account_id=account_id,
            collection_id=collection.id,
            method=method,
            path=clean_path,
            path_pattern=path_pattern,
            host=host,
            protocol=protocol,
            last_response_code=status_code,
            last_seen=_datetime_from_ms(observed_at_ms),
            status="ACTIVE",
            api_type="REST",
        )
        db.add(endpoint)
        await db.flush()
        return endpoint.id


normalization_agent = NormalizationAgent()
