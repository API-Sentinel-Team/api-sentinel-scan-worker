"""Turn a captured HAR-shaped flow entry into inventory + evidence records.

This is the real body-capture path the north-star strategy settled on: rather
than adopting DeepFlow (whose l7_flow_log schema carries method/path/host/
status/latency but, confirmed against its own docs, no request/response body
field), a TLS-terminating proxy sees full plaintext bodies by construction.
mitmproxy_integration.py (the addon mitmdump loads) converts a captured flow
into the HAR-shaped dict this module consumes — kept mitmproxy-free so it is
importable and unit-testable without the mitmproxy package installed.

Mirrors the same golden-path persistence contract
`server.modules.ingestion.processors.process_event_batch` uses for the
structured `api_traffic` event type: endpoint upsert with body columns,
tenant-retention-policy redaction before persisting SampleData, and PII
scanning that promotes response-body findings into evidence-grade
Vulnerability records via persist_sensitive_data_exposure.
"""
from __future__ import annotations

import datetime
import json
import uuid
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import RequestLog, SampleData, Sensor, SensitiveDataFinding
from server.modules.api_inventory.endpoint_discovery import EndpointDiscovery
from server.modules.passive.findings import persist_sensitive_data_exposure
from server.modules.privacy.retention import apply_retention_policy, get_retention_policy
from server.modules.sensors.keys import resolve_sensor_by_key
from server.modules.utils.redactor import Redactor
from server.modules.vulnerability_detector.pii_scanner import PIIScanner

_pii = PIIScanner()


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _headers_dict(pairs: Any) -> dict[str, str]:
    """Flatten HAR's ``[{"name": ..., "value": ...}, ...]`` header list."""
    if not isinstance(pairs, list):
        return {}
    out: dict[str, str] = {}
    for item in pairs:
        if isinstance(item, dict) and item.get("name") is not None:
            out[str(item["name"])] = str(item.get("value") or "")
    return out


def _parsed_body(text: Any) -> Any:
    """Best-effort JSON parse of a HAR body/content.text string.

    Falls back to a ``{"raw": text}`` wrapper (matching the existing HAR
    import path in traffic.py) so a non-JSON body is still scanned/stored
    rather than dropped, and returns None for an empty/absent body so it
    doesn't get treated as "present" downstream.
    """
    if not text:
        return None
    if not isinstance(text, str):
        return text
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return {"raw": text}


def _query_dict(pairs: Any) -> dict[str, str]:
    if not isinstance(pairs, list):
        return {}
    out: dict[str, str] = {}
    for item in pairs:
        if isinstance(item, dict) and item.get("name") is not None:
            out[str(item["name"])] = str(item.get("value") or "")
    return out


async def resolve_mitmproxy_sensor(db: AsyncSession) -> Sensor | None:
    """Resolve the Sensor row for the configured MITMPROXY_SENSOR_API_KEY.

    Returns None when no key is configured or the key doesn't match a
    registered sensor — the caller decides whether/how to log that.
    """
    raw_key = (settings.MITMPROXY_SENSOR_API_KEY or "").strip()
    if not raw_key:
        return None
    return await resolve_sensor_by_key(db, raw_key)


async def process_captured_flow(db: AsyncSession, *, entry: dict[str, Any]) -> dict[str, Any]:
    """Resolve the mitmproxy sensor's account, then persist one captured flow.

    Returns a summary dict (never raises for a malformed/incomplete entry —
    callers wrap this in try/except anyway, but this keeps a single bad flow
    from ever being able to take down a long-running mitmdump process).
    Does not commit; the caller owns the transaction boundary.
    """
    sensor = await resolve_mitmproxy_sensor(db)
    if sensor is None:
        return {"skipped": True, "reason": "sensor_not_configured_or_unknown"}

    account_id = int(sensor.account_id)
    sensor.last_heartbeat = _utc_now()
    sensor.status = "ONLINE"
    sensor.lines_shipped = (sensor.lines_shipped or 0) + 1

    return await persist_captured_flow(db, account_id=account_id, entry=entry, source="mitmproxy")


async def persist_captured_flow(
    db: AsyncSession, *, account_id: int, entry: dict[str, Any], source: str = "traffic_capture"
) -> dict[str, Any]:
    """Persist one HAR-shaped captured flow: endpoint + redacted bodies + PII.

    Account-agnostic — shared by the mitmproxy sensor path (process_captured_flow,
    which resolves account_id from a sensor key) and any other already-authenticated
    body-capable ingestion path (e.g. the /traffic/har/upload endpoint, which has
    account_id from the caller's JWT). Does not commit.
    """
    request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
    response = entry.get("response") if isinstance(entry.get("response"), dict) else {}

    url = str(request.get("url") or "")
    if not url:
        return {"skipped": True, "reason": "missing_request_url"}
    parsed = urlparse(url)

    method = str(request.get("method") or "GET").upper()
    status_code = int(response.get("status") or 0) or 200

    req_headers = _headers_dict(request.get("headers"))
    resp_headers = _headers_dict((response.get("headers")))
    # Request body: HARConverter's own simplified shape puts it directly under
    # "body"; a real HAR 1.2 file (e.g. uploaded from browser devtools) nests it
    # under postData.text per spec. Accept either.
    raw_req_body = request.get("body")
    if raw_req_body is None and isinstance(request.get("postData"), dict):
        raw_req_body = request["postData"].get("text")
    req_body = _parsed_body(raw_req_body)
    resp_body = _parsed_body((response.get("content") or {}).get("text") if isinstance(response.get("content"), dict) else None)
    query = _query_dict(request.get("queryString"))

    discovery_entry = {
        "account_id": account_id,
        "source": source,
        "request": {"url": url, "method": method},
        "response": {"status": status_code},
        "query_string": "&".join(f"{k}={v}" for k, v in query.items()) if query else None,
        "last_seen": _utc_now(),
    }
    endpoint = await EndpointDiscovery(db).discover(discovery_entry, commit=False)

    policy = await get_retention_policy(db, account_id)
    redacted = apply_retention_policy(
        policy,
        {"headers": req_headers, "body": req_body},
        {"headers": resp_headers, "body": resp_body},
    )

    endpoint.last_response_code = status_code
    if query:
        endpoint.last_query_string = json.dumps(query)
    endpoint.last_request_body = (
        json.dumps(redacted["request_body"])
        if isinstance(redacted["request_body"], (dict, list))
        else (str(redacted["request_body"]) if redacted["request_body"] is not None else None)
    )
    endpoint.last_response_body = (
        json.dumps(redacted["response_body"])
        if isinstance(redacted["response_body"], (dict, list))
        else (str(redacted["response_body"]) if redacted["response_body"] is not None else None)
    )
    endpoint.last_response_headers = redacted["response_headers"]

    db.add(
        SampleData(
            id=str(uuid.uuid4()),
            account_id=account_id,
            endpoint_id=endpoint.id,
            request={"headers": redacted["request_headers"], "body": redacted["request_body"]},
            response={"headers": redacted["response_headers"], "body": redacted["response_body"]},
        )
    )
    db.add(
        RequestLog(
            id=str(uuid.uuid4()),
            account_id=account_id,
            endpoint_id=endpoint.id,
            source_ip=None,
            method=method,
            path=Redactor.redact_url(endpoint.path or parsed.path or "/"),
            response_code=status_code,
        )
    )

    pii_findings_count = 0
    for finding in _pii.scan_payload(req_body):
        pii_findings_count += 1
        db.add(
            SensitiveDataFinding(
                account_id=account_id,
                endpoint_id=endpoint.id,
                entity_type=finding.get("entity_type"),
                sample_value=Redactor.REDACT_VALUE,
                source="request",
                confidence=0.6,
            )
        )
    for finding in _pii.scan_payload(resp_body):
        pii_findings_count += 1
        db.add(
            SensitiveDataFinding(
                account_id=account_id,
                endpoint_id=endpoint.id,
                entity_type=finding.get("entity_type"),
                sample_value=Redactor.REDACT_VALUE,
                source="response",
                confidence=0.6,
            )
        )
        await persist_sensitive_data_exposure(
            db,
            account_id=account_id,
            endpoint_id=endpoint.id,
            entity_type=finding.get("entity_type"),
            source="response",
            path=endpoint.path,
            method=method,
        )

    await db.flush()
    return {
        "skipped": False,
        "account_id": account_id,
        "endpoint_id": endpoint.id,
        "method": method,
        "path": endpoint.path,
        "status_code": status_code,
        "pii_findings": pii_findings_count,
    }
