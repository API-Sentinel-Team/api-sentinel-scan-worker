import datetime
import json
import logging
import time
import uuid
import hashlib
from typing import Any, Dict, List

from sqlalchemy import insert, select, update, func

from server.models.core import (
    Alert,
    IngestionDeadLetter,
    IngestionJob,
    MaliciousEventRecord,
    RequestLog,
    Sensor,
    APIEndpoint,
    SampleData,
    EndpointRevision,
    OpenAPISpec,
    GovernanceRule,
    PolicyViolation,
    SensitiveDataFinding,
    EvidenceRecord,
    TestResult,
    Vulnerability,
)
from server.modules.detection.engine import detect_api_behavior
from server.modules.detection.pipeline import unified_detection_pipeline
from server.modules.business_logic.graph_builder import detect_transition_violation
from server.modules.cache.redis_cache import bump_cache_version
from server.modules.ingestion.parsers import detect_attacks, parse_log_line
from server.modules.ingestion.dead_letter import redact_dead_letter_error, redact_dead_letter_payload
from server.modules.ingestion.redaction import redact_ingestion_path
from server.modules.ingestion.schema import EventUnion
from pydantic import TypeAdapter
from server.modules.ingestion.quality import compute_quality
from server.modules.persistence.database import AsyncSessionLocal, apply_tenant_context
from server.modules.tenancy.context import set_current_account_id
from server.api.websocket.manager import ws_manager
from server.modules.utils.redactor import Redactor
from server.modules.privacy.retention import get_retention_policy, apply_retention_policy
from server.modules.api_inventory.path_normalizer import PathNormalizer
from server.modules.vulnerability_detector.pii_scanner import PIIScanner
from server.modules.streaming.event_bus import get_event_bus, tenant_topic, track_topic
from server.modules.agentic.mcp_security import record_tool_invocation
from server.modules.agentic.mcp_parser import parse_mcp_invocation
from server.modules.llm.findings import persist_llm_api_findings
from server.modules.passive.findings import persist_passive_attack_signal, persist_sensitive_data_exposure
from server.modules.vulnerability_detector.store import create_or_merge_vulnerability
from server.config import settings

logger = logging.getLogger(__name__)


def func_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


_normalizer = PathNormalizer()
_pii = PIIScanner()


def _infer_schema_from_body(body: Any) -> Dict[str, Any]:
    if body is None:
        return {"type": "object"}
    if isinstance(body, str):
        try:
            data = json.loads(body)
        except Exception:
            return {"type": "string"}
        return _infer_schema_from_body(data)
    if isinstance(body, dict):
        return {"type": "object", "properties": {k: _infer_schema_from_body(v) for k, v in body.items()}}
    if isinstance(body, list):
        item_schema = _infer_schema_from_body(body[0]) if body else {"type": "object"}
        return {"type": "array", "items": item_schema}
    if isinstance(body, bool):
        return {"type": "boolean"}
    if isinstance(body, (int, float)):
        return {"type": "number"}
    return {"type": "string"}


def _resolve_actor(event: Dict[str, Any]) -> str:
    req = event.get("request") or {}
    headers = req.get("headers") or {}
    actor = headers.get("x-api-client-id") or headers.get("x-api-key")
    if not actor:
        actor = event.get("source_ip") or str(headers.get("x-forwarded-for") or "unknown")
    return actor or "anonymous"


def _observed_at_datetime(value: Any) -> datetime.datetime:
    try:
        timestamp = float(value)
    except (TypeError, ValueError):
        return func_now()
    if timestamp > 1_000_000_000_000:
        timestamp = timestamp / 1000
    try:
        return datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return func_now()


def _elapsed_ms(later: datetime.datetime | None, earlier: datetime.datetime | None) -> int | None:
    if later is None or earlier is None:
        return None
    return int((later - earlier).total_seconds() * 1000)


async def _record_revision(db: Any, account_id: int, endpoint_id: str, schema_json: Dict[str, Any]) -> None:
    encoded = json.dumps(schema_json, sort_keys=True)
    version_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    existing = await db.execute(
        select(EndpointRevision)
        .where(EndpointRevision.endpoint_id == endpoint_id)
        .order_by(EndpointRevision.created_at.desc())
        .limit(1)
    )
    last = existing.scalar_one_or_none()
    if last and last.version_hash == version_hash:
        return
    db.add(EndpointRevision(
        account_id=account_id,
        endpoint_id=endpoint_id,
        version_hash=version_hash,
        schema_json=schema_json,
    ))


async def _apply_governance_rules(db: Any, account_id: int, endpoint: APIEndpoint) -> None:
    rules_result = await db.execute(
        select(GovernanceRule).where(
            GovernanceRule.account_id == account_id,
            GovernanceRule.enabled == True,
        )
    )
    rules = rules_result.scalars().all()
    for rule in rules:
        cond = rule.condition or {}
        field = cond.get("field", "")
        op = cond.get("op", "eq")
        value = cond.get("value", "")
        ep_val = getattr(endpoint, field, None)
        if ep_val is None:
            continue
        violated = False
        if op == "eq" and str(ep_val).lower() == str(value).lower():
            violated = True
        elif op == "neq" and str(ep_val).lower() != str(value).lower():
            violated = True
        elif op == "has_uppercase" and str(ep_val) != str(ep_val).lower():
            violated = True
        elif op == "contains" and str(value).lower() in str(ep_val).lower():
            violated = True
        if violated:
            violation = PolicyViolation(
                account_id=account_id,
                rule_id=rule.id,
                endpoint_id=endpoint.id,
                rule_type=rule.rule_type,
                severity="MEDIUM",
                message=f"Rule '{rule.name}' violated for {endpoint.method} {endpoint.path}",
                violation_metadata={"field": field, "value": str(ep_val), "expected": f"{op} {value}"},
            )
            db.add(violation)
            db.add(EvidenceRecord(
                account_id=account_id,
                evidence_type="policy",
                ref_id=violation.id,
                endpoint_id=endpoint.id,
                severity="MEDIUM",
                summary=violation.message,
            ))
            rule.violation_count = (rule.violation_count or 0) + 1


async def _apply_openapi_conformance(db: Any, account_id: int, endpoint: APIEndpoint) -> None:
    spec_result = await db.execute(
        select(OpenAPISpec)
        .where(OpenAPISpec.account_id == account_id)
        .order_by(OpenAPISpec.created_at.desc())
        .limit(1)
    )
    spec = spec_result.scalar_one_or_none()
    if not spec:
        return
    paths = (spec.spec_json or {}).get("paths", {})
    path_entry = paths.get(endpoint.path or "")
    if not path_entry or endpoint.method.lower() not in path_entry:
        violation = PolicyViolation(
            account_id=account_id,
            rule_type="SCHEMA",
            severity="HIGH",
            endpoint_id=endpoint.id,
            message=f"Endpoint {endpoint.method} {endpoint.path} missing from OpenAPI spec",
        )
        db.add(violation)
        db.add(EvidenceRecord(
            account_id=account_id,
            evidence_type="policy",
            ref_id=violation.id,
            endpoint_id=endpoint.id,
            severity="HIGH",
            summary=violation.message,
        ))


async def _update_risk_score(db: Any, endpoint: APIEndpoint, account_id: int) -> None:
    vuln_count = await db.scalar(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.account_id == account_id,
            Vulnerability.endpoint_id == endpoint.id,
            Vulnerability.status == "OPEN",
        )
    ) or 0
    violation_count = await db.scalar(
        select(func.count(PolicyViolation.id)).where(
            PolicyViolation.account_id == account_id,
            PolicyViolation.endpoint_id == endpoint.id,
            PolicyViolation.status == "OPEN",
        )
    ) or 0
    pii_count = await db.scalar(
        select(func.count(SensitiveDataFinding.id)).where(
            SensitiveDataFinding.account_id == account_id,
            SensitiveDataFinding.endpoint_id == endpoint.id,
        )
    ) or 0
    endpoint.risk_score = min(100.0, vuln_count * 20 + violation_count * 5 + pii_count * 2)


async def _update_job(job_id: str, account_id: int | None = None, **fields: Any) -> None:
    async with AsyncSessionLocal() as db:
        if account_id is not None:
            set_current_account_id(account_id)
            await apply_tenant_context(db)
        await db.execute(
            update(IngestionJob).where(IngestionJob.id == job_id).values(**fields)
        )
        await db.commit()


async def process_stream_lines(job_id: str, account_id: int, payload: Dict[str, Any]) -> None:
    await _update_job(job_id, account_id=account_id, status="RUNNING", started_at=func_now())
    lines: List[str] = payload.get("lines") or []
    sensor_id = payload.get("sensor_id")

    async with AsyncSessionLocal() as db:
        set_current_account_id(account_id)
        await apply_tenant_context(db)
        sensor = None
        if sensor_id:
            result = await db.execute(
                select(Sensor).where(
                    Sensor.id == sensor_id,
                    Sensor.account_id == account_id,
                )
            )
            sensor = result.scalar_one_or_none()

        logs: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        alerts: List[Dict[str, Any]] = []
        pipeline_mode = unified_detection_pipeline.mode()

        lines_processed = 0
        threats_detected = 0

        events_for_ws: List[Dict[str, Any]] = []
        for line in lines:
            parsed = parse_log_line(line)
            if not parsed:
                continue
            safe_path = redact_ingestion_path(parsed["path"])
            lines_processed += 1
            if pipeline_mode == "active":
                result = await unified_detection_pipeline.process(
                    db,
                    account_id=account_id,
                    source_type="stream_line",
                    raw_event=parsed,
                    persist_request_log=True,
                    context_source="GATEWAY_LOG",
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
                        source_type="stream_line",
                        raw_event=parsed,
                        persist_request_log=False,
                        context_source="GATEWAY_LOG",
                        shadow=True,
                    )

                attacks = detect_attacks(parsed["path"], parsed["ua"])
                log_id = str(uuid.uuid4())
                logs.append({
                    "id": log_id,
                    "account_id": account_id,
                    "source_ip": parsed["ip"],
                    "method": parsed["method"],
                    "path": safe_path,
                    "response_code": parsed["status"],
                    "created_at": parsed["time"],
                })

                for attack in attacks:
                    threats_detected += 1
                    events.append({
                        "id": str(uuid.uuid4()),
                        "account_id": account_id,
                        "actor": parsed["ip"],
                        "ip": parsed["ip"],
                        "url": safe_path,
                        "method": parsed["method"],
                        "category": attack["category"],
                        "severity": attack["severity"],
                        "detected_at": int(parsed["time"].timestamp() * 1000),
                        "status": "OPEN",
                    })
                    if attack["severity"] in {"CRITICAL", "HIGH"}:
                        alerts.append({
                            "id": str(uuid.uuid4()),
                            "account_id": account_id,
                            "title": f"{attack['category']} detected from {parsed['ip']}",
                            "message": f"Attack pattern matched on {parsed['method']} {safe_path}",
                            "severity": attack["severity"],
                            "category": attack["category"],
                            "source_ip": parsed["ip"],
                            "endpoint": safe_path,
                        })
                    await persist_passive_attack_signal(
                        db,
                        account_id=account_id,
                        category=attack["category"],
                        severity=attack["severity"],
                        response_code=parsed["status"],
                        url=safe_path,
                        method=parsed["method"],
                        source="stream_line",
                        actor=parsed["ip"],
                        evidence={
                            "user_agent": Redactor.redact_text(parsed.get("ua") or ""),
                            "referer": Redactor.redact_url(parsed.get("referer") or ""),
                            "bytes": parsed.get("bytes"),
                        },
                    )
            events_for_ws.append({
                "type": "log_entry",
                "data": {
                    "ip": parsed["ip"],
                    "method": parsed["method"],
                    "path": safe_path,
                    "status": parsed["status"],
                    "bytes": parsed["bytes"],
                    "timestamp": parsed["time"].isoformat(),
                    "attacks": attacks,
                    "blocked": False,
                },
            })

        if logs:
            await db.execute(insert(RequestLog), logs)
        if events:
            await db.execute(insert(MaliciousEventRecord), events)
        if alerts:
            await db.execute(insert(Alert), alerts)

        if sensor:
            sensor.lines_shipped = (sensor.lines_shipped or 0) + lines_processed
            sensor.events_detected = (sensor.events_detected or 0) + threats_detected
            sensor.status = "ONLINE"
            sensor.last_heartbeat = func_now()

        await db.commit()

        for event_msg in events_for_ws:
            try:
                await ws_manager.broadcast(event_msg, account_id=account_id)
            except Exception:
                break

    await bump_cache_version(account_id)
    await _update_job(
        job_id,
        status="COMPLETED",
        processed_count=lines_processed,
        threats_detected=threats_detected,
        completed_at=func_now(),
    )


async def process_http_traffic(job_id: str, account_id: int, payload: Dict[str, Any]) -> None:
    await _update_job(job_id, account_id=account_id, status="RUNNING", started_at=func_now())

    method = payload.get("method", "GET")
    path = payload.get("path", "/")
    safe_path = redact_ingestion_path(path)
    source_ip = payload.get("sourceIp", payload.get("source_ip", ""))
    status_code = payload.get("statusCode", payload.get("status_code", 200))
    request_payload = payload.get("requestPayload", payload.get("request_payload", ""))
    response_payload = payload.get("responsePayload", payload.get("response_payload", ""))
    request_headers = payload.get("requestHeaders", payload.get("request_headers", {}))
    response_headers = payload.get("responseHeaders", payload.get("response_headers", {}))
    api_collection_id = payload.get("apiCollectionId", payload.get("api_collection_id", 0))

    threats = []
    pipeline_mode = unified_detection_pipeline.mode()
    payload_combined = (request_payload or "") + " " + (path or "")
    sql_patterns = ["'", "OR 1=1", "UNION SELECT", "--", "DROP TABLE"]
    cmd_patterns = [";ls", "|cat", "&&id", "`whoami`", "$(id)"]
    xss_patterns = ["<script", "javascript:", "onerror=", "alert("]

    for p in sql_patterns:
        if p.lower() in payload_combined.lower():
            threats.append(("SQL_INJECTION", "HIGH"))
            break
    for p in cmd_patterns:
        if p.lower() in payload_combined.lower():
            threats.append(("COMMAND_INJECTION", "CRITICAL"))
            break
    for p in xss_patterns:
        if p.lower() in payload_combined.lower():
            threats.append(("XSS", "MEDIUM"))
            break

    async with AsyncSessionLocal() as db:
        set_current_account_id(account_id)
        await apply_tenant_context(db)
        if pipeline_mode == "active":
            result = await unified_detection_pipeline.process(
                db,
                account_id=account_id,
                source_type="http_traffic",
                raw_event=payload,
                persist_request_log=True,
                context_source="HTTP_TRAFFIC",
            )
            threats = [(signal.category, signal.severity) for signal in result["signals"]]
        else:
            if pipeline_mode == "shadow":
                await unified_detection_pipeline.process(
                    db,
                    account_id=account_id,
                    source_type="http_traffic",
                    raw_event=payload,
                    persist_request_log=False,
                    context_source="HTTP_TRAFFIC",
                    shadow=True,
                )

            await db.execute(
                insert(RequestLog),
                [{
                    "id": str(uuid.uuid4()),
                    "account_id": account_id,
                    "source_ip": source_ip,
                    "method": method,
                    "path": safe_path,
                    "response_code": status_code,
                }],
            )

            events = []
            for category, severity in threats:
                events.append({
                    "id": str(uuid.uuid4()),
                    "account_id": account_id,
                    "actor": source_ip,
                    "ip": source_ip,
                    "url": safe_path,
                    "method": method,
                    "payload": Redactor.redact_text((request_payload or "")[:2000]),
                    "event_type": "EVENT_TYPE_SINGLE",
                    "category": category,
                    "sub_category": category,
                    "severity": severity,
                    "detected_at": int(time.time() * 1000),
                    "status": "OPEN",
                    "api_collection_id": api_collection_id,
                    "event_metadata": {
                        "request_headers": Redactor.redact_headers(request_headers or {}),
                        "response_headers": Redactor.redact_headers(response_headers or {}),
                        "response_payload": Redactor.redact_text((response_payload or "")[:2000]),
                    },
                })

            if events:
                await db.execute(insert(MaliciousEventRecord), events)
                for event_record in events:
                    await persist_passive_attack_signal(
                        db,
                        account_id=account_id,
                        category=event_record.get("category"),
                        severity=event_record.get("severity"),
                        response_code=status_code,
                        url=safe_path,
                        method=method,
                        source="http_traffic",
                        actor=source_ip,
                        evidence={
                            "payload": Redactor.redact_text((request_payload or "")[:500]),
                            "request_headers": Redactor.redact_headers(request_headers or {}),
                            "response_headers": Redactor.redact_headers(response_headers or {}),
                        },
                    )
        await db.commit()

    await bump_cache_version(account_id)
    await _update_job(
        job_id,
        status="COMPLETED",
        processed_count=1,
        threats_detected=len(threats),
        completed_at=func_now(),
    )


async def process_event_batch(job_id: str, account_id: int, payload: Dict[str, Any]) -> None:
    await _update_job(job_id, account_id=account_id, status="RUNNING", started_at=func_now())
    events = payload.get("events") or []
    processed = 0
    threats = 0
    errors = 0

    bus = get_event_bus()
    async with AsyncSessionLocal() as db:
        set_current_account_id(account_id)
        await apply_tenant_context(db)
        pipeline_mode = unified_detection_pipeline.mode()
        try:
            retention_policy = await get_retention_policy(db, account_id)
        except Exception:
            retention_policy = {"full_payload_retention": not settings.REDACT_PAYLOADS_BY_DEFAULT}
        adapter = TypeAdapter(EventUnion)
        for event in events:
            try:
                parsed_model = adapter.validate_python(event)
                event = parsed_model.model_dump()
            except Exception as exc:
                errors += 1
                db.add(IngestionDeadLetter(
                    job_id=job_id,
                    account_id=account_id,
                    payload=redact_dead_letter_payload(event),
                    error_message=f"event_validation_failed: {redact_dead_letter_error(exc)}",
                ))
                continue

            quality_score = compute_quality(event) if event.get("event_type") == "api_traffic" else 1.0
            if settings.INGESTION_DROP_LOW_QUALITY and quality_score < settings.INGESTION_MIN_QUALITY_SCORE:
                errors += 1
                db.add(IngestionDeadLetter(
                    job_id=job_id,
                    account_id=account_id,
                    payload=redact_dead_letter_payload(event),
                    error_message=f"low_quality_event: {quality_score:.2f}",
                ))
                continue

            etype = event.get("event_type")
            if etype == "api_traffic":
                processed += 1
                req = event.get("request") or {}
                resp = event.get("response") or {}
                method = (req.get("method") or "GET").upper()
                path = req.get("path") or "/"
                safe_path = redact_ingestion_path(path)
                host = req.get("host") or "unknown"
                scheme = req.get("scheme") or "http"
                port = 443 if scheme == "https" else 80
                path_pattern = _normalizer.normalize(path)

                policy = retention_policy or {"full_payload_retention": not settings.REDACT_PAYLOADS_BY_DEFAULT}
                redacted = apply_retention_policy(policy, req, resp)
                redacted_headers = redacted["request_headers"]
                redacted_body = redacted["request_body"]
                redacted_resp_headers = redacted["response_headers"]
                redacted_resp_body = redacted["response_body"]

                # upsert endpoint
                result = await db.execute(
                    select(APIEndpoint).where(
                        APIEndpoint.account_id == account_id,
                        APIEndpoint.host == host,
                        APIEndpoint.method == method,
                        APIEndpoint.path_pattern == path_pattern,
                    )
                )
                endpoint = result.scalar_one_or_none()
                if not endpoint:
                    endpoint = APIEndpoint(
                        id=str(uuid.uuid4()),
                        account_id=account_id,
                        method=method,
                        path=path,
                        path_pattern=path_pattern,
                        host=host,
                        protocol=scheme,
                        port=port,
                        collection_id=event.get("collection_id"),
                        last_seen=func_now(),
                    )
                    db.add(endpoint)
                    await db.flush()
                else:
                    endpoint.last_seen = func_now()
                    if event.get("collection_id"):
                        endpoint.collection_id = event.get("collection_id")
                    if endpoint.status in ("ZOMBIE", "SHADOW"):
                        endpoint.status = "ACTIVE"
                        # resolve any open shadow/zombie policy violations
                        await db.execute(
                            update(PolicyViolation)
                            .where(
                                PolicyViolation.account_id == account_id,
                                PolicyViolation.endpoint_id == endpoint.id,
                                PolicyViolation.rule_type.in_(["ZOMBIE_ENDPOINT", "SHADOW_ENDPOINT"]),
                                PolicyViolation.status == "OPEN",
                            )
                            .values(status="RESOLVED")
                        )
                endpoint.last_response_code = resp.get("status_code", endpoint.last_response_code)
                if req.get("query"):
                    endpoint.last_query_string = json.dumps(req.get("query"))
                endpoint.last_request_body = json.dumps(redacted_body) if isinstance(redacted_body, (dict, list)) else str(redacted_body)
                endpoint.last_response_body = json.dumps(redacted_resp_body) if isinstance(redacted_resp_body, (dict, list)) else str(redacted_resp_body)
                endpoint.last_response_headers = redacted_resp_headers

                # detect GraphQL
                if "graphql" in (path or "").lower() or isinstance(req.get("body"), dict) and "query" in req.get("body", {}):
                    endpoint.api_type = "GRAPHQL"

                actor_id = _resolve_actor(event)

                # store sample data (redacted)
                db.add(SampleData(
                    id=str(uuid.uuid4()),
                    account_id=account_id,
                    endpoint_id=endpoint.id,
                    request={"headers": redacted_headers, "body": redacted_body},
                    response={"headers": redacted_resp_headers, "body": redacted_resp_body},
                ))

                # request log
                db.add(RequestLog(
                    id=str(uuid.uuid4()),
                    account_id=account_id,
                    endpoint_id=endpoint.id,
                    source_ip=actor_id,
                    method=method,
                    path=safe_path,
                    response_code=resp.get("status_code", 200),
                    response_time_ms=resp.get("latency_ms"),
                    created_at=_observed_at_datetime(event.get("observed_at")),
                ))
                await db.flush()
                # publish enriched stream event
                enriched_event = {
                    "account_id": account_id,
                    "endpoint_id": endpoint.id,
                    "actor_id": actor_id or "anonymous",
                    "response_code": resp.get("status_code", 200),
                    "timestamp_ms": event.get("observed_at") or int(time.time() * 1000),
                    "path": redact_ingestion_path(endpoint.path or path),
                    "method": method,
                    "latency_ms": resp.get("latency_ms"),
                    "quality_score": quality_score,
                    "protocol": event.get("protocol", "HTTP/1.1"),
                    "detection_processed": pipeline_mode in {"shadow", "active"},
                }
                try:
                    topic = tenant_topic(account_id, "enriched")
                    track_topic(topic)
                    await bus.publish(topic, enriched_event)
                except Exception:
                    pass
                if actor_id and actor_id != "anonymous":
                    prev_result = await db.execute(
                        select(RequestLog)
                        .where(
                            RequestLog.account_id == account_id,
                            RequestLog.source_ip == actor_id,
                        )
                        .order_by(RequestLog.created_at.desc())
                        .limit(2)
                    )
                    prev_logs = prev_result.scalars().all()
                    if len(prev_logs) >= 2:
                        await detect_transition_violation(
                            db,
                            account_id,
                            actor_id,
                            prev_logs[1].path,
                            prev_logs[0].path,
                            elapsed_ms=_elapsed_ms(prev_logs[0].created_at, prev_logs[1].created_at),
                        )

                # PII scan (store findings, do not store raw)
                for finding in _pii.scan_payload(req.get("body") or {}):
                    db.add(SensitiveDataFinding(
                        account_id=account_id,
                        endpoint_id=endpoint.id,
                        entity_type=finding.get("entity_type"),
                        sample_value=Redactor.REDACT_VALUE,
                        source="request",
                        confidence=0.6,
                    ))
                for finding in _pii.scan_payload(resp.get("body") or {}):
                    db.add(SensitiveDataFinding(
                        account_id=account_id,
                        endpoint_id=endpoint.id,
                        entity_type=finding.get("entity_type"),
                        sample_value=Redactor.REDACT_VALUE,
                        source="response",
                        confidence=0.6,
                    ))
                    await persist_sensitive_data_exposure(
                        db,
                        account_id=account_id,
                        endpoint_id=endpoint.id,
                        entity_type=finding.get("entity_type"),
                        source="response",
                        path=path,
                        method=method,
                    )

                await persist_llm_api_findings(
                    db,
                    account_id=account_id,
                    endpoint_id=endpoint.id,
                    path=path,
                    method=method,
                    request_body=req.get("body"),
                    response_body=resp.get("body"),
                )

                # MCP parsing (JSON-RPC 2.0)
                invocation = parse_mcp_invocation(
                    request_body=req.get("body"),
                    response_body=resp.get("body"),
                    headers=req.get("headers") or {},
                    path=path,
                )
                if invocation:
                    await record_tool_invocation(
                        db=db,
                        account_id=account_id,
                        agent_id=invocation["agent_id"],
                        tool_name=invocation["tool_name"],
                        parameters=invocation["parameters"],
                        result_text=invocation["result_text"],
                        declared_scope=invocation["declared_scope"],
                        effective_scope=invocation["effective_scope"],
                        parent_agent_id=invocation["parent_agent_id"],
                        human_principal=invocation["human_principal"],
                    )

                # schema revision + governance + conformance
                schema_json = _infer_schema_from_body(resp.get("body"))
                await _record_revision(db, account_id, endpoint.id, schema_json)
                await _apply_governance_rules(db, account_id, endpoint)
                await _apply_openapi_conformance(db, account_id, endpoint)
                await _update_risk_score(db, endpoint, account_id)
                if pipeline_mode in {"shadow", "active"}:
                    result = await unified_detection_pipeline.process(
                        db,
                        account_id=account_id,
                        source_type="api_traffic",
                        raw_event=event,
                        persist_request_log=False,
                        existing_endpoint_id=endpoint.id,
                        existing_actor_id=actor_id,
                        context_source="EVENT_BATCH",
                        shadow=(pipeline_mode == "shadow"),
                    )
                    if pipeline_mode == "active":
                        threats += len(result["signals"])
                else:
                    await detect_api_behavior(
                        db,
                        account_id,
                        actor_id,
                        endpoint.id,
                        endpoint.path or path,
                        event.get("observed_at") or int(time.time() * 1000),
                        resp.get("latency_ms"),
                    )

            elif etype == "gateway_log":
                lines = event.get("lines") or []
                for line in lines:
                    parsed = parse_log_line(line)
                    if not parsed:
                        continue
                    safe_path = redact_ingestion_path(parsed["path"])
                    processed += 1
                    if pipeline_mode == "active":
                        result = await unified_detection_pipeline.process(
                            db,
                            account_id=account_id,
                            source_type="gateway_log",
                            raw_event=parsed,
                            persist_request_log=True,
                            context_source="GATEWAY_LOG",
                        )
                        threats += len(result["signals"])
                    else:
                        if pipeline_mode == "shadow":
                            await unified_detection_pipeline.process(
                                db,
                                account_id=account_id,
                                source_type="gateway_log",
                                raw_event=parsed,
                                persist_request_log=False,
                                context_source="GATEWAY_LOG",
                                shadow=True,
                            )
                        attacks = detect_attacks(parsed["path"], parsed["ua"])
                        db.add(RequestLog(
                            id=str(uuid.uuid4()),
                            account_id=account_id,
                            source_ip=parsed["ip"],
                            method=parsed["method"],
                            path=safe_path,
                            response_code=parsed["status"],
                            created_at=parsed["time"],
                        ))
                        for attack in attacks:
                            threats += 1
                            db.add(MaliciousEventRecord(
                                id=str(uuid.uuid4()),
                                account_id=account_id,
                                actor=parsed["ip"],
                                ip=parsed["ip"],
                                url=safe_path,
                                method=parsed["method"],
                                category=attack["category"],
                                severity=attack["severity"],
                                detected_at=int(parsed["time"].timestamp() * 1000),
                                status="OPEN",
                            ))
                            await persist_passive_attack_signal(
                                db,
                                account_id=account_id,
                                category=attack["category"],
                                severity=attack["severity"],
                                response_code=parsed["status"],
                                url=safe_path,
                                method=parsed["method"],
                                source="gateway_log",
                                actor=parsed["ip"],
                                evidence={"user_agent": Redactor.redact_text(parsed.get("ua") or "")},
                            )

            elif etype == "test_result":
                processed += 1
                tr = TestResult(
                    id=str(uuid.uuid4()),
                    run_id=event.get("run_id"),
                    endpoint_id=event.get("endpoint_id"),
                    template_id=event.get("template_id"),
                    is_vulnerable=event.get("is_vulnerable", False),
                    severity=event.get("severity", "MEDIUM"),
                    sent_request=event.get("request"),
                    received_response=event.get("response"),
                    evidence=json.dumps(event.get("evidence", {})),
                )
                db.add(tr)
                if event.get("is_vulnerable"):
                    await create_or_merge_vulnerability(
                        db,
                        {
                            "account_id": account_id,
                            "template_id": event.get("template_id"),
                            "endpoint_id": event.get("endpoint_id"),
                            "severity": event.get("severity", "MEDIUM"),
                            "type": event.get("template_id"),
                            "status": "OPEN",
                            "evidence": event.get("evidence", {}),
                        },
                    )

        await db.commit()

    await bump_cache_version(account_id)
    await _update_job(
        job_id,
        status="COMPLETED",
        processed_count=processed,
        threats_detected=threats,
        error_count=errors,
        completed_at=func_now(),
    )
