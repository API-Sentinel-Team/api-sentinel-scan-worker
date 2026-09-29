"""
Third-party integrations — CRUD + test + fire events + Postman/Burp import.
Supports: Slack, Jira, Splunk, Datadog, Azure Boards, PagerDuty, Webhook, BigQuery.
"""
import json
import uuid
from typing import Optional, List, Any
from fastapi import APIRouter, Depends, HTTPException, Body, UploadFile, File, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete

from server.modules.persistence.database import get_db
from server.models.core import Integration
from server.modules.auth.rbac import Permission, RBAC
from server.modules.integrations.slack_client import SlackClient
from server.modules.integrations.jira_client import JiraClient
from server.modules.integrations.splunk_client import SplunkClient
from server.modules.integrations.datadog_client import DatadogClient
from server.modules.integrations.azure_boards_client import AzureBoardsClient
from server.modules.integrations.pagerduty_client import PagerDutyClient
from server.modules.integrations.webhook_client import WebhookClient
from server.modules.integrations.sentinel_client import SentinelClient
from server.modules.integrations.qradar_client import QRadarClient
from server.modules.integrations.elastic_client import ElasticClient
from server.modules.integrations.chronicle_client import ChronicleClient
from server.modules.integrations.dispatcher import dispatch_event
from server.modules.integrations.postman_importer import PostmanImporter
from server.modules.integrations.burp_importer import BurpImporter
from server.modules.integrations.destination_guard import (
    IntegrationDestinationError,
    validate_integration_destination_config,
)
from server.modules.integrations.secrets import IntegrationSecretCodec
from server.modules.utils.redactor import Redactor
from server.modules.validation.input_validator import InputValidator, ValidationError
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Integrations"])

SUPPORTED_TYPES = {
    "slack", "jira", "splunk", "datadog", "azure_boards", "pagerduty", "webhook", "bigquery",
    "sentinel", "qradar", "elastic", "chronicle",
}

SUPPORTED_EVENTS = {
    "vulnerability_found",
    "test_complete",
    "alert.created",
    "alert.playbook",
    "endpoint.shadow_detected",
    "endpoint.zombie_detected",
    "endpoint.zombie_revived",
}


def _validation_error(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def _validate_integration_id(integration_id: str) -> str:
    try:
        return InputValidator.validate_uuid(integration_id, "integration_id")
    except ValidationError as exc:
        raise _validation_error(exc) from exc


def _validate_integration_type(value: str) -> str:
    try:
        integration_type = InputValidator.validate_string(
            value,
            "type",
            max_length=50,
            allow_empty=False,
            pattern=r"^[a-z_]+$",
        )
    except ValidationError as exc:
        raise _validation_error(exc) from exc
    if integration_type not in SUPPORTED_TYPES:
        raise HTTPException(400, f"Unsupported type. Supported: {sorted(SUPPORTED_TYPES)}")
    return integration_type


def _validate_name(value: str) -> str:
    try:
        return InputValidator.validate_string(value, "name", max_length=100, allow_empty=False)
    except ValidationError as exc:
        raise _validation_error(exc) from exc


def _validate_config(integration_type: str, config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="config: Must be an object")
    if not InputValidator.validate_json_depth(config, max_depth=12):
        raise HTTPException(status_code=400, detail="config: Exceeds maximum JSON depth")
    try:
        serialized = json.dumps(config)
    except TypeError as exc:
        raise HTTPException(status_code=400, detail="config: Must be JSON serializable") from exc
    if len(serialized) > 65536:
        raise HTTPException(status_code=400, detail="config: Exceeds max size of 65536 bytes")
    try:
        validate_integration_destination_config(integration_type, config)
    except IntegrationDestinationError as exc:
        raise HTTPException(
            status_code=400,
            detail={"message": "Integration destination blocked", "reason": str(exc)},
        ) from exc
    return config


def _validate_events(events: List[str] | None) -> list[str]:
    if events is None:
        return []
    try:
        InputValidator.validate_collection_size(events, "events", max_size=50)
        validated = [
            InputValidator.validate_string(
                event,
                f"events[{index}]",
                max_length=100,
                allow_empty=False,
                pattern=r"^[A-Za-z0-9_.:-]+$",
            )
            for index, event in enumerate(events)
        ]
    except ValidationError as exc:
        raise _validation_error(exc) from exc
    unsupported = sorted({event for event in validated if event not in SUPPORTED_EVENTS})
    if unsupported:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported events: {unsupported}. Supported: {sorted(SUPPORTED_EVENTS)}",
        )
    return validated


def _redacted_config_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redacted_config_shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redacted_config_shape(item) for item in value]
    if value is None or value == "":
        return value
    return Redactor.REDACT_VALUE


def _serialize_integration(integration: Integration, *, include_config: bool = False) -> dict[str, Any]:
    raw_config = integration.config or {}
    data: dict[str, Any] = {
        "id": integration.id,
        "type": integration.type,
        "name": integration.name,
        "enabled": integration.enabled,
        "events": integration.events,
        "created_at": integration.created_at,
        "configured_fields": sorted(raw_config.keys()) if isinstance(raw_config, dict) else [],
        "config_redacted": bool(raw_config),
    }
    if include_config:
        data["config"] = _redacted_config_shape(raw_config)
    return data


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.get("/")
async def list_integrations(
    request: Request,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_READ))
):
    account_id = payload.get("account_id")
    result = await db.execute(select(Integration).where(Integration.account_id == account_id))
    items = result.scalars().all()
    return {"total": len(items), "integrations": [_serialize_integration(i) for i in items]}


@router.post("/")
async def create_integration(
    type: str = Body(...), name: str = Body(...),
    config: dict = Body(...),
    events: List[str] = Body(default=["vulnerability_found", "test_complete"]),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_WRITE))
):
    account_id = payload.get("account_id")
    """
    Config schemas per type:
    - slack:        {"webhook_url": "https://hooks.slack.com/..."}
    - jira:         {"base_url": "...", "email": "...", "api_token": "...", "project_key": "SEC"}
    - splunk:       {"hec_url": "...", "hec_token": "...", "index": "main"}
    - datadog:      {"api_key": "...", "app_key": "...", "site": "datadoghq.com"}
    - azure_boards: {"organization": "...", "project": "...", "personal_access_token": "..."}
    - pagerduty:    {"routing_key": "..."}
    - webhook:      {"url": "...", "secret": "...", "method": "POST"}
    - bigquery:     {"project_id": "...", "dataset_id": "...", "credentials_json": {...}}
    - sentinel:     {"endpoint_url": "...", "headers": {"x-api-key": "..."}}
    - qradar:       {"endpoint_url": "...", "format": "LEEF|JSON"}
    - elastic:      {"endpoint_url": "...", "api_key": "..."}
    - chronicle:    {"endpoint_url": "...", "api_key": "..."}
    """
    integration_type = _validate_integration_type(type)
    validated_name = _validate_name(name)
    validated_events = _validate_events(events)
    validated_config = _validate_config(integration_type, config)
    integration = Integration(
        id=str(uuid.uuid4()),
        account_id=account_id,
        type=integration_type,
        name=validated_name,
        config=IntegrationSecretCodec.encrypt_config(validated_config),
        events=validated_events,
        enabled=True,
    )
    db.add(integration)
    await db.commit()
    await db.refresh(integration)
    return {"id": integration.id, "type": integration_type, "name": validated_name, "status": "created"}


@router.get("/{integration_id}")
async def get_integration(
    integration_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_READ))
):
    account_id = payload.get("account_id")
    validated_integration_id = _validate_integration_id(integration_id)
    result = await db.execute(select(Integration).where(
        Integration.id == validated_integration_id,
        Integration.account_id == account_id
    ))
    i = result.scalar_one_or_none()
    if not i:
        raise HTTPException(404, "Integration not found")
    return _serialize_integration(i, include_config=True)


@router.patch("/{integration_id}")
async def update_integration(
    integration_id: str,
    enabled: Optional[bool] = Body(None),
    config: Optional[dict] = Body(None),
    events: Optional[List[str]] = Body(None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_WRITE))
):
    account_id = payload.get("account_id")
    validated_integration_id = _validate_integration_id(integration_id)
    updates = {}
    if enabled is not None: updates["enabled"] = enabled
    if config is not None:
        current = await db.scalar(
            select(Integration).where(
                Integration.id == validated_integration_id,
                Integration.account_id == account_id,
            )
        )
        if current is None:
            raise HTTPException(404, "Integration not found")
        updates["config"] = IntegrationSecretCodec.encrypt_config(
            _validate_config(current.type, config)
        )
    if events is not None:  updates["events"] = _validate_events(events)
    if not updates:
        raise HTTPException(400, "No updates provided")
    result = await db.execute(update(Integration).where(
        Integration.id == validated_integration_id,
        Integration.account_id == account_id
    ).values(**updates))
    if result.rowcount == 0:
        raise HTTPException(404, "Integration not found")
    await db.commit()
    return {"integration_id": validated_integration_id, "updated": list(updates.keys())}


@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_WRITE))
):
    account_id = payload.get("account_id")
    validated_integration_id = _validate_integration_id(integration_id)
    result = await db.execute(delete(Integration).where(
        Integration.id == validated_integration_id,
        Integration.account_id == account_id
    ))
    if result.rowcount == 0:
        raise HTTPException(404, "Integration not found")
    await db.commit()
    return {"deleted": validated_integration_id}


# ── Test / ping ────────────────────────────────────────────────────────────────

@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_WRITE))
):
    """Send a test event to verify the integration configuration works."""
    account_id = payload.get("account_id")
    validated_integration_id = _validate_integration_id(integration_id)
    result = await db.execute(select(Integration).where(
        Integration.id == validated_integration_id,
        Integration.account_id == account_id
    ))
    i = result.scalar_one_or_none()
    if not i:
        raise HTTPException(404, "Integration not found")

    cfg = IntegrationSecretCodec.runtime_config(i)
    try:
        validate_integration_destination_config(i.type, cfg)
    except IntegrationDestinationError as exc:
        raise HTTPException(
            status_code=400,
            detail={"message": "Integration destination blocked", "reason": str(exc)},
        ) from exc
    ok, detail = False, ""

    if i.type == "slack":
        client = SlackClient(cfg.get("webhook_url", ""))
        ok = await client.send_alert("Test Alert", "Integration test from API Security Engine", "LOW")
        detail = "Slack test message sent" if ok else "Failed — check webhook_url"

    elif i.type == "jira":
        client = JiraClient(cfg.get("base_url", ""), cfg.get("email", ""), cfg.get("api_token", ""))
        ticket = await client.create_issue(cfg.get("project_key", "SEC"),
                                           "API Security Engine - Test", "Connectivity test", "Task")
        ok = ticket is not None
        detail = f"Jira issue created: {ticket}" if ok else "Failed — check credentials"

    elif i.type == "splunk":
        client = SplunkClient(cfg.get("hec_url", ""), cfg.get("hec_token", ""), cfg.get("index", "main"))
        ok = await client.send_event({"message": "Integration test", "source": "api-security-engine"})
        detail = "Splunk HEC event sent" if ok else "Failed — check hec_url and hec_token"

    elif i.type == "datadog":
        client = DatadogClient(cfg.get("api_key", ""), cfg.get("app_key", ""), cfg.get("site", "datadoghq.com"))
        ok = await client.send_event("API Security Engine Test", "Integration connectivity test", alert_type="info")
        detail = "Datadog event sent" if ok else "Failed — check api_key"

    elif i.type == "azure_boards":
        client = AzureBoardsClient(cfg.get("organization", ""), cfg.get("project", ""),
                                   cfg.get("personal_access_token", ""))
        item_id = await client.create_bug("API Security Engine - Test", "Connectivity test", severity="LOW")
        ok = item_id is not None
        detail = f"Work item created: {item_id}" if ok else "Failed — check org/project/PAT"

    elif i.type == "pagerduty":
        client = PagerDutyClient(cfg.get("routing_key", ""))
        dedup = await client.trigger("API Security Engine - Test", severity="info",
                                     custom_details={"test": True})
        ok = dedup is not None
        detail = f"PagerDuty incident triggered: {dedup}" if ok else "Failed — check routing_key"

    elif i.type == "webhook":
        client = WebhookClient(cfg.get("url", ""), secret=cfg.get("secret", ""),
                               method=cfg.get("method", "POST"))
        ok = await client.send({"test": True, "source": "api-security-engine"}, event_type="test")
        detail = "Webhook delivered" if ok else "Failed — check url"

    elif i.type == "bigquery":
        from server.modules.integrations.bigquery_client import BigQueryClient
        client = BigQueryClient(cfg.get("project_id", ""), cfg.get("dataset_id", ""),
                                cfg.get("credentials_json"))
        ok = client.is_available()
        detail = "BigQuery client ready" if ok else "Unavailable — install google-cloud-bigquery or check credentials"
    elif i.type == "sentinel":
        ok = await SentinelClient(cfg.get("endpoint_url", ""), cfg.get("headers")).send_event({"test": True})
        detail = "Sentinel event delivered" if ok else "Failed — check endpoint_url"
    elif i.type == "qradar":
        ok = await QRadarClient(cfg.get("endpoint_url", ""), cfg.get("format", "LEEF")).send_event({"test": True})
        detail = "QRadar event delivered" if ok else "Failed — check endpoint_url"
    elif i.type == "elastic":
        ok = await ElasticClient(cfg.get("endpoint_url", ""), cfg.get("api_key", "")).send_event({"test": True})
        detail = "Elastic event delivered" if ok else "Failed — check endpoint_url/api_key"
    elif i.type == "chronicle":
        ok = await ChronicleClient(cfg.get("endpoint_url", ""), cfg.get("api_key", "")).send_event({"test": True})
        detail = "Chronicle event delivered" if ok else "Failed — check endpoint_url/api_key"

    return {"integration_id": validated_integration_id, "type": i.type, "success": ok, "detail": detail}


# ── Import endpoints ───────────────────────────────────────────────────────────

@router.post("/import/postman")
async def import_postman(
    collection_file: UploadFile = File(...),
    collection_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.ENDPOINTS_WRITE))
):
    """Upload Postman Collection v2.1 JSON to auto-discover API endpoints."""
    account_id = payload.get("account_id")
    try:
        content = await collection_file.read()
        data = json.loads(content)
    except Exception as e:
        raise HTTPException(400, f"Invalid JSON: {e}")

    endpoints_data = PostmanImporter.parse_collection(data, account_id=account_id, collection_id=collection_id)
    from server.models.core import APIEndpoint
    for ep_data in endpoints_data:
        db.add(APIEndpoint(id=str(uuid.uuid4()), **ep_data))
    await db.commit()
    return {"imported": len(endpoints_data), "source": "postman", "filename": collection_file.filename}


@router.post("/import/burp")
async def import_burp(
    burp_file: UploadFile = File(...),
    collection_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_MANAGE))
):
    """Upload Burp Suite XML export to auto-discover endpoints and sample data."""
    try:
        content = await burp_file.read()
        xml_content = content.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(400, f"Invalid file: {e}")

    account_id = payload.get("account_id")
    parsed = BurpImporter.parse_xml(xml_content, account_id=account_id, collection_id=collection_id)
    from server.models.core import APIEndpoint, SampleData
    for ep_data in parsed["endpoints"]:
        db.add(APIEndpoint(id=str(uuid.uuid4()), **ep_data))
    for sd in parsed["sample_data"]:
        db.add(
            SampleData(
                id=str(uuid.uuid4()),
                account_id=sd["account_id"],
                request=sd["request"],
                response=sd["response"],
            )
        )
    await db.commit()
    return {"endpoints_imported": len(parsed["endpoints"]),
            "samples_imported": len(parsed["sample_data"]), "source": "burp"}


# ── Utility: broadcast event to all subscribed integrations ───────────────────

async def fire_event(event_name: str, payload: dict, account_id: int, db: AsyncSession):
    """Call from other routers to notify enabled integrations subscribed to event_name."""
    await dispatch_event(event_name, payload, account_id, db)
