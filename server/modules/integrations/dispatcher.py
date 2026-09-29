"""Unified integration dispatch for alerts/events."""
import logging
from typing import Dict, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import Integration
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
from server.modules.integrations.destination_guard import (
    IntegrationDestinationError,
    validate_integration_destination_config,
)
from server.modules.integrations.secrets import IntegrationSecretCodec

logger = logging.getLogger(__name__)


async def dispatch_event(event_name: str, payload: Dict[str, Any], account_id: int, db: AsyncSession) -> None:
    """Notify enabled integrations subscribed to the event_name."""
    result = await db.execute(
        select(Integration).where(Integration.account_id == account_id, Integration.enabled == True)
    )
    for i in result.scalars().all():
        if event_name not in (i.events or []):
            continue
        cfg = IntegrationSecretCodec.runtime_config(i)
        try:
            validate_integration_destination_config(i.type, cfg)
            if i.type == "slack":
                await SlackClient(cfg.get("webhook_url", "")).send_alert(
                    payload.get("type", event_name), str(payload.get("description", ""))[:500],
                    payload.get("severity", "MEDIUM"))
            elif i.type == "jira":
                await JiraClient(cfg.get("base_url", ""), cfg.get("email", ""), cfg.get("api_token", "")).create_issue(
                    cfg.get("project_key", "SEC"),
                    payload.get("title", "API Security Alert"),
                    payload.get("description", str(payload)[:2000]),
                    "Task"
                )
            elif i.type == "splunk":
                await SplunkClient(cfg.get("hec_url", ""), cfg.get("hec_token", "")).send_event(
                    {**payload, "event_name": event_name})
            elif i.type == "datadog":
                await DatadogClient(cfg.get("api_key", ""), cfg.get("app_key", "")).send_vulnerability_event(payload)
            elif i.type == "pagerduty":
                await PagerDutyClient(cfg.get("routing_key", "")).trigger_vulnerability(payload)
            elif i.type == "webhook":
                await WebhookClient(cfg.get("url", ""), cfg.get("secret", "")).send(payload, event_type=event_name)
            elif i.type == "azure_boards":
                await AzureBoardsClient(cfg.get("organization", ""), cfg.get("project", ""),
                                       cfg.get("personal_access_token", "")).create_bug(
                    payload.get("title", "API Security Alert"), payload.get("description", str(payload)[:2000]),
                    severity=payload.get("severity", "MEDIUM")
                )
            elif i.type == "sentinel":
                await SentinelClient(cfg.get("endpoint_url", ""), cfg.get("headers")).send_event(payload)
            elif i.type == "qradar":
                await QRadarClient(cfg.get("endpoint_url", ""), cfg.get("format", "LEEF")).send_event(payload)
            elif i.type == "elastic":
                await ElasticClient(cfg.get("endpoint_url", ""), cfg.get("api_key", "")).send_event(payload)
            elif i.type == "chronicle":
                await ChronicleClient(cfg.get("endpoint_url", ""), cfg.get("api_key", "")).send_event(payload)
        except IntegrationDestinationError as exc:
            logger.warning("Integration %s (%s) destination blocked: %s", i.id, i.type, exc)
        except Exception as exc:
            logger.error("Integration %s (%s) dispatch_event error: %s", i.id, i.type, exc)
