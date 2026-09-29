"""Response playbook execution for automated enforcement and notifications."""
from __future__ import annotations

import uuid
from typing import Dict, Any, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import ResponsePlaybook, ResponseActionLog, BlockedIP, Integration
from server.modules.enforcement.engine import (
    push_waf_rule,
    rate_limit_override,
    token_invalidate,
    circuit_breaker,
)
from server.modules.integrations.dispatcher import dispatch_event
from server.modules.integrations.webhook_client import WebhookClient
from server.modules.integrations.jira_client import JiraClient
from server.modules.integrations.azure_boards_client import AzureBoardsClient
from server.modules.integrations.destination_guard import (
    IntegrationDestinationError,
    validate_integration_destination_config,
)
from server.modules.integrations.secrets import IntegrationSecretCodec
from server.modules.response.playbook_secrets import PlaybookActionSecretCodec
from server.modules.utils.redactor import Redactor

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity.upper(), 0) >= SEVERITY_ORDER.get(threshold.upper(), 0)


async def _block_ips(db: AsyncSession, account_id: int, ips: List[str], reason: str) -> Dict[str, Any]:
    if not ips:
        return {"status": "SKIPPED", "detail": "no_ips"}
    result = await db.execute(
        select(BlockedIP.ip).where(BlockedIP.account_id == account_id, BlockedIP.ip.in_(ips))
    )
    already = set(result.scalars().all())
    added = 0
    for ip in ips:
        if ip in already:
            continue
        db.add(BlockedIP(
            id=str(uuid.uuid4()),
            account_id=account_id,
            ip=ip,
            reason=reason,
            blocked_by="AUTO",
        ))
        added += 1
    return {"status": "SUCCESS", "detail": f"blocked={added}", "blocked": added}


async def _resolve_integration_config(
    db: AsyncSession, account_id: int, integration_id: str | None, integration_type: str
) -> Dict[str, Any] | None:
    if integration_id:
        integration = await db.scalar(
            select(Integration).where(
                Integration.account_id == account_id,
                Integration.id == integration_id,
                Integration.enabled == True,
            )
        )
        if integration and integration.type == integration_type:
            return IntegrationSecretCodec.runtime_config(integration)
        return None
    integration = await db.scalar(
        select(Integration).where(
            Integration.account_id == account_id,
            Integration.type == integration_type,
            Integration.enabled == True,
        )
    )
    if integration:
        return IntegrationSecretCodec.runtime_config(integration)
    return None


async def execute_playbooks(
    db: AsyncSession,
    alert: Any,
    evidence: Dict[str, Any] | None = None,
    trigger: str = "alert.created",
) -> List[ResponseActionLog]:
    """Execute all playbooks matching the alert and trigger.

    Returns action logs (already added to the session).
    """
    result = await db.execute(
        select(ResponsePlaybook).where(
            ResponsePlaybook.account_id == alert.account_id,
            ResponsePlaybook.enabled == True,
            ResponsePlaybook.trigger == trigger,
        )
    )
    logs: List[ResponseActionLog] = []
    for playbook in result.scalars().all():
        if not _severity_at_least(alert.severity, playbook.severity_threshold or "MEDIUM"):
            continue

        for action in PlaybookActionSecretCodec.decrypt_actions(playbook.actions or []):
            action_type = (action.get("type") or "").upper()
            status = "SUCCESS"
            details: Dict[str, Any] = {}
            try:
                if action_type == "NOTIFY":
                    await dispatch_event(
                        "alert.playbook",
                        {
                            "title": alert.title,
                            "description": alert.message,
                            "severity": alert.severity,
                            "category": alert.category,
                            "source_ip": alert.source_ip,
                            "endpoint": alert.endpoint,
                            "evidence": evidence or {},
                        },
                        alert.account_id,
                        db,
                    )
                elif action_type == "WEBHOOK":
                    url = action.get("url", "")
                    secret = action.get("secret", "")
                    validate_integration_destination_config("webhook", {"url": url})
                    ok = await WebhookClient(url, secret=secret).send(
                        {"alert": alert.id, "payload": evidence or {}},
                        event_type="alert.playbook",
                    )
                    details["delivered"] = ok
                    if not ok:
                        status = "FAILED"
                elif action_type == "BLOCK_IP_LIST":
                    ips = action.get("ips") or (evidence or {}).get("source_ips") or []
                    result_info = await _block_ips(db, alert.account_id, ips, action.get("reason", "Auto-block"))
                    status = result_info.get("status", "SUCCESS")
                    details.update(result_info)
                elif action_type == "WAF_RULE_PUSH":
                    rule_id = action.get("rule_id", "auto-block")
                    source_ips = action.get("ips") or (evidence or {}).get("source_ips") or []
                    details = await push_waf_rule(
                        db, alert.account_id, rule_id=rule_id,
                        source_ips=source_ips, path=alert.endpoint, severity=alert.severity
                    )
                    status = details.get("status", "SUCCESS")
                elif action_type == "RATE_LIMIT_OVERRIDE":
                    endpoint_id = action.get("endpoint_id") or alert.endpoint
                    limit = int(action.get("limit", 60))
                    duration = int(action.get("duration_minutes", 60))
                    details = await rate_limit_override(
                        db, alert.account_id, endpoint_id=endpoint_id,
                        limit_rpm=limit, duration_minutes=duration,
                        reason=action.get("reason", "playbook"),
                    )
                    status = details.get("status", "SUCCESS")
                elif action_type == "TOKEN_INVALIDATION":
                    token_jti = action.get("token_jti") or (evidence or {}).get("token_jti")
                    if not token_jti:
                        status = "SKIPPED"
                        details["reason"] = "missing_token_jti"
                    else:
                        details = await token_invalidate(
                            db, alert.account_id, token_jti=token_jti,
                            expires_minutes=int(action.get("expires_minutes", 1440)),
                        )
                        status = details.get("status", "SUCCESS")
                elif action_type == "CIRCUIT_BREAKER":
                    endpoint_id = action.get("endpoint_id") or alert.endpoint
                    details = await circuit_breaker(
                        db, alert.account_id, endpoint_id=endpoint_id,
                        duration_minutes=int(action.get("duration_minutes", 60)),
                        reason=action.get("reason", "playbook"),
                    )
                    status = details.get("status", "SUCCESS")
                elif action_type == "CREATE_TICKET":
                    system = (action.get("system") or "jira").lower()
                    title = action.get("title") or alert.title or "API Security Alert"
                    description = action.get("description") or alert.message or str(evidence or {})
                    integration_id = action.get("integration_id")
                    cfg = IntegrationSecretCodec.decrypt_config(action.get("config") or {})
                    if system == "jira":
                        if not cfg:
                            cfg = await _resolve_integration_config(
                                db, alert.account_id, integration_id, "jira"
                            ) or {}
                        if not cfg:
                            status = "SKIPPED"
                            details["reason"] = "missing_jira_config"
                        else:
                            validate_integration_destination_config("jira", cfg)
                            client = JiraClient(
                                cfg.get("base_url", ""),
                                cfg.get("email", ""),
                                cfg.get("api_token", ""),
                            )
                            project_key = action.get("project_key") or cfg.get("project_key", "SEC")
                            issue_type = action.get("issue_type") or "Task"
                            ticket = await client.create_issue(project_key, title, description, issue_type)
                            details["ticket"] = ticket
                            status = "SUCCESS" if ticket else "FAILED"
                    elif system == "azure_boards":
                        if not cfg:
                            cfg = await _resolve_integration_config(
                                db, alert.account_id, integration_id, "azure_boards"
                            ) or {}
                        if not cfg:
                            status = "SKIPPED"
                            details["reason"] = "missing_azure_boards_config"
                        else:
                            client = AzureBoardsClient(
                                cfg.get("organization", ""),
                                cfg.get("project", ""),
                                cfg.get("personal_access_token", ""),
                            )
                            work_item = await client.create_bug(
                                title,
                                description,
                                severity=alert.severity or "MEDIUM",
                            )
                            details["work_item"] = work_item
                            status = "SUCCESS" if work_item else "FAILED"
                    else:
                        status = "SKIPPED"
                        details["reason"] = "unknown_ticket_system"
                else:
                    status = "SKIPPED"
                    details["reason"] = "unknown_action"
            except IntegrationDestinationError as exc:
                status = "FAILED"
                details["reason"] = "integration_destination_blocked"
                details["error"] = str(exc)
            except Exception as exc:
                status = "FAILED"
                details["error"] = Redactor.redact_text(str(exc))

            log = ResponseActionLog(
                id=str(uuid.uuid4()),
                account_id=alert.account_id,
                playbook_id=playbook.id,
                alert_id=alert.id,
                action_type=action_type or "UNKNOWN",
                status=status,
                details=details,
            )
            db.add(log)
            logs.append(log)

    return logs
