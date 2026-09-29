"""Seed default response playbooks for recon/lifecycle events."""
from __future__ import annotations

from typing import List, Dict, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import ResponsePlaybook


DEFAULT_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "name": "Shadow Endpoint Notify",
        "trigger": "endpoint.shadow_detected",
        "severity_threshold": "HIGH",
        "actions": [{"type": "NOTIFY"}],
    },
    {
        "name": "Shadow Endpoint Ticket",
        "trigger": "endpoint.shadow_detected",
        "severity_threshold": "HIGH",
        "enabled": False,
        "actions": [{"type": "CREATE_TICKET", "system": "jira"}],
    },
    {
        "name": "Zombie Endpoint Notify",
        "trigger": "endpoint.zombie_detected",
        "severity_threshold": "MEDIUM",
        "actions": [{"type": "NOTIFY"}],
    },
    {
        "name": "Zombie Endpoint Ticket",
        "trigger": "endpoint.zombie_detected",
        "severity_threshold": "MEDIUM",
        "enabled": False,
        "actions": [{"type": "CREATE_TICKET", "system": "jira"}],
    },
    {
        "name": "Zombie Revived Notify",
        "trigger": "endpoint.zombie_revived",
        "severity_threshold": "LOW",
        "actions": [{"type": "NOTIFY"}],
    },
    {
        "name": "Rate Burst Throttle",
        "trigger": "alert.rate_burst",
        "severity_threshold": "HIGH",
        "actions": [
            {"type": "RATE_LIMIT_OVERRIDE", "limit_rpm": 20, "duration_minutes": 30},
            {"type": "NOTIFY"},
        ],
    },
    {
        "name": "Injection WAF Block",
        "trigger": "alert.injection_detected",
        "severity_threshold": "HIGH",
        "actions": [
            {"type": "WAF_RULE_PUSH", "rule_name": "injection-auto", "priority": "high"},
            {"type": "NOTIFY"},
        ],
    },
    {
        "name": "High-Risk Actor Block",
        "trigger": "threat.actor.high_risk",
        "severity_threshold": "HIGH",
        "actions": [
            {"type": "BLOCK_IP_LIST", "duration_hours": 24},
            {"type": "NOTIFY"},
        ],
    },
    {
        "name": "Credential Stuffing Response",
        "trigger": "alert.credential_stuffing",
        "severity_threshold": "CRITICAL",
        "actions": [
            {"type": "RATE_LIMIT_OVERRIDE", "limit_rpm": 5, "duration_minutes": 60},
            {"type": "NOTIFY"},
            {"type": "CREATE_TICKET", "system": "jira"},
        ],
    },
]


async def ensure_default_playbooks(db: AsyncSession, account_id: int) -> int:
    """Ensure default playbooks exist; returns count created."""
    created = 0
    for pb in DEFAULT_PLAYBOOKS:
        exists = await db.scalar(
            select(ResponsePlaybook).where(
                ResponsePlaybook.account_id == account_id,
                ResponsePlaybook.name == pb["name"],
                ResponsePlaybook.trigger == pb["trigger"],
            )
        )
        if exists:
            continue
        db.add(
            ResponsePlaybook(
                account_id=account_id,
                name=pb["name"],
                trigger=pb["trigger"],
                severity_threshold=pb["severity_threshold"],
                enabled=pb.get("enabled", True),
                actions=pb["actions"],
            )
        )
        created += 1
    return created
