"""Agentic MCP security checks: prompt injection + trust chain validation."""
from __future__ import annotations

import re
import uuid
from hashlib import sha256
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import (
    AgentIdentity,
    MCPToolInvocation,
    AgenticViolation,
    Alert,
    EvidenceRecord,
)
from server.config import settings
from server.modules.enforcement.inline_mcp import apply_inline_decision
from server.modules.llm.findings import persist_agentic_violation_finding, summarize_agentic_violation_details
from server.modules.utils.redactor import Redactor

INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+previous\s+instructions", re.I), "PROMPT_INJECTION", "CRITICAL"),
    (re.compile(r"system:\s*|developer:\s*", re.I), "PROMPT_INJECTION", "HIGH"),
    (re.compile(r"bypass\s+safety|jailbreak|DAN\s+mode", re.I), "PROMPT_INJECTION", "CRITICAL"),
    (re.compile(r"you\s+are\s+now\s+|act\s+as\s+if", re.I), "PROMPT_INJECTION", "HIGH"),
]


def scan_prompt_injection(text: str) -> Tuple[bool, str, str, str]:
    if not text:
        return False, "", "", ""
    for pattern, category, severity in INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return True, category, severity, match.group()[:200]
    return False, "", "", ""


def evaluate_trust_chain(declared_scope: list, effective_scope: list) -> list:
    declared = set(declared_scope or [])
    effective = set(effective_scope or [])
    return sorted(effective - declared)


def _safe_result_metadata(result_text: Optional[str]) -> str:
    text = result_text or ""
    if not text:
        return ""
    redacted = Redactor.redact_text(text)
    digest = sha256(redacted.encode("utf-8")).hexdigest()
    return f"sha256:{digest}; length:{len(text)}; content_persisted:false"


async def record_tool_invocation(
    db: AsyncSession,
    account_id: int,
    agent_id: str,
    tool_name: str,
    parameters: Optional[dict],
    result_text: Optional[str],
    declared_scope: Optional[list],
    effective_scope: Optional[list],
    parent_agent_id: Optional[str],
    human_principal: Optional[str],
):
    result = await db.execute(
        select(AgentIdentity).where(
            AgentIdentity.account_id == account_id,
            AgentIdentity.agent_id == agent_id,
        )
    )
    identity = result.scalar_one_or_none()
    if not identity:
        identity = AgentIdentity(
            id=str(uuid.uuid4()),
            account_id=account_id,
            agent_id=agent_id,
            parent_agent_id=parent_agent_id,
            declared_scope=declared_scope or [],
            effective_scope=effective_scope or [],
            human_principal=human_principal,
        )
        db.add(identity)
    else:
        identity.parent_agent_id = parent_agent_id or identity.parent_agent_id
        identity.declared_scope = declared_scope or identity.declared_scope
        identity.effective_scope = effective_scope or identity.effective_scope
        identity.human_principal = human_principal or identity.human_principal

    invocation = MCPToolInvocation(
        id=str(uuid.uuid4()),
        account_id=account_id,
        agent_id=agent_id,
        tool_name=tool_name,
        parameters=Redactor.redact_json(parameters or {}),
        result_excerpt=_safe_result_metadata(result_text),
        status="OK",
    )
    db.add(invocation)

    violations = []

    excess_scope = evaluate_trust_chain(declared_scope or [], effective_scope or [])
    if excess_scope:
        violations.append(("TRUST_CHAIN_VIOLATION", "CRITICAL", {"excess_scope": excess_scope}))

    injected, category, severity, match = scan_prompt_injection(result_text or "")
    if injected:
        violations.append((category, severity, {"match": match}))

    for v_type, v_sev, v_details in violations:
        safe_violation_details = summarize_agentic_violation_details(v_details)
        violation = AgenticViolation(
            id=str(uuid.uuid4()),
            account_id=account_id,
            agent_id=agent_id,
            violation_type=v_type,
            severity=v_sev,
            details=safe_violation_details,
        )
        db.add(violation)

        alert = Alert(
            account_id=account_id,
            title="Agentic security violation",
            message=f"{v_type} detected for agent {agent_id}",
            severity=v_sev,
            category="AGENTIC",
            source_ip=agent_id,
            endpoint=f"mcp:{tool_name}",
        )
        db.add(alert)
        await db.flush()
        db.add(EvidenceRecord(
            account_id=account_id,
            evidence_type="agentic",
            ref_id=alert.id,
            severity=v_sev,
            summary=f"{v_type}: content_persisted=false",
            details={
                "agent_id": agent_id,
                "tool_name": tool_name,
                "violation_type": v_type,
                "violation_details": safe_violation_details,
            },
        ))
        await persist_agentic_violation_finding(
            db,
            account_id=account_id,
            agent_id=agent_id,
            tool_name=tool_name,
            violation_type=v_type,
            severity=v_sev,
            details=v_details,
        )

    if settings.INLINE_MCP_ENFORCEMENT_ENABLED and violations:
        await apply_inline_decision(
            db=db,
            account_id=account_id,
            agent_id=agent_id,
            tool_name=tool_name,
            violations=violations,
        )
