"""Agent Guard — AI/LLM agentic session monitoring and guardrail enforcement."""
import re
import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from server.modules.persistence.database import get_db
from server.models.core import AgenticSession, MaliciousEventRecord
from server.modules.auth.rbac import Permission, RBAC
from server.modules.utils.redactor import Redactor

router = APIRouter(tags=["Agent Guard"])

GUARDRAIL_PATTERNS = [
    (re.compile(r'ignore previous instructions|jailbreak|DAN mode|act as if you|bypass safety|pretend you are', re.I), "PROMPT_INJECTION", "CRITICAL"),
    (re.compile(r'\bdrop\s+table\b|\bdelete\s+from\b|\btruncate\s+table\b', re.I), "SQL_INJECTION", "HIGH"),
    (re.compile(r'rm\s+-rf|format\s+c:|del\s+/f\s+/s', re.I), "COMMAND_INJECTION", "CRITICAL"),
    (re.compile(r'exfiltrate|send.*credentials|leak.*api.?key|steal.*token', re.I), "DATA_EXFILTRATION", "HIGH"),
    (re.compile(r'execute.*malware|deploy.*ransomware|run.*botnet', re.I), "MALWARE_ATTEMPT", "CRITICAL"),
    (re.compile(r'<script>|javascript:|onerror=|onload=', re.I), "XSS_ATTEMPT", "HIGH"),
]


def _check_guardrails(text: str) -> List[dict]:
    violations = []
    for pattern, category, severity in GUARDRAIL_PATTERNS:
        m = pattern.search(text)
        if m:
            violations.append({"category": category, "severity": severity, "match": Redactor.redact_text(m.group()[:100])})
    return violations


def _safe_text(value: str | None) -> str:
    return Redactor.redact_text(value or "")


def _safe_conversation(value):
    return Redactor.redact_json(value or [])


@router.post("/sessions")
async def create_session(
    session_identifier: str = Body(...),
    session_summary: Optional[str] = Body(None),
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_INSPECT)),
    db: AsyncSession = Depends(get_db)
):
    account_id = payload["account_id"]
    existing = await db.execute(
        select(AgenticSession).where(
            AgenticSession.session_identifier == session_identifier,
            AgenticSession.account_id == account_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(409, "Session already exists")
    session = AgenticSession(
        id=str(uuid.uuid4()),
        account_id=account_id,
        session_identifier=session_identifier,
        session_summary=_safe_text(session_summary),
    )
    db.add(session)
    await db.commit()
    return {"session_id": session.id, "session_identifier": _safe_text(session_identifier)}


@router.post("/sessions/{session_id}/inspect")
async def inspect_message(
    session_id: str,
    message: str = Body(..., embed=True),
    role: str = Body("user", embed=True),
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_INSPECT)),
    db: AsyncSession = Depends(get_db)
):
    """
    Inspect an agent message for guardrail violations.
    Returns action: ALLOW | WARN | BLOCK
    """
    account_id = payload["account_id"]
    result = await db.execute(
        select(AgenticSession).where(
            AgenticSession.id == session_id,
            AgenticSession.account_id == account_id,
        )
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Session not found")

    violations = _check_guardrails(message)
    is_blocked = any(v["severity"] == "CRITICAL" for v in violations)

    conversation = list(session.conversation_info or [])
    conversation.append({
        "role": _safe_text(role),
        "content": _safe_text(message[:500]),
        "violations": Redactor.redact_json(violations),
        "blocked": is_blocked,
    })
    session.conversation_info = _safe_conversation(conversation)
    if violations:
        session.is_malicious = True
        session.blocked_reason = _safe_text(violations[0]["category"])

    if is_blocked:
        db.add(MaliciousEventRecord(
            id=str(uuid.uuid4()), account_id=session.account_id,
            actor=session_id, category="AGENT_GUARD",
            sub_category=violations[0]["category"],
            severity=violations[0]["severity"],
            label="guardrail", context_source="AGENTIC",
            session_id=session_id,
            payload=_safe_text(message[:1000]),
            event_metadata={"content_redacted": True, "content_persisted": True},
        ))

    await db.commit()
    return {
        "action": "BLOCK" if is_blocked else ("WARN" if violations else "ALLOW"),
        "violations": violations, "session_id": session_id,
    }


@router.get("/sessions")
async def list_sessions(
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_READ)),
    is_malicious: Optional[bool] = Query(None),
    limit: int = Query(50), db: AsyncSession = Depends(get_db)
):
    account_id = payload["account_id"]
    q = select(AgenticSession).where(AgenticSession.account_id == account_id)
    if is_malicious is not None:
        q = q.where(AgenticSession.is_malicious == is_malicious)
    result = await db.execute(q.order_by(AgenticSession.created_at.desc()).limit(limit))
    sessions = result.scalars().all()
    return {"total": len(sessions), "sessions": [
        {"id": s.id, "session_identifier": _safe_text(s.session_identifier), "is_malicious": s.is_malicious,
         "blocked_reason": _safe_text(s.blocked_reason), "turn_count": len(s.conversation_info or []),
         "created_at": s.created_at}
        for s in sessions
    ]}


@router.get("/sessions/{session_id}")
async def get_session(
    session_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(AgenticSession).where(
            AgenticSession.id == session_id,
            AgenticSession.account_id == account_id,
        )
    )
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Session not found")
    return {"id": s.id, "session_identifier": _safe_text(s.session_identifier), "is_malicious": s.is_malicious,
            "blocked_reason": _safe_text(s.blocked_reason), "conversation_info": _safe_conversation(s.conversation_info), "created_at": s.created_at}


@router.get("/stats")
async def guardrail_stats(
    payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    total    = (await db.execute(select(func.count()).select_from(AgenticSession).where(AgenticSession.account_id == account_id))).scalar()
    malicious= (await db.execute(select(func.count()).select_from(AgenticSession).where(AgenticSession.account_id == account_id, AgenticSession.is_malicious == True))).scalar()
    return {"total_sessions": total, "malicious_sessions": malicious, "clean_sessions": total - malicious}


@router.get("/guardrail-rules")
async def list_guardrail_rules(payload: dict = Depends(RBAC.require_permission(Permission.AGENT_GUARD_READ))):
    """Returns active guardrail pattern rules."""
    return {"rules": [
        {"category": cat, "severity": sev, "pattern": pat.pattern}
        for pat, cat, sev in GUARDRAIL_PATTERNS
    ]}
