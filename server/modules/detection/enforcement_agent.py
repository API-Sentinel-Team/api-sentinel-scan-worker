from __future__ import annotations

import uuid

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import BlockedIP, ResponseActionLog
from server.modules.cache.redis_cache import delete
from server.modules.enforcement.engine import circuit_breaker, rate_limit_override, token_invalidate

from .models import DetectionEnvelope, EnforcementAction, IncidentDecision


class EnforcementAgent:
    async def apply(
        self,
        db: AsyncSession,
        envelope: DetectionEnvelope,
        decision: IncidentDecision,
        *,
        persist: bool = True,
    ) -> list[EnforcementAction]:
        actions: list[EnforcementAction] = []
        if not persist or not decision.signals:
            decision.actions = actions
            return actions

        categories = {signal.category for signal in decision.signals}

        if decision.risk_score >= settings.DETECTION_IP_BLOCK_THRESHOLD and envelope.source_ip:
            actions.append(await self._block_ip(db, envelope, decision))

        if envelope.endpoint_id and decision.risk_score >= settings.DETECTION_RATE_LIMIT_THRESHOLD and ({"Rate Burst", "Resource Abuse", "Pagination Crawl"} & categories):
            actions.append(await self._rate_limit(db, envelope, decision))

        if envelope.endpoint_id and decision.risk_score >= settings.DETECTION_ENDPOINT_BLOCK_THRESHOLD and ({"SSRF", "Command Injection", "Path Traversal"} & categories):
            actions.append(await self._endpoint_block(db, envelope, decision))

        if envelope.token_jti and {"Expired JWT", "Session Fixation", "Credential Stuffing"} & categories:
            actions.append(await self._revoke_token(db, envelope, decision))

        decision.actions = actions
        decision.auto_blocked = any(action.action_type == "block_ip" and action.status == "SUCCESS" for action in actions)
        return actions

    async def _block_ip(self, db: AsyncSession, envelope: DetectionEnvelope, decision: IncidentDecision) -> EnforcementAction:
        result = await db.execute(
            select(BlockedIP).where(
                and_(
                    BlockedIP.account_id == envelope.account_id,
                    BlockedIP.ip == envelope.source_ip,
                )
            )
        )
        blocked = result.scalar_one_or_none()
        if blocked is None:
            blocked = BlockedIP(
                id=str(uuid.uuid4()),
                account_id=envelope.account_id,
                ip=envelope.source_ip,
                reason=f"Unified pipeline auto-block ({decision.category})",
                blocked_by="AUTO",
                risk_score=decision.risk_score,
                event_count=len(decision.signals),
            )
            db.add(blocked)
        else:
            blocked.risk_score = decision.risk_score
            blocked.event_count = max(blocked.event_count or 0, len(decision.signals))
            blocked.blocked_by = "AUTO"
        await delete(f"blocked:{envelope.account_id}:{envelope.source_ip}")
        action = EnforcementAction(action_type="block_ip", status="SUCCESS", params={"ip": envelope.source_ip}, result={"risk_score": decision.risk_score})
        db.add(
            ResponseActionLog(
                id=str(uuid.uuid4()),
                account_id=envelope.account_id,
                alert_id=decision.alert_id,
                action_type="block_ip",
                status="SUCCESS",
                details={"ip": envelope.source_ip, "risk_score": decision.risk_score},
            )
        )
        return action

    async def _rate_limit(self, db: AsyncSession, envelope: DetectionEnvelope, decision: IncidentDecision) -> EnforcementAction:
        result = await rate_limit_override(
            db,
            envelope.account_id,
            endpoint_id=envelope.endpoint_id,
            limit_rpm=max(30, settings.DETECTION_BURST_THRESHOLD // 2),
            duration_minutes=60,
            reason=f"Unified detection: {decision.category}",
        )
        db.add(
            ResponseActionLog(
                id=str(uuid.uuid4()),
                account_id=envelope.account_id,
                alert_id=decision.alert_id,
                action_type="rate_limit_override",
                status=result.get("status", "SUCCESS"),
                details=result,
            )
        )
        return EnforcementAction(action_type="rate_limit_override", status=result.get("status", "SUCCESS"), params={"endpoint_id": envelope.endpoint_id}, result=result)

    async def _endpoint_block(self, db: AsyncSession, envelope: DetectionEnvelope, decision: IncidentDecision) -> EnforcementAction:
        result = await circuit_breaker(
            db,
            envelope.account_id,
            endpoint_id=envelope.endpoint_id,
            duration_minutes=30,
            reason=f"Unified detection: {decision.category}",
            blocked_by="AUTO",
        )
        db.add(
            ResponseActionLog(
                id=str(uuid.uuid4()),
                account_id=envelope.account_id,
                alert_id=decision.alert_id,
                action_type="endpoint_block",
                status=result.get("status", "SUCCESS"),
                details=result,
            )
        )
        return EnforcementAction(action_type="endpoint_block", status=result.get("status", "SUCCESS"), params={"endpoint_id": envelope.endpoint_id}, result=result)

    async def _revoke_token(self, db: AsyncSession, envelope: DetectionEnvelope, decision: IncidentDecision) -> EnforcementAction:
        result = await token_invalidate(
            db,
            envelope.account_id,
            token_jti=envelope.token_jti,
            user_id=envelope.user_id,
        )
        db.add(
            ResponseActionLog(
                id=str(uuid.uuid4()),
                account_id=envelope.account_id,
                alert_id=decision.alert_id,
                action_type="token_invalidate",
                status=result.get("status", "SUCCESS"),
                details=result,
            )
        )
        return EnforcementAction(action_type="token_invalidate", status=result.get("status", "SUCCESS"), params={"token_jti": envelope.token_jti}, result=result)


enforcement_agent = EnforcementAgent()
