from sqlalchemy.future import select
from sqlalchemy import update, func
from server.models.core import ThreatActor, MaliciousEvent
from server.modules.persistence.database import AsyncSessionLocal
import logging

logger = logging.getLogger(__name__)

class ActorTracker:
    """
    Identifies and profiles threat actors based on their activity logs.
    """
    async def track_activity(
        self,
        source_ip: str,
        event_type: str = None,
        severity: str = "LOW",
        account_id: int | None = None,
    ):
        """
        Updates an actor's profile and potentially flags them.
        """
        if account_id is None:
            raise ValueError("ActorTracker.track_activity requires account_id")
        async with AsyncSessionLocal() as session:
            # 1. Find or create actor
            stmt = select(ThreatActor).where(
                ThreatActor.source_ip == source_ip,
                ThreatActor.account_id == account_id,
            )
            result = await session.execute(stmt)
            actor = result.scalar_one_or_none()

            if not actor:
                actor = ThreatActor(account_id=account_id, source_ip=source_ip, event_count=1)
                session.add(actor)
            else:
                actor.event_count += 1
                
            # 2. Add Malicious Event if provided
            if event_type:
                new_event = MaliciousEvent(
                    account_id=account_id,
                    actor_id=actor.id,
                    event_type=event_type,
                    severity=severity
                )
                session.add(new_event)
                
                # Simple risk scoring logic: severity-based weight
                weights = {"LOW": 1, "MEDIUM": 5, "HIGH": 20, "CRITICAL": 100}
                actor.risk_score += weights.get(severity, 1)

            # 3. Handle Status Transitions
            if actor.risk_score > 500:
                actor.status = "BLOCKED"
            elif actor.risk_score > 100:
                actor.status = "FLAGGED"

            await session.commit()
            return actor
