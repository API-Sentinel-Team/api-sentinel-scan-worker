import asyncio
from sqlalchemy.future import select
from sqlalchemy import func
from server.models.core import RequestLog, ThreatActor
from server.modules.persistence.database import AsyncSessionLocal
from .actor_tracker import ActorTracker
import logging

logger = logging.getLogger(__name__)

class StreamProcessor:
    """
    Analyzes historical request logs in chunks to detect high-level patterns.
    (Near-real-time processing)
    """
    def __init__(self, interval_sec: int = 10):
        self.interval = interval_sec
        self.tracker = ActorTracker()
        self.running = False

    async def start(self):
        self.running = True
        while self.running:
            try:
                await self._process_batch()
            except Exception as e:
                logger.error(f"Stream processor error: {e}")
            await asyncio.sleep(self.interval)

    async def _process_batch(self):
        """
        Detects anomalies by analyzing the last N requests.
        """
        async with AsyncSessionLocal() as session:
            # Simple Pattern: IP with many 4xx/403 errors in a short period
            # Logic: Group by IP, count status_code >= 400
            stmt = select(
                RequestLog.account_id,
                RequestLog.source_ip, 
                func.count(RequestLog.id).label('err_count')
            ).where(
                RequestLog.response_code >= 400
            ).group_by(
                RequestLog.account_id,
                RequestLog.source_ip
            ).having(
                func.count(RequestLog.id) > 20 # Threshold for probing
            )

            result = await session.execute(stmt)
            for row in result:
                account_id = row[0]
                ip = row[1]
                count = row[2]
                logger.info(f"Potential probe detected from {ip}: {count} errors")
                await self.tracker.track_activity(
                    source_ip=ip, 
                    event_type="PROBING_DETECTED",
                    severity="MEDIUM",
                    account_id=account_id,
                )

    def stop(self):
        self.running = False
