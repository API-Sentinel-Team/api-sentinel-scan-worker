"""
Rate abuse and sequential pattern detector.
Uses SQLite time-series queries instead of Redis for simplicity.
"""
import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from server.models.core import RequestLog


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class RateDetector:
    """
    Detects anomalous request rates and sequential ID enumeration patterns.
    """

    def __init__(self, window_seconds: int = 60, threshold_multiplier: float = 3.0):
        self.window_seconds = window_seconds
        self.threshold_multiplier = threshold_multiplier

    async def check_rate(self, source_ip: str, endpoint_id: str, db: AsyncSession) -> dict:
        """
        Checks if source_ip is hitting endpoint_id at an unusual rate.
        Returns {anomalous, requests_in_window, baseline_avg, score}
        """
        now = _utc_now()
        window_start = now - datetime.timedelta(seconds=self.window_seconds)
        day_start = now - datetime.timedelta(hours=24)

        try:
            # Count requests in current window
            current_q = await db.execute(
                select(func.count(RequestLog.id))
                .where(
                    RequestLog.source_ip == source_ip,
                    RequestLog.endpoint_id == endpoint_id,
                    RequestLog.created_at >= window_start,
                )
            )
            current_count = current_q.scalar() or 0

            # Baseline: average requests per window over past 24h
            total_q = await db.execute(
                select(func.count(RequestLog.id))
                .where(
                    RequestLog.endpoint_id == endpoint_id,
                    RequestLog.created_at >= day_start,
                )
            )
            total_24h = total_q.scalar() or 0
            windows_in_24h = (24 * 3600) / self.window_seconds
            baseline = total_24h / windows_in_24h if windows_in_24h else 1

            threshold = max(baseline * self.threshold_multiplier, 10)
            anomalous = current_count > threshold
            score = min(current_count / threshold, 1.0) if threshold > 0 else 0.0

            return {
                "anomalous": anomalous,
                "requests_in_window": current_count,
                "baseline_avg": round(baseline, 2),
                "threshold": round(threshold, 2),
                "score": round(score, 3),
                "source_ip": source_ip,
            }
        except Exception:
            return {"anomalous": False, "requests_in_window": 0, "baseline_avg": 0, "score": 0.0, "source_ip": source_ip}

    async def detect_sequential_enumeration(self, endpoint_id: str, db: AsyncSession) -> dict:
        """
        Detects BOLA-style sequential ID enumeration:
        many different IDs for the same path pattern from the same IP.
        """
        try:
            now = _utc_now()
            window_start = now - datetime.timedelta(minutes=10)

            result = await db.execute(
                select(RequestLog.source_ip, func.count(RequestLog.id).label("req_count"))
                .where(
                    RequestLog.endpoint_id == endpoint_id,
                    RequestLog.created_at >= window_start,
                )
                .group_by(RequestLog.source_ip)
                .having(func.count(RequestLog.id) > 20)
            )
            suspicious = result.all()

            return {
                "sequential_enumeration_detected": len(suspicious) > 0,
                "suspicious_ips": [{"ip": row[0], "requests": row[1]} for row in suspicious],
            }
        except Exception:
            return {"sequential_enumeration_detected": False, "suspicious_ips": []}
