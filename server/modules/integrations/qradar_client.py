"""IBM QRadar integration via HTTP webhook or syslog relay."""
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def _to_leef(event: Dict[str, Any]) -> str:
    """Minimal LEEF formatter."""
    vendor = "APISentinel"
    product = "API-Security"
    version = "1.0"
    event_id = event.get("id", "alert")
    header = f"LEEF:1.0|{vendor}|{product}|{version}|{event_id}|"
    kv = []
    for k, v in event.items():
        if v is None:
            continue
        kv.append(f"{k}={str(v).replace('=', ':')}")
    return header + "\t".join(kv)


class QRadarClient:
    def __init__(self, endpoint_url: str, format: str = "LEEF"):
        self.endpoint_url = endpoint_url
        self.format = format.upper()

    async def send_event(self, event: Dict[str, Any]) -> bool:
        if not self.endpoint_url:
            return False
        payload = event if self.format == "JSON" else _to_leef(event)
        headers = {"Content-Type": "application/json"} if self.format == "JSON" else {"Content-Type": "text/plain"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.endpoint_url, content=payload if isinstance(payload, str) else None,
                                         json=payload if isinstance(payload, dict) else None,
                                         headers=headers)
                return 200 <= resp.status_code < 300
        except Exception as exc:
            logger.error("QRadar send_event failed: %s", exc)
            return False
