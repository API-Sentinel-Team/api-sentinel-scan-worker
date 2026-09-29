import httpx
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class SlackClient:
    """
    Integrates with Slack Webhooks for real-time alerting.
    Delivers vulnerability alerts directly to security/dev channels.
    """
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def send_alert(self, summary: str, details: str, severity: str = "MEDIUM") -> bool:
        """
        Sends an alert formatted with Slack Blocks.
        """
        color_map = {"CRITICAL": "#ff0000", "HIGH": "#ff9900", "MEDIUM": "#ffcc00", "LOW": "#00ccff"}
        color = color_map.get(severity, "#cccccc")
        
        payload = {
            "text": f"New *{severity}* Vulnerability Found!",
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Summary:* {summary}\n*Severity:* {severity}"}
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Details:* {details}"}
                    }
                ]
            }]
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.webhook_url, json=payload)
                resp.raise_for_status()
                return True
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
            return False
