import httpx
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class JiraClient:
    """
    Integrates with the Atlassian Jira REST API.
    Used for automated ticket creation when vulnerabilities are found.
    """
    def __init__(self, base_url: str, email: str, api_token: str):
        self.base_url = base_url.rstrip("/")
        self.auth = (email, api_token) # Basic Auth with API Token

    async def create_issue(self, project_key: str, summary: str, description: str, issue_type: str = "Bug") -> Optional[str]:
        """
        Creates a new issue in the specified Jira project.
        Returns the issue key (e.g. 'SEC-123') if successful.
        """
        url = f"{self.base_url}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{"type": "paragraph", "content": [{"text": description, "type": "text"}]}]
                },
                "issuetype": {"name": issue_type},
                "labels": ["api-security", "autofound"]
            }
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload, auth=self.auth)
                resp.raise_for_status()
                return resp.json().get('key')
        except Exception as e:
            logger.error(f"Jira issue creation failed: {e}")
            return None
