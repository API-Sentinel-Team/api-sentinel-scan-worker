"""GitHub OAuth2 SSO implementation."""
import httpx
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


class GitHubOAuth:
    """
    GitHub OAuth2 flow:
    1. get_authorization_url() → redirect user
    2. GitHub calls back with ?code=
    3. exchange_code_for_token(code) → access_token
    4. get_user_info(access_token) → user profile
    """

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def get_authorization_url(self, state: str = "") -> str:
        params = (f"client_id={self.client_id}&redirect_uri={self.redirect_uri}"
                  f"&scope=read:user,user:email&state={state}")
        return f"{GITHUB_AUTHORIZE_URL}?{params}"

    async def exchange_code_for_token(self, code: str) -> Optional[str]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    GITHUB_TOKEN_URL,
                    data={"client_id": self.client_id, "client_secret": self.client_secret,
                          "code": code, "redirect_uri": self.redirect_uri},
                    headers={"Accept": "application/json"},
                )
                return resp.json().get("access_token")
        except Exception as e:
            logger.error(f"GitHub token exchange failed: {e}")
            return None

    async def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                user_resp = await client.get(GITHUB_USER_URL, headers=headers)
                user_resp.raise_for_status()
                user = user_resp.json()
                if not user.get("email"):
                    email_resp = await client.get(GITHUB_EMAILS_URL, headers=headers)
                    emails = email_resp.json()
                    primary = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
                    user["email"] = primary
                return {
                    "provider": "github", "provider_id": str(user["id"]),
                    "email": user.get("email"), "name": user.get("name") or user.get("login"),
                    "avatar_url": user.get("avatar_url"), "login": user.get("login"),
                }
        except Exception as e:
            logger.error(f"GitHub get_user_info failed: {e}")
            return None
