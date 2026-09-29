import httpx
import logging
from typing import Dict, Any, List, Optional
from server.modules.test_executor.context_manager import ContextManager
from server.modules.test_executor.request_mutator import RequestMutator
from server.modules.test_executor.target_guard import TargetGuard

logger = logging.getLogger(__name__)

class LoginFlowExecutor:
    """
    Executes a series of steps to authenticate a user and extract tokens.
    Used for automated BOLA/BFLA testing where valid sessions are required for multiple roles.
    """
    def __init__(self, target_guard: TargetGuard | None = None):
        self.mutator = RequestMutator()
        self.target_guard = target_guard or TargetGuard.from_settings()

    async def execute_login(
        self,
        flow_cfg: Dict[str, Any],
        credentials: Dict[str, str],
        *,
        base_url: str | None = None,
    ) -> Dict[str, str]:
        """
        Executes the login workflow.
        Returns a dictionary of extracted tokens/cookies.
        """
        context = ContextManager()
        # Seed context with credentials
        for k, v in credentials.items():
            context.store[k] = v
            
        auth_tokens = {}
        steps = flow_cfg.get('steps', [])

        flow_base_url = base_url
        async with httpx.AsyncClient(timeout=15.0, verify=True) as client:
            for step in steps:
                # 1. Prepare request
                request_data = context.substitute_recursive(step.get('request', {}))
                request_url = str(request_data.get('url') or "")
                if not request_url:
                    raise ValueError("login flow request URL is required")
                if flow_base_url is None:
                    flow_base_url = request_url
                self.target_guard.validate_url(request_url, base_url=flow_base_url)
                
                # 2. Execute
                resp = await client.request(
                    method=request_data.get('method', 'POST'),
                    url=request_url,
                    headers=request_data.get('headers'),
                    content=request_data.get('body')
                )
                
                # 3. Extract tokens if defined (uses resp.text / headers in ContextManager)
                extraction_rules = step.get('extract', [])
                context.extract_from_response({
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text
                }, extraction_rules)
                
                # Accumulate tokens from context
                for rule in extraction_rules:
                    key = rule.get('key')
                    if key in context.store:
                        auth_tokens[key] = context.store[key]

        return auth_tokens
