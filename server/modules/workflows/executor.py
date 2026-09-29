"""API workflow executor - chains multi-step API calls with variable extraction."""
import httpx
import logging
from typing import Dict, Any, List, Optional

from server.modules.pentest.auth_scope import (
    AuthScopeError,
    auth_scope_policy_for_error,
    validate_auth_profile_scope,
)
from server.modules.pentest.target_policy import build_target_guard_policy
from server.modules.test_executor.state_change_guard import (
    StateChangeBlocked,
    StateChangeGuard,
    state_change_policy_for_request,
)
from server.modules.test_executor.target_guard import TargetGuard, TargetGuardError
from server.modules.utils.redactor import Redactor

logger = logging.getLogger(__name__)


_SENSITIVE_STEP_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
}


class PlaintextWorkflowAuthHeaderBlocked(ValueError):
    pass


class WorkflowExecutor:
    """
    Executes ordered API steps. Each step can:
    - Send HTTP request (method, url, headers, body)
    - Extract vars from response via dotted path: {"token": "data.access_token"}
    - Pass vars to next steps via {{var}} templating
    - Assert status code or body content
    """

    def __init__(
        self,
        *,
        target_guard: TargetGuard | None = None,
        allow_state_change: bool = False,
        allow_destructive_methods: bool = False,
        follow_redirects: bool = False,
    ) -> None:
        self.target_guard = target_guard or TargetGuard.from_settings()
        self.allow_state_change = bool(allow_state_change)
        self.allow_destructive_methods = bool(allow_destructive_methods)
        self.follow_redirects = bool(follow_redirects)

    async def run(
        self,
        steps: List[Dict[str, Any]],
        auth_headers: Optional[Dict[str, str]] = None,
        *,
        auth_profile: object | None = None,
    ) -> Dict[str, Any]:
        variables: Dict[str, str] = {}
        step_results = []
        auth_headers = auth_headers or {}
        workflow_base_url = None

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=self.follow_redirects, verify=True) as client:
            for idx, step in enumerate(steps):
                result = await self._execute_step(
                    client,
                    step,
                    variables,
                    auth_headers,
                    base_url=workflow_base_url,
                    auth_profile=auth_profile,
                )
                workflow_base_url = workflow_base_url or result.pop("_workflow_base_url", None)
                raw_response_body = result.pop("_raw_response_body", result.get("response_body", {}))
                step_results.append(result)
                if not result["success"] and step.get("stop_on_failure", True):
                    safe_error = Redactor.redact_text(str(result.get("error") or "workflow step failed"))
                    return {
                        "status": "FAILED",
                        "step_results": step_results,
                        "variables": Redactor.redact_json(variables),
                        "error": f"Step {idx+1} failed: {safe_error}",
                    }
                for var_name, path in step.get("extract", {}).items():
                    val = self._extract(raw_response_body, path)
                    if val is not None:
                        variables[var_name] = str(val)

        return {
            "status": "COMPLETED",
            "step_results": step_results,
            "variables": Redactor.redact_json(variables),
        }

    async def _execute_step(
        self,
        client,
        step,
        variables,
        auth_headers,
        *,
        base_url: str | None = None,
        auth_profile: object | None = None,
    ):
        method = step.get("method", "GET").upper()
        url = self._render(step.get("url", ""), variables)
        step_headers = {
            k: self._render(str(v), variables)
            for k, v in (step.get("headers", {}) or {}).items()
        }
        body = step.get("body")
        active_base_url = base_url or url
        if isinstance(body, dict):
            body = {k: self._render(str(v), variables) for k, v in body.items()}
        elif isinstance(body, str):
            body = self._render(body, variables)

        try:
            if not url:
                raise ValueError("workflow step URL is required")
            self.target_guard.validate_url(url, base_url=active_base_url)
            if auth_profile is not None:
                validate_auth_profile_scope(auth_profile, url)
            if _has_plaintext_auth_headers(step_headers):
                raise PlaintextWorkflowAuthHeaderBlocked(
                    "Workflow step headers cannot carry auth material. "
                    "Attach credentials with an encrypted auth_profile_id."
                )
            headers = {**step_headers, **auth_headers}
            step_allows_state_change = bool(step.get("allow_state_change", self.allow_state_change))
            step_allows_destructive_methods = bool(
                step.get("allow_destructive_methods", step.get("allow_destructive", False))
            )
            state_guard = StateChangeGuard(
                allow_state_change=bool(self.allow_state_change and step_allows_state_change),
                allow_destructive_methods=bool(
                    self.allow_state_change
                    and self.allow_destructive_methods
                    and step_allows_destructive_methods
                ),
            )
            state_guard.validate_request({"method": method, "headers": headers})
            resp = await client.request(
                method, url, headers=headers,
                json=body if isinstance(body, dict) else None,
                content=body.encode() if isinstance(body, str) else None,
            )
            try:
                response_body = resp.json()
            except Exception:
                response_body = {"raw": resp.text[:2000]}

            assertions = step.get("assert", {})
            ok, msg = True, ""
            if "status_code" in assertions and resp.status_code != int(assertions["status_code"]):
                ok, msg = False, f"Expected {assertions['status_code']}, got {resp.status_code}"
            if ok and "body_contains" in assertions and assertions["body_contains"] not in resp.text:
                ok, msg = False, f"Body missing: {Redactor.redact_text(str(assertions['body_contains']))}"

            return {
                "step_name": step.get("name", f"Step"),
                "url": Redactor.redact_url(url),
                "method": method,
                "status_code": resp.status_code,
                "response_body": Redactor.redact_json(response_body),
                "_raw_response_body": response_body,
                "_workflow_base_url": active_base_url,
                "success": resp.is_success and ok,
                "assertion_passed": ok,
                "error": Redactor.redact_text(msg) if not ok else None,
            }
        except TargetGuardError as e:
            return {
                "step_name": step.get("name", "Step"),
                "url": Redactor.redact_url(url),
                "method": method,
                "success": False,
                "skip_reason": "target_guard",
                "error": f"target_guard_blocked: {Redactor.redact_text(str(e))}",
                "target_guard_policy": build_target_guard_policy(
                    url=url,
                    base_url=active_base_url,
                    reason=str(e),
                    guard=self.target_guard,
                ),
            }
        except AuthScopeError as e:
            policy = getattr(e, "auth_profile_scope_policy", None)
            if not isinstance(policy, dict):
                policy = auth_scope_policy_for_error(
                    e,
                    auth_profile=auth_profile,
                    target_url=url,
                    base_url=active_base_url,
                )
            return {
                "step_name": step.get("name", "Step"),
                "url": Redactor.redact_url(url),
                "method": method,
                "success": False,
                "skip_reason": "auth_profile_scope_guard",
                "error": Redactor.redact_text(str(e)),
                "auth_profile_scope_policy": policy,
            }
        except StateChangeBlocked as e:
            return {
                "step_name": step.get("name", "Step"),
                "url": Redactor.redact_url(url),
                "method": method,
                "success": False,
                "skip_reason": "state_change_guard",
                "error": Redactor.redact_text(str(e)),
                "state_change_policy": state_change_policy_for_request(
                    {"method": method, "headers": headers},
                    state_guard,
                    reason=str(e),
                ),
            }
        except PlaintextWorkflowAuthHeaderBlocked as e:
            return {
                "step_name": step.get("name", "Step"),
                "url": Redactor.redact_url(url),
                "method": method,
                "success": False,
                "skip_reason": "plaintext_auth_headers_not_allowed",
                "error": Redactor.redact_text(str(e)),
            }
        except Exception as e:
            return {
                "step_name": step.get("name", "Step"),
                "url": Redactor.redact_url(url),
                "method": method,
                "success": False,
                "error": Redactor.redact_text(str(e)),
            }

    def _render(self, template: str, variables: Dict[str, str]) -> str:
        for k, v in variables.items():
            template = template.replace(f"{{{{{k}}}}}", v)
        return template

    def _extract(self, body: Any, path: str) -> Any:
        current = body
        for part in path.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list) and part.isdigit():
                current = current[int(part)]
            else:
                return None
        return current


def _has_plaintext_auth_headers(headers: dict[str, Any]) -> bool:
    for key, value in (headers or {}).items():
        key_text = str(key or "").strip().lower()
        value_text = str(value or "").strip().lower()
        if key_text in _SENSITIVE_STEP_HEADER_NAMES:
            return True
        if value_text.startswith("bearer ") or value_text.startswith("basic "):
            return True
    return False
