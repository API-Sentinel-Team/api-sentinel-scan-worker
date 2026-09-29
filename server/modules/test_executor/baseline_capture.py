"""
Captures a baseline response from an endpoint before mutation.
Used by ExecutionEngine to feed original_response into percentage_match checks.
"""
import httpx

from server.modules.pentest.target_policy import build_target_guard_policy

from .state_change_guard import StateChangeGuard, state_change_policy_for_request
from .target_guard import TargetGuard, TargetGuardError


class BaselineCapturer:
    """Sends the original (unmodified) request to get a baseline response."""

    async def capture(
        self,
        endpoint: dict,
        *,
        headers: dict | None = None,
        cookies: dict | None = None,
        timeout_seconds: float = 8.0,
        follow_redirects: bool = False,
        auth: tuple[str, str] | None = None,
        allow_state_change: bool = False,
        allow_destructive_methods: bool = False,
        target_guard: TargetGuard | None = None,
    ) -> dict:
        url = endpoint.get("url") or f"{endpoint.get('protocol', 'http')}://{endpoint.get('host', '')}{endpoint.get('path', '/')}"
        method = endpoint.get("method", "GET").upper()
        merged_headers = dict(endpoint.get("headers") or {})
        merged_headers.update(headers or {})

        active_target_guard = target_guard or TargetGuard.from_settings()
        try:
            active_target_guard.validate_url(url, base_url=url)
        except TargetGuardError as exc:
            return {
                "status_code": endpoint.get("last_response_code", 0) or 0,
                "headers": endpoint.get("last_response_headers") or {},
                "body": endpoint.get("last_response_body") or "",
                "skipped": True,
                "skip_reason": "target_guard_baseline_blocked",
                "error": f"target_guard_blocked: {exc}",
                "target_guard_policy": build_target_guard_policy(
                    url=url,
                    base_url=url,
                    reason=str(exc),
                    guard=active_target_guard,
                ),
            }

        if not allow_state_change and not StateChangeGuard.is_safe_method(method):
            guard = StateChangeGuard(
                allow_state_change=allow_state_change,
                allow_destructive_methods=allow_destructive_methods,
            )
            reason = f"state_change_blocked: {method} requires baseline allow_state_change=true"
            state_change_policy = state_change_policy_for_request(
                {"method": method, "headers": merged_headers},
                guard,
                reason=reason,
            )
            return {
                "status_code": endpoint.get("last_response_code", 0) or 0,
                "headers": endpoint.get("last_response_headers") or {},
                "body": endpoint.get("last_response_body") or "",
                "skipped": True,
                "skip_reason": "state_change_baseline_blocked",
                "state_change_policy": state_change_policy,
            }
        if StateChangeGuard.is_destructive_method(method) and not allow_destructive_methods:
            guard = StateChangeGuard(
                allow_state_change=allow_state_change,
                allow_destructive_methods=allow_destructive_methods,
            )
            reason = f"destructive_method_blocked: {method} requires baseline allow_destructive_methods=true"
            return {
                "status_code": endpoint.get("last_response_code", 0) or 0,
                "headers": endpoint.get("last_response_headers") or {},
                "body": endpoint.get("last_response_body") or "",
                "skipped": True,
                "skip_reason": "destructive_baseline_blocked",
                "state_change_policy": state_change_policy_for_request(
                    {"method": method, "headers": merged_headers},
                    guard,
                    reason=reason,
                ),
            }

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds, verify=True, cookies=cookies or {}) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=merged_headers,
                    auth=auth,
                    follow_redirects=follow_redirects,
                )
                return {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text,
                }
        except Exception:
            # Fall back to cached data stored on the endpoint record
            return {
                "status_code": endpoint.get("last_response_code", 200),
                "headers": {},
                "body": endpoint.get("last_response_body") or "",
            }
