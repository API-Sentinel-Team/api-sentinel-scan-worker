"""
Dedicated BOLA (Broken Object Level Authorization) validator.

Executes cross-user replay: uses victim's request but attacker's token.
Determines vulnerability based on response similarity (percentage_match).
"""
import httpx
from server.modules.pentest.target_policy import build_target_guard_policy
from server.modules.utils.redactor import Redactor

from ..test_executor.response_validator import ResponseValidator
from ..test_executor.state_change_guard import (
    StateChangeBlocked,
    StateChangeGuard,
    state_change_policy_for_request,
)
from ..test_executor.target_guard import TargetGuard, TargetGuardError
from .auth_mechanism import AuthMechanismManager


class BOLAValidator:
    """
    Replays a victim's request with the attacker's auth token.
    If the server returns the same resource → BOLA confirmed.
    """

    def __init__(
        self,
        attacker_token: str,
        auth_header: str = "Authorization",
        *,
        target_guard: TargetGuard | None = None,
        allow_state_change: bool = False,
    ):
        self.attacker_token = attacker_token
        self.auth_header = auth_header
        self.auth_manager = AuthMechanismManager()
        self.validator = ResponseValidator()
        self.target_guard = target_guard or TargetGuard.from_settings()
        self.state_guard = StateChangeGuard(allow_state_change=allow_state_change)

    async def validate(
        self,
        original_request: dict,
        original_response: dict,
        validate_rules: dict,
        timeout: float = 10.0,
    ) -> dict:
        """
        Returns {is_vulnerable, similarity_pct, status_code, evidence}
        """
        # Build attacker request: swap auth token
        attacker_headers = self.auth_manager.replace_auth(
            original_request.get("headers", {}),
            self.attacker_token,
            self.auth_header,
        )
        attacker_request = {**original_request, "headers": attacker_headers}

        try:
            self.target_guard.validate_url(attacker_request["url"], base_url=original_request.get("url"))
            self.state_guard.validate_request(attacker_request)
            async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                resp = await client.request(
                    method=attacker_request["method"],
                    url=attacker_request["url"],
                    headers=attacker_request["headers"],
                    content=attacker_request.get("body", ""),
                )
                attacker_response = {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text,
                }

            # Calculate similarity
            orig_body = original_response.get("body", "")
            att_body = attacker_response.get("body", "")
            similarity = self.validator._percentage_match(orig_body, att_body)
            schema_match = self.validator._percentage_match_schema(orig_body, att_body)

            is_vulnerable = self.validator.validate(attacker_response, validate_rules, original_response)

            return {
                "is_vulnerable": is_vulnerable,
                "similarity_pct": similarity,
                "schema_match_pct": schema_match,
                "attacker_status_code": attacker_response["status_code"],
                "evidence": f"Response similarity: {similarity:.1f}% (schema: {schema_match:.1f}%)",
            }

        except TargetGuardError as e:
            target_url = str(attacker_request.get("url") or original_request.get("url") or "")
            return {
                "is_vulnerable": False,
                "skip_reason": "target_guard",
                "error": f"target_guard_blocked: {Redactor.redact_text(str(e))}",
                "target_guard_policy": build_target_guard_policy(
                    url=target_url,
                    base_url=target_url,
                    reason=str(e),
                    guard=self.target_guard,
                ),
            }
        except StateChangeBlocked as e:
            return {
                "is_vulnerable": False,
                "skip_reason": "state_change_guard",
                "error": Redactor.redact_text(str(e)),
                "state_change_policy": state_change_policy_for_request(
                    attacker_request,
                    self.state_guard,
                    reason=str(e),
                ),
            }
        except Exception as e:
            return {"is_vulnerable": False, "error": Redactor.redact_text(str(e))}
