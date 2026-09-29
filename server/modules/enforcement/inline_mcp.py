"""Inline enforcement decisions for MCP traffic."""
from __future__ import annotations

from typing import List, Tuple, Dict, Any

from server.modules.enforcement.engine import push_waf_rule, circuit_breaker


async def apply_inline_decision(
    db,
    account_id: int,
    agent_id: str,
    tool_name: str,
    violations: List[Tuple[str, str, Dict[str, Any]]],
) -> None:
    """Apply inline enforcement actions for MCP violations.

    This is an out-of-band fallback when inline blocking is not available.
    """
    for v_type, v_sev, v_details in violations:
        if v_type in ("PROMPT_INJECTION", "TRUST_CHAIN_VIOLATION"):
            # Push a WAF rule as a fallback signal
            await push_waf_rule(
                db,
                account_id,
                rule_id=f"mcp-{v_type.lower()}",
                source_ips=[],
                path=f"mcp:{tool_name}",
                severity=v_sev,
            )
        if v_sev in ("CRITICAL",) and v_type == "TRUST_CHAIN_VIOLATION":
            # Optional circuit breaker for critical trust violations
            await circuit_breaker(
                db,
                account_id,
                endpoint_id=f"mcp:{tool_name}",
                duration_minutes=60,
                reason="MCP trust-chain violation",
            )
