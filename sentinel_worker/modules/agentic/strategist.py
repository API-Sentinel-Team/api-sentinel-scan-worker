"""Strategist: the LLM proposes test plans; this module validates them hard.

The strategist is the "probabilistic edge". It hands the model recon context
(endpoint shape, auth, observed responses, prior findings) and asks for a ranked
list of candidate tests. Every proposal is then **validated and clamped** against
a strict allowlist before it can reach the executor:

- the test category must be one the platform actually runs,
- the target endpoint must be one already in scope (the model cannot invent URLs),
- intensity is clamped to a safe bound,
- free-text rationale is length-capped and never executed.

A proposal that fails validation is dropped, not "fixed". If the model is absent
or returns garbage, the strategist returns an empty plan and the caller falls
back to deterministic selection. The LLM never picks a host, never sends a
request, and never decides severity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# The only test categories the strategist is allowed to propose. Maps to the
# platform's real detection surfaces.
ALLOWED_CATEGORIES = {
    "BOLA",
    "BFLA",
    "BROKEN_AUTH",
    "MASS_ASSIGNMENT",
    "EXCESSIVE_DATA_EXPOSURE",
    "SSRF",
    "INJECTION",
    "RATE_LIMIT",
    "BUSINESS_LOGIC",
    "LLM_PROMPT_INJECTION",
}
MAX_PROPOSALS = 25
MAX_RATIONALE_LEN = 280
_INTENSITY_MIN = 1
_INTENSITY_MAX = 5

# LLMs phrase categories in natural language; map common synonyms to the
# canonical allowlist BEFORE validating. This keeps the allowlist as the hard
# security boundary (an unmapped category is still dropped) while being robust to
# how a model actually talks. Keys are normalized (upper, non-alnum -> _).
_CATEGORY_SYNONYMS = {
    "AUTHORIZATION": "BFLA",
    "BROKEN_FUNCTION_LEVEL_AUTHORIZATION": "BFLA",
    "FUNCTION_LEVEL_AUTHORIZATION": "BFLA",
    "BROKEN_OBJECT_LEVEL_AUTHORIZATION": "BOLA",
    "OBJECT_LEVEL_AUTHORIZATION": "BOLA",
    "IDOR": "BOLA",
    "AUTHENTICATION": "BROKEN_AUTH",
    "BROKEN_AUTHENTICATION": "BROKEN_AUTH",
    "AUTH": "BROKEN_AUTH",
    "JWT": "BROKEN_AUTH",
    "MASS_ASSIGNMENT": "MASS_ASSIGNMENT",
    "EXCESSIVE_DATA": "EXCESSIVE_DATA_EXPOSURE",
    "DATA_EXPOSURE": "EXCESSIVE_DATA_EXPOSURE",
    "INFORMATION_DISCLOSURE": "EXCESSIVE_DATA_EXPOSURE",
    "SERVER_SIDE_REQUEST_FORGERY": "SSRF",
    "SQL_INJECTION": "INJECTION",
    "SQLI": "INJECTION",
    "COMMAND_INJECTION": "INJECTION",
    "NOSQL_INJECTION": "INJECTION",
    "RATE_LIMITING": "RATE_LIMIT",
    "RESOURCE_CONSUMPTION": "RATE_LIMIT",
    "BUSINESS_LOGIC": "BUSINESS_LOGIC",
    "BUSINESS_LOGIC_ABUSE": "BUSINESS_LOGIC",
    "LOGIC": "BUSINESS_LOGIC",
    "PROMPT_INJECTION": "LLM_PROMPT_INJECTION",
    "LLM_INJECTION": "LLM_PROMPT_INJECTION",
}


def canonical_category(raw: str) -> str | None:
    """Normalize a model-proposed category to a canonical allowed one, else None."""
    key = "".join(c if c.isalnum() else "_" for c in str(raw or "").strip().upper())
    key = "_".join(part for part in key.split("_") if part)  # collapse repeats
    if key in ALLOWED_CATEGORIES:
        return key
    return _CATEGORY_SYNONYMS.get(key)


@dataclass(frozen=True)
class TestProposal:
    """A single validated candidate test the LLM proposed."""

    category: str
    endpoint_id: str
    rationale: str
    intensity: int = 1
    priority: float = 0.5

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "endpoint_id": self.endpoint_id,
            "rationale": self.rationale,
            "intensity": self.intensity,
            "priority": self.priority,
        }


@dataclass
class StrategyPlan:
    proposals: list[TestProposal] = field(default_factory=list)
    dropped: list[dict[str, Any]] = field(default_factory=list)
    model_name: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "proposal_count": len(self.proposals),
            "dropped_count": len(self.dropped),
            "proposals": [p.as_dict() for p in self.proposals],
            "dropped": self.dropped,
        }


_SCHEMA_HINT = (
    '{"proposals": [{"category": "<one of allowed>", "endpoint_id": "<id from context>", '
    '"rationale": "<short why>", "intensity": 1-5, "priority": 0.0-1.0}]}'
)

_SYSTEM_PROMPT = (
    "You are an API security strategist for an authorized red-team engagement on "
    "OWNED APIs. Given recon context, propose a RANKED list of the most promising "
    "security tests. Only propose tests for endpoints present in the context. "
    "Only use the allowed categories. You do NOT execute anything; a deterministic "
    "engine runs and confirms. Prefer high-signal authorization and business-logic "
    "tests over generic noise. Return ONLY JSON."
)


def build_strategy(
    *,
    llm_client: Any,
    endpoints: list[dict[str, Any]],
    prior_findings: list[dict[str, Any]] | None = None,
    guarantee_authorization_tests: bool = True,
) -> StrategyPlan:
    """Ask the LLM to propose tests, then validate every proposal.

    When ``guarantee_authorization_tests`` is true (the production default), every
    authenticated endpoint with a private identifier additionally gets a
    deterministic BOLA proposal so the highest-signal test does not depend on LLM
    whim. Set false to test pure model-proposal validation in isolation.
    """
    valid_endpoint_ids = {str(ep.get("id")) for ep in endpoints if ep.get("id") is not None}
    user_prompt = _render_context(endpoints=endpoints, prior_findings=prior_findings or [])

    raw = llm_client.complete_json(
        system=_SYSTEM_PROMPT,
        user=user_prompt,
        schema_hint=_SCHEMA_HINT,
    )
    plan = StrategyPlan(model_name=getattr(llm_client, "name", "unknown"))

    raw_proposals = raw.get("proposals") if isinstance(raw, dict) else None
    if isinstance(raw_proposals, list):
        for entry in raw_proposals[:MAX_PROPOSALS]:
            proposal, reason = _validate_proposal(entry, valid_endpoint_ids)
            if proposal is not None:
                plan.proposals.append(proposal)
            else:
                plan.dropped.append({"entry": _safe_entry(entry), "reason": reason})

    # Deterministic safety net: high-signal authorization tests should not depend
    # on LLM whim. Every authenticated endpoint with a private identifier ALWAYS
    # gets a BOLA proposal (the single highest-value, reliably-confirmable test),
    # merged with — not replacing — the model's creative proposals.
    if guarantee_authorization_tests:
        _add_guaranteed_proposals(plan, endpoints)

    # Stable deterministic ordering: priority desc, then category, then endpoint.
    plan.proposals.sort(key=lambda p: (-p.priority, p.category, p.endpoint_id))
    return plan


def _add_guaranteed_proposals(plan: StrategyPlan, endpoints: list[dict[str, Any]]) -> None:
    existing = {(p.category, p.endpoint_id) for p in plan.proposals}
    for ep in endpoints:
        endpoint_id = str(ep.get("id")) if ep.get("id") is not None else None
        if endpoint_id is None:
            continue
        has_auth = bool(ep.get("auth_types_found"))
        try:
            has_private_id = int(ep.get("private_variable_count") or 0) > 0
        except (TypeError, ValueError):
            has_private_id = False
        if has_auth and has_private_id and ("BOLA", endpoint_id) not in existing:
            plan.proposals.append(
                TestProposal(
                    category="BOLA",
                    endpoint_id=endpoint_id,
                    rationale="authenticated endpoint exposes a private identifier; "
                    "cross-identity object access is the highest-signal test",
                    intensity=2,
                    priority=0.95,
                )
            )
            existing.add(("BOLA", endpoint_id))


def _validate_proposal(
    entry: Any, valid_endpoint_ids: set[str]
) -> tuple[TestProposal | None, str]:
    if not isinstance(entry, dict):
        return None, "not_an_object"

    category = canonical_category(entry.get("category"))
    if category is None:
        return None, "category_not_allowed"

    endpoint_id = str(entry.get("endpoint_id") or "").strip()
    if endpoint_id not in valid_endpoint_ids:
        return None, "endpoint_not_in_scope"

    intensity = _clamp_int(entry.get("intensity", 1), _INTENSITY_MIN, _INTENSITY_MAX)
    priority = _clamp_float(entry.get("priority", 0.5), 0.0, 1.0)
    rationale = str(entry.get("rationale") or "").strip()[:MAX_RATIONALE_LEN]

    return (
        TestProposal(
            category=category,
            endpoint_id=endpoint_id,
            rationale=rationale,
            intensity=intensity,
            priority=priority,
        ),
        "",
    )


def _clamp_int(value: Any, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return low


def _clamp_float(value: Any, low: float, high: float) -> float:
    try:
        return max(low, min(high, float(value)))
    except (TypeError, ValueError):
        return low


def _safe_entry(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {"raw": str(entry)[:120]}
    return {k: str(v)[:120] for k, v in list(entry.items())[:8]}


def _render_context(
    *, endpoints: list[dict[str, Any]], prior_findings: list[dict[str, Any]]
) -> str:
    lines = ["ENDPOINTS IN SCOPE:"]
    for ep in endpoints[:100]:
        lines.append(
            f"- id={ep.get('id')} {ep.get('method', 'GET')} {ep.get('path', '/')} "
            f"auth={ep.get('auth_types_found') or 'none'} "
            f"private_ids={ep.get('private_variable_count', 0)}"
        )
    if prior_findings:
        lines.append("")
        lines.append("PRIOR CONFIRMED FINDINGS (chain from these):")
        for f in prior_findings[:50]:
            lines.append(
                f"- {f.get('type', '?')} on endpoint {f.get('endpoint_id', '?')} "
                f"severity={f.get('severity', '?')}"
            )
    lines.append("")
    lines.append("Propose the highest-signal tests as JSON.")
    return "\n".join(lines)
