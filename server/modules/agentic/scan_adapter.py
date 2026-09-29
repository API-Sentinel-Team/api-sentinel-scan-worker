"""Bridge the agentic proposer-confirmer loop to the real scan engine.

The agentic layer is engine-agnostic: it calls an ``executor`` to run a proposal
and a ``judge`` to confirm the result. This module supplies both, wired to the
platform's real :class:`ExecutionEngine` and its deterministic vulnerability
signal — so a confirmed agentic finding went through the exact same execution and
evidence path as a normal scan finding. The LLM only chose *which* category to
try on *which* in-scope endpoint; everything that touches the network or decides
"is this real" is the deterministic engine.

Category -> template selection uses each template's ``info.category.shortName``.
A proposal maps to the highest-priority matching template for its endpoint.
"""
from __future__ import annotations

from typing import Any, Callable

from server.modules.agentic.strategist import TestProposal

# Map strategist proposal categories to the template ``info.category.shortName``
# values that actually exist in the library (see template vocabulary).
_CATEGORY_TO_TEMPLATE_CATEGORIES: dict[str, tuple[str, ...]] = {
    "BOLA": ("BOLA", "Broken Object Level Authorization"),
    "BFLA": ("BFLA", "Broken Function Level Authorization"),
    "BROKEN_AUTH": ("Broken Authentication",),
    "MASS_ASSIGNMENT": ("Mass Assignment",),
    "EXCESSIVE_DATA_EXPOSURE": ("Mass Assignment", "Misconfiguration"),
    "SSRF": ("Server Side Request Forgery",),
    "INJECTION": (
        "Command Injection",
        "Injection",
        "Injection Attacks",
        "Input Validation",
        "Server Side Template Injection",
        "CRLF Injection",
    ),
    "RATE_LIMIT": ("Lack of Resources & Rate Limiting",),
    "BUSINESS_LOGIC": ("BFLA", "Mass Assignment"),
    "LLM_PROMPT_INJECTION": ("Injection", "Input Validation"),
}


def _template_short_name(template: dict[str, Any]) -> str:
    category = (template.get("info", {}) or {}).get("category") or {}
    if isinstance(category, dict):
        return str(category.get("shortName") or category.get("name") or "")
    return str(category or "")


def build_template_index(templates: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group templates by their short category name for fast proposal lookup."""
    index: dict[str, list[dict[str, Any]]] = {}
    for template in templates:
        index.setdefault(_template_short_name(template), []).append(template)
    return index


def templates_for_category(
    category: str, index: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for short_name in _CATEGORY_TO_TEMPLATE_CATEGORIES.get(category.upper(), ()):  # noqa: E501
        matches.extend(index.get(short_name, []))
    return matches


# Categories that are confirmed by multi-identity replay, not by a template.
_REPLAY_CATEGORIES = {"BOLA", "BFLA"}


def make_async_scan_executor(
    *,
    engine: Any,
    templates: list[dict[str, Any]],
    selection_context_by_endpoint: dict[str, dict[str, Any]] | None = None,
    max_templates_per_proposal: int = 3,
    test_accounts: list[Any] | None = None,
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
) -> Callable[[TestProposal, dict[str, Any]], Any]:
    """Return an async ExecutorFn that runs a proposal via the real engine.

    Routing:
    - BOLA/BFLA proposals -> authenticated multi-identity replay-and-diff (the
      only way to *confirm* an authorization bug), when >=2 test identities are
      configured. Falls back to the template path otherwise.
    - all other categories -> the deterministic template ExecutionEngine.

    Awaited by ``run_proposer_confirmer_async`` so engine calls stay on the
    caller's event loop and DB session.
    """
    index = build_template_index(templates)
    selection_context_by_endpoint = selection_context_by_endpoint or {}
    accounts = list(test_accounts or [])

    async def executor(proposal: TestProposal, endpoint: dict[str, Any]) -> dict[str, Any]:
        # Authorization categories can ONLY be confirmed by multi-identity replay
        # (a template hit cannot prove cross-identity access). Never fall through to
        # templates for these — doing so mislabels a generic template finding as
        # BOLA/BFLA, a false positive.
        if proposal.category in _REPLAY_CATEGORIES:
            if len(accounts) < 2:
                return {"is_vulnerable": False, "skip_reason": "insufficient_identities_for_replay"}
            replay_result = await _run_replay(
                proposal=proposal,
                endpoint=endpoint,
                accounts=accounts,
                allow_state_change=allow_state_change,
                allow_destructive_methods=allow_destructive_methods,
            )
            if replay_result is None:
                return {"is_vulnerable": False, "skip_reason": "no_identity_pair_for_replay"}
            return replay_result

        candidates = templates_for_category(proposal.category, index)
        if not candidates:
            return {"is_vulnerable": False, "skip_reason": "no_template_for_category"}

        selection_context = selection_context_by_endpoint.get(proposal.endpoint_id)
        last_result: dict[str, Any] = {"is_vulnerable": False}
        for template in candidates[:max_templates_per_proposal]:
            result = await engine.execute_test(
                endpoint, template, selection_context=selection_context
            )
            last_result = result
            if result.get("is_vulnerable"):
                # Keep the template's own finding type; do NOT relabel it as the
                # proposed category (that would misattribute the finding).
                result.setdefault("type", result.get("template_id") or proposal.category)
                return result
        return last_result

    return executor


async def _run_replay(
    *,
    proposal: TestProposal,
    endpoint: dict[str, Any],
    accounts: list[Any],
    allow_state_change: bool,
    allow_destructive_methods: bool,
) -> dict[str, Any] | None:
    """Run multi-identity replay for a BOLA/BFLA proposal. None if no identity pair."""
    from server.modules.identity.multi_identity_replay import (
        pick_identity_pair,
        run_multi_identity_replay,
    )

    if proposal.category.upper() == "BFLA":
        from server.modules.identity.bfla_matrix import pick_bfla_pair
        pair = pick_bfla_pair(accounts, endpoint=endpoint)
    else:
        pair = pick_identity_pair(accounts, issue=proposal.category)

    if pair is None:
        return None
    victim, attacker = pair
    return await run_multi_identity_replay(
        endpoint=endpoint,
        victim=victim,
        attacker=attacker,
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )


def scan_judge(result: dict[str, Any]) -> dict[str, Any]:
    """Confirm a result using the engine's own deterministic vulnerability signal.

    The engine already ran confirmation/evidence logic; the agentic judge simply
    trusts that deterministic verdict (the LLM does not get a vote on truth).
    """
    confirmed = bool(result.get("is_vulnerable"))
    return {
        "confirmed": confirmed,
        "severity": result.get("severity", "MEDIUM"),
        "confidence": "HIGH" if confirmed else "LOW",
        "evidence": result.get("evidence"),
    }
