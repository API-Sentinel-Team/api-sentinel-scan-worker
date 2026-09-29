"""High-level agentic orchestration: graph -> strategist -> proposer-confirmer.

This is the single entry point the rest of the platform calls to run the
agentic reasoning layer over a set of endpoints. It:

1. builds/loads the :class:`KnowledgeGraph` recon model,
2. runs the bounded proposer-confirmer loop with the real safety guards,
3. returns confirmed findings plus the updated graph for persistence.

It is gated by ``AGENTIC_LLM_ENABLED``: when off (the default), it returns an
empty, well-formed result without calling any model, so callers can invoke it
unconditionally and the platform behaves exactly as before until an operator
opts in.
"""
from __future__ import annotations

from typing import Any, Callable

from server.modules.agentic.guard_adapter import make_guard
from server.modules.agentic.knowledge_graph import KnowledgeGraph, build_from_endpoints
from server.modules.agentic.llm_client import build_llm_client
from server.modules.agentic.proposer_loop import (
    ExecutorFn,
    JudgeFn,
    LoopOutcome,
    run_proposer_confirmer,
    run_proposer_confirmer_async,
)


def run_agentic_assessment(
    *,
    endpoints: list[dict[str, Any]],
    executor: ExecutorFn,
    judge: JudgeFn,
    settings: Any = None,
    existing_graph: KnowledgeGraph | None = None,
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
    llm_client: Any = None,
) -> dict[str, Any]:
    """Run the agentic loop. Returns {enabled, outcome, graph} as plain dicts.

    ``executor`` and ``judge`` are injected so the caller wires them to the real
    ExecutionEngine + confirmation pipeline (production) or fakes (tests). The
    LLM, guards, and graph are constructed here from settings.
    """
    if settings is None:
        from server.config import settings as default_settings

        settings = default_settings

    graph = (existing_graph or KnowledgeGraph()).merge(build_from_endpoints(endpoints))

    if not bool(getattr(settings, "AGENTIC_LLM_ENABLED", False)):
        return {
            "enabled": False,
            "reason": "agentic_llm_disabled",
            "outcome": LoopOutcome(model_name="disabled").as_dict(),
            "graph": graph.as_dict(),
        }

    client = llm_client or build_llm_client(settings)
    from server.modules.test_executor.target_guard import TargetGuard

    guard = make_guard(
        target_guard=TargetGuard.from_settings(settings),
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )

    outcome = run_proposer_confirmer(
        llm_client=client,
        endpoints=graph.recon_context(),
        guard=guard,
        executor=executor,
        judge=judge,
        max_rounds=int(getattr(settings, "AGENTIC_LOOP_MAX_ROUNDS", 3)),
    )

    # Feed confirmed findings back into the graph so chains grow across runs.
    for finding in outcome.confirmed_findings:
        graph.ingest_finding(finding)

    return {
        "enabled": True,
        "outcome": outcome.as_dict(),
        "graph": graph.as_dict(),
    }


async def run_agentic_scan_async(
    *,
    engine: Any,
    endpoints: list[dict[str, Any]],
    templates: list[dict[str, Any]],
    settings: Any = None,
    existing_graph: KnowledgeGraph | None = None,
    prior_findings: list[dict[str, Any]] | None = None,
    selection_context_by_endpoint: dict[str, dict[str, Any]] | None = None,
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
    test_accounts: list[Any] | None = None,
    llm_client: Any = None,
) -> dict[str, Any]:
    """Run the agentic loop wired to the live ExecutionEngine (async, on-loop).

    This is what ``/api/tests/run`` calls after the deterministic scan. The
    executor/judge come from :mod:`server.modules.agentic.scan_adapter`, so a
    confirmed agentic finding traversed the exact same engine + evidence path as a
    normal finding. Gated by ``AGENTIC_LLM_ENABLED`` (no-op when off).
    """
    if settings is None:
        from server.config import settings as default_settings

        settings = default_settings

    graph = (existing_graph or KnowledgeGraph()).merge(build_from_endpoints(endpoints))

    # Active deterministic sweeps (attack chains + targeted detectors) issue real
    # httpx traffic against discovered endpoints. Require an explicit pentest
    # target allowlist so we never actively probe hosts the operator has not
    # scoped. When the allowlist is empty (e.g. test fixtures, or a fresh
    # deploy that hasn't been scoped yet), skip the sweeps entirely — the LLM
    # proposer loop below is separately gated by AGENTIC_LLM_ENABLED.
    allowlist = str(getattr(settings, "PENTEST_TARGET_ALLOWLIST", "") or "").strip()
    active_sweeps_allowed = bool(allowlist)

    # ── ALWAYS (when allowlist is set): multi-step attack chains (no LLM) ──
    # These are deterministic and need >=2 identities (same requirement as
    # replay). The graph is enriched here so later stages (LLM proposer,
    # detector sweep) see cross-endpoint edges.
    chain_findings: list[dict[str, Any]] = []
    if active_sweeps_allowed and test_accounts and len(test_accounts) >= 2:
        chain_findings = await _run_attack_chains(
            graph=graph,
            endpoints=endpoints,
            victim=test_accounts[0],
            attacker=test_accounts[1],
            settings=settings,
            allow_state_change=allow_state_change,
            allow_destructive_methods=allow_destructive_methods,
        )
        for finding in chain_findings:
            graph.ingest_finding(finding)

    # ── ALWAYS (when allowlist is set): targeted deterministic detectors ────
    # Single-endpoint checks that templates miss: sensitive-data/credential
    # dumps, error-based SQLi, and mass-assignment. Deterministic (no LLM),
    # each behind the same TargetGuard/StateChangeGuard as the rest of the
    # engine.
    detector_findings: list[dict[str, Any]] = []
    if active_sweeps_allowed:
        detector_findings = await _run_targeted_detectors(
            endpoints=endpoints,
            settings=settings,
            allow_state_change=allow_state_change,
        )
    for finding in detector_findings:
        graph.ingest_finding(finding)

    if not bool(getattr(settings, "AGENTIC_LLM_ENABLED", False)):
        return {
            "enabled": False,
            "reason": "agentic_llm_disabled",
            "outcome": LoopOutcome(model_name="disabled").as_dict(),
            "chain_findings": chain_findings,
            "detector_findings": detector_findings,
            "graph": graph.as_dict(),
        }

    from server.modules.agentic.scan_adapter import make_async_scan_executor, scan_judge
    from server.modules.test_executor.target_guard import TargetGuard

    client = llm_client or build_llm_client(settings)
    guard = make_guard(
        target_guard=TargetGuard.from_settings(settings),
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )
    executor = make_async_scan_executor(
        engine=engine,
        templates=templates,
        selection_context_by_endpoint=selection_context_by_endpoint,
        test_accounts=test_accounts,
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )

    outcome = await run_proposer_confirmer_async(
        llm_client=client,
        endpoints=graph.recon_context(),
        guard=guard,
        executor=executor,
        judge=scan_judge,
        max_rounds=int(getattr(settings, "AGENTIC_LOOP_MAX_ROUNDS", 3)),
        prior_findings=prior_findings,
    )

    for finding in outcome.confirmed_findings:
        graph.ingest_finding(finding)

    return {
        "enabled": True,
        "outcome": outcome.as_dict(),
        "chain_findings": chain_findings,
        "detector_findings": detector_findings,
        "graph": graph.as_dict(),
    }


async def _run_targeted_detectors(
    *,
    endpoints: list[dict[str, Any]],
    settings: Any,
    allow_state_change: bool,
    max_endpoints: int = 100,
) -> list[dict[str, Any]]:
    """Run sensitive-exposure / SQLi / mass-assignment / business-abuse detectors per endpoint."""
    from server.modules.identity.business_abuse import detect_coupon_reuse, detect_otp_spam
    from server.modules.identity.mass_assignment import detect_mass_assignment
    from server.modules.identity.sensitive_exposure import detect_sensitive_exposure
    from server.modules.identity.sqli_probe import (
        detect_boolean_based_sqli,
        detect_error_based_sqli,
    )
    from server.modules.test_executor.target_guard import TargetGuard

    guard = TargetGuard.from_settings(settings)
    findings: list[dict[str, Any]] = []

    def _record(result: dict[str, Any], endpoint: dict[str, Any]) -> None:
        if result.get("is_vulnerable"):
            findings.append(
                {
                    "type": result.get("type"),
                    "endpoint_id": str(endpoint.get("id") or ""),
                    "severity": result.get("severity", "MEDIUM"),
                    "evidence": result.get("evidence"),
                }
            )

    for endpoint in endpoints[:max_endpoints]:
        method = str(endpoint.get("method") or "GET").upper()
        try:
            if method in {"GET", "HEAD"}:
                _record(await detect_sensitive_exposure(endpoint=endpoint, target_guard=guard), endpoint)
                _record(await detect_error_based_sqli(endpoint=endpoint, target_guard=guard), endpoint)
                _record(await detect_boolean_based_sqli(endpoint=endpoint, target_guard=guard), endpoint)
            elif method in {"POST", "PUT", "PATCH"}:
                # Mass assignment needs a base payload; use the captured/sampled body
                # when present, else a minimal generic registration-style payload.
                base_payload = _base_payload_for(endpoint)
                _record(
                    await detect_mass_assignment(
                        endpoint=endpoint,
                        base_payload=base_payload,
                        target_guard=guard,
                        allow_state_change=allow_state_change,
                    ),
                    endpoint,
                )
                _record(
                    await detect_otp_spam(
                        endpoint=endpoint,
                        target_guard=guard,
                        allow_state_change=allow_state_change,
                    ),
                    endpoint,
                )
                _record(
                    await detect_coupon_reuse(
                        endpoint=endpoint,
                        target_guard=guard,
                        allow_state_change=allow_state_change,
                    ),
                    endpoint,
                )
        except Exception:  # one bad endpoint must not abort the sweep
            continue
    return findings


def _base_payload_for(endpoint: dict[str, Any]) -> dict[str, Any]:
    """Best-effort request body for a write endpoint's mass-assignment probe."""
    import json as _json

    raw = endpoint.get("last_request_body")
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = _json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, TypeError):
            pass
    # Generic fallback covering common create/registration shapes.
    return {"username": "sentinel_probe", "password": "Sentinel123!", "email": "sentinel_probe@example.com"}


async def _run_attack_chains(
    *,
    graph: KnowledgeGraph,
    endpoints: list[dict[str, Any]],
    victim: Any,
    attacker: Any,
    settings: Any,
    allow_state_change: bool,
    allow_destructive_methods: bool,
    max_chains: int = 25,
) -> list[dict[str, Any]]:
    """Execute the knowledge graph's cross-endpoint chains as 2-step attacks."""
    from server.modules.identity.attack_chain import run_attack_chain
    from server.modules.test_executor.target_guard import TargetGuard

    endpoints_by_id = {str(ep.get("id")): ep for ep in endpoints if ep.get("id") is not None}
    guard = TargetGuard.from_settings(settings)
    findings: list[dict[str, Any]] = []

    for edge in graph.chains()[:max_chains]:
        source = endpoints_by_id.get(edge.source_endpoint_id)
        target = endpoints_by_id.get(edge.target_endpoint_id)
        if source is None or target is None:
            continue
        try:
            result = await run_attack_chain(
                source_endpoint=source,
                target_endpoint=target,
                victim=victim,
                attacker=attacker,
                id_kind=edge.id_kind,
                target_guard=guard,
                allow_state_change=allow_state_change,
                allow_destructive_methods=allow_destructive_methods,
            )
        except Exception:  # a single bad chain must not abort the rest
            continue
        if result.get("is_vulnerable"):
            findings.append(
                {
                    "type": result.get("type", "BOLA"),
                    "endpoint_id": edge.target_endpoint_id,
                    "severity": result.get("severity", "MEDIUM"),
                    "confidence": result.get("confidence"),
                    "rationale": f"2-step chain: {edge.reason}",
                    "chain": result.get("chain"),
                }
            )
    return findings
