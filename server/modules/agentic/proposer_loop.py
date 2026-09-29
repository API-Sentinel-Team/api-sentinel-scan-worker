"""Proposer-confirmer loop: the agentic edge over the deterministic core.

This is where the North Star's P6 reasoning layer lives, built so that the LLM's
creativity is fully contained:

    recon context
        -> Strategist (LLM PROPOSES ranked tests)        [probabilistic]
        -> TargetGuard + StateChangeGuard (SAFETY)        [deterministic, hard]
        -> deterministic executor runs the test           [deterministic]
        -> judge confirms (your existing confirmation)    [deterministic]
        -> confirmed findings feed back into recon        [the loop]

The loop NEVER lets the LLM:
- choose a host or send a request (executor + guards own that),
- decide what is a confirmed finding (the judge owns that),
- escalate intensity past the safe clamp (strategist owns that).

The executor and judge are injected as callables so this module stays decoupled
and unit-testable. In production they are wired to the real ExecutionEngine and
confirmation pipeline; in tests they are deterministic fakes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from server.modules.agentic.strategist import StrategyPlan, TestProposal, build_strategy

# A guard callable returns (allowed, reason). Reuses the platform's real guards.
GuardFn = Callable[[TestProposal, dict[str, Any]], "GuardDecision"]
# An executor runs one proposal against its endpoint and returns a raw result.
ExecutorFn = Callable[[TestProposal, dict[str, Any]], dict[str, Any]]
# A judge takes a raw result and returns a confirmation verdict dict.
JudgeFn = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    reason: str = ""


@dataclass
class LoopOutcome:
    confirmed_findings: list[dict[str, Any]] = field(default_factory=list)
    proposed: int = 0
    guard_blocked: list[dict[str, Any]] = field(default_factory=list)
    executed: int = 0
    unconfirmed: int = 0
    rounds: int = 0
    model_name: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "rounds": self.rounds,
            "proposed": self.proposed,
            "executed": self.executed,
            "guard_blocked_count": len(self.guard_blocked),
            "guard_blocked": self.guard_blocked,
            "confirmed_count": len(self.confirmed_findings),
            "unconfirmed": self.unconfirmed,
            "confirmed_findings": self.confirmed_findings,
        }


def run_proposer_confirmer(
    *,
    llm_client: Any,
    endpoints: list[dict[str, Any]],
    guard: GuardFn,
    executor: ExecutorFn,
    judge: JudgeFn,
    max_rounds: int = 3,
    prior_findings: list[dict[str, Any]] | None = None,
) -> LoopOutcome:
    """Run the bounded propose -> guard -> execute -> judge -> feedback loop."""
    endpoints_by_id = {str(ep.get("id")): ep for ep in endpoints if ep.get("id") is not None}
    outcome = LoopOutcome()
    confirmed_running: list[dict[str, Any]] = list(prior_findings or [])
    seen_proposals: set[tuple[str, str]] = set()

    for round_index in range(max(1, max_rounds)):
        plan: StrategyPlan = build_strategy(
            llm_client=llm_client,
            endpoints=endpoints,
            prior_findings=confirmed_running,
        )
        outcome.model_name = plan.model_name
        outcome.rounds = round_index + 1

        fresh = [
            p for p in plan.proposals
            if (p.category, p.endpoint_id) not in seen_proposals
        ]
        if not fresh:
            break  # converged: nothing new to try

        new_confirmed_this_round = 0
        for proposal in fresh:
            seen_proposals.add((proposal.category, proposal.endpoint_id))
            outcome.proposed += 1
            endpoint = endpoints_by_id.get(proposal.endpoint_id)
            if endpoint is None:
                outcome.guard_blocked.append(
                    {"proposal": proposal.as_dict(), "reason": "endpoint_missing"}
                )
                continue

            decision = guard(proposal, endpoint)
            if not decision.allowed:
                outcome.guard_blocked.append(
                    {"proposal": proposal.as_dict(), "reason": decision.reason}
                )
                continue

            result = executor(proposal, endpoint)
            outcome.executed += 1

            verdict = judge(result)
            if verdict.get("confirmed"):
                finding = _build_finding(proposal, result, verdict)
                outcome.confirmed_findings.append(finding)
                confirmed_running.append(finding)
                new_confirmed_this_round += 1
            else:
                outcome.unconfirmed += 1

        if new_confirmed_this_round == 0:
            break  # no new confirmed findings -> further rounds unlikely to help

    return outcome


def _build_finding(
    proposal: TestProposal, result: dict[str, Any], verdict: dict[str, Any]
) -> dict[str, Any]:
    # The deterministic engine/replay result's own ``type`` is authoritative — it
    # may differ from the LLM's proposed category (e.g. a BOLA proposal that the
    # replay's no-auth control reclassifies as BROKEN_AUTH). Prefer it; fall back
    # to the proposal category only when the result did not specify one.
    finding = {
        "type": result.get("type") or proposal.category,
        "endpoint_id": proposal.endpoint_id,
        "severity": verdict.get("severity", result.get("severity", "MEDIUM")),
        "confidence": verdict.get("confidence", "MEDIUM"),
        "rationale": proposal.rationale,
        "evidence": verdict.get("evidence") or result.get("evidence"),
    }
    if isinstance(result.get("assessment"), dict):
        finding["assessment"] = result["assessment"]
    # Carry identifier fields a finding exposed so the knowledge graph can build
    # cross-object chains from them on the next round.
    exposed_fields = verdict.get("exposed_fields") or result.get("exposed_fields")
    if exposed_fields:
        finding["exposed_fields"] = exposed_fields
    return finding


async def run_proposer_confirmer_async(
    *,
    llm_client: Any,
    endpoints: list[dict[str, Any]],
    guard: GuardFn,
    executor: Callable[[TestProposal, dict[str, Any]], Any],
    judge: JudgeFn,
    max_rounds: int = 3,
    prior_findings: list[dict[str, Any]] | None = None,
) -> LoopOutcome:
    """Async sibling of :func:`run_proposer_confirmer`.

    Identical control flow, but ``executor`` is awaited so engine calls stay on
    the caller's event loop and DB session (no thread/loop hazards). The
    strategist, guard, and judge stay synchronous (they are pure/CPU-only).
    """
    endpoints_by_id = {str(ep.get("id")): ep for ep in endpoints if ep.get("id") is not None}
    outcome = LoopOutcome()
    confirmed_running: list[dict[str, Any]] = list(prior_findings or [])
    seen_proposals: set[tuple[str, str]] = set()

    for round_index in range(max(1, max_rounds)):
        plan: StrategyPlan = build_strategy(
            llm_client=llm_client,
            endpoints=endpoints,
            prior_findings=confirmed_running,
        )
        outcome.model_name = plan.model_name
        outcome.rounds = round_index + 1

        fresh = [
            p for p in plan.proposals
            if (p.category, p.endpoint_id) not in seen_proposals
        ]
        if not fresh:
            break

        new_confirmed_this_round = 0
        for proposal in fresh:
            seen_proposals.add((proposal.category, proposal.endpoint_id))
            outcome.proposed += 1
            endpoint = endpoints_by_id.get(proposal.endpoint_id)
            if endpoint is None:
                outcome.guard_blocked.append(
                    {"proposal": proposal.as_dict(), "reason": "endpoint_missing"}
                )
                continue

            decision = guard(proposal, endpoint)
            if not decision.allowed:
                outcome.guard_blocked.append(
                    {"proposal": proposal.as_dict(), "reason": decision.reason}
                )
                continue

            result = await executor(proposal, endpoint)
            outcome.executed += 1

            verdict = judge(result)
            if verdict.get("confirmed"):
                finding = _build_finding(proposal, result, verdict)
                outcome.confirmed_findings.append(finding)
                confirmed_running.append(finding)
                new_confirmed_this_round += 1
            else:
                outcome.unconfirmed += 1

        if new_confirmed_this_round == 0:
            break

    return outcome
