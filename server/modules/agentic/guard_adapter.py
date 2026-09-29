"""Bridge LLM-proposed tests to the platform's existing safety guards.

The agentic loop must not re-implement safety — it reuses the SAME TargetGuard
and StateChangeGuard the deterministic engine uses, so there is one safety model,
not two. This adapter turns a strategist proposal + endpoint into a guard
decision using those real guards.
"""
from __future__ import annotations

from server.modules.agentic.proposer_loop import GuardDecision
from server.modules.agentic.strategist import TestProposal
from server.modules.test_executor.state_change_guard import StateChangeGuard
from server.modules.test_executor.target_guard import (
    TargetGuard,
    TargetGuardError,
    endpoint_target_url,
)

# Categories that imply a state-changing request. These require the same
# allow_state_change / destructive arming the deterministic engine enforces.
_STATE_CHANGING_CATEGORIES = {"MASS_ASSIGNMENT", "BUSINESS_LOGIC", "INJECTION"}


def make_guard(
    *,
    target_guard: TargetGuard | None = None,
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
):
    """Return a GuardFn closure bound to real guard instances."""
    tguard = target_guard or TargetGuard.from_settings()
    sguard = StateChangeGuard(
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )

    def guard(proposal: TestProposal, endpoint: dict) -> GuardDecision:
        url = endpoint_target_url(endpoint)
        try:
            tguard.validate_url(url, base_url=url)
        except TargetGuardError as exc:
            return GuardDecision(allowed=False, reason=f"target_guard: {exc}")

        method = str(endpoint.get("method") or "GET")
        # BFLA/BOLA replay and a state-changing category both require the method
        # to clear the state-change guard.
        try:
            sguard.validate_method(method)
        except Exception as exc:  # StateChangeBlocked subclasses ValueError
            return GuardDecision(allowed=False, reason=f"state_change_guard: {exc}")

        if proposal.category in _STATE_CHANGING_CATEGORIES and not sguard.allow_state_change:
            return GuardDecision(
                allowed=False,
                reason=f"state_change_required_for_{proposal.category.lower()}",
            )

        return GuardDecision(allowed=True)

    return guard
