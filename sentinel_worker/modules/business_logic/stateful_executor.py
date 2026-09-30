"""Bounded, cleanup-safe orchestration for stateful business-logic probes.

The HTTP transport remains owned by the test execution engine.  This module
owns the lifecycle contract: setup must complete before mutation, invariants
are evaluated at phase boundaries, and cleanup is attempted even when a
mutation or invariant fails.  Keeping that policy separate makes it usable by
template, replay, and future state-machine executors without duplicating the
safety rules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable


class StatefulFlowError(RuntimeError):
    """Raised when a stateful flow is malformed or exceeds its safety budget."""


@dataclass(frozen=True)
class StatefulFlowStep:
    """A single bounded step in a setup/mutation/cleanup flow."""

    name: str
    phase: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class StatefulFlowResult:
    """Redacted lifecycle metadata; response bodies are never stored here."""

    status: str
    completed_phases: list[str] = field(default_factory=list)
    executed_steps: list[str] = field(default_factory=list)
    cleanup_attempted: bool = False
    cleanup_errors: list[str] = field(default_factory=list)
    invariant_failures: list[str] = field(default_factory=list)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "completed_phases": list(self.completed_phases),
            "executed_steps": list(self.executed_steps),
            "cleanup_attempted": self.cleanup_attempted,
            "cleanup_errors": list(self.cleanup_errors),
            "invariant_failures": list(self.invariant_failures),
            **({"error": self.error} if self.error else {}),
        }


ExecuteStep = Callable[[StatefulFlowStep], Awaitable[Any]]
CheckInvariant = Callable[[str, Any], Awaitable[bool] | bool]

_PHASE_ORDER = ("setup", "mutation", "cleanup")


def normalize_stateful_flow_steps(raw_steps: Iterable[dict[str, Any] | StatefulFlowStep]) -> list[StatefulFlowStep]:
    """Validate and normalize a flow while rejecting ambiguous phase order."""
    steps: list[StatefulFlowStep] = []
    for index, raw in enumerate(raw_steps or []):
        if isinstance(raw, StatefulFlowStep):
            step = raw
        elif isinstance(raw, dict):
            name = str(raw.get("name") or f"step_{index}").strip()
            phase = str(raw.get("phase") or "").strip().lower()
            payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else raw
            step = StatefulFlowStep(name=name, phase=phase, payload=dict(payload))
        else:
            raise StatefulFlowError(f"invalid stateful flow step at index {index}")
        if not step.name or step.phase not in _PHASE_ORDER:
            raise StatefulFlowError(f"invalid stateful flow step {step.name or index}")
        steps.append(step)

    if not steps:
        raise StatefulFlowError("stateful flow requires at least one step")
    phase_indexes = [_PHASE_ORDER.index(step.phase) for step in steps]
    if phase_indexes != sorted(phase_indexes):
        raise StatefulFlowError("stateful flow phases must be ordered setup, mutation, cleanup")
    if "mutation" not in {step.phase for step in steps}:
        raise StatefulFlowError("stateful flow requires a mutation phase")
    return steps


async def execute_stateful_flow(
    steps: Iterable[dict[str, Any] | StatefulFlowStep],
    execute_step: ExecuteStep,
    *,
    check_invariant: CheckInvariant | None = None,
    max_steps: int = 8,
) -> StatefulFlowResult:
    """Execute a bounded flow and always attempt cleanup.

    Cleanup steps are run in reverse order.  A failed setup or mutation stops
    forward execution, while cleanup remains best-effort and is reflected in
    the returned lifecycle evidence.  The caller decides how HTTP responses
    map to findings; this function only enforces lifecycle safety.
    """
    normalized = normalize_stateful_flow_steps(steps)
    if max_steps <= 0 or len(normalized) > max_steps:
        raise StatefulFlowError("stateful flow exceeds the configured step budget")

    result = StatefulFlowResult(status="running")
    forward_steps = [step for step in normalized if step.phase != "cleanup"]
    cleanup_steps = [step for step in normalized if step.phase == "cleanup"]
    current_phase: str | None = None
    try:
        for step in forward_steps:
            if step.phase != current_phase:
                current_phase = step.phase
                if check_invariant is not None and result.executed_steps:
                    passed = check_invariant(current_phase, None)
                    if hasattr(passed, "__await__"):
                        passed = await passed
                    if not passed:
                        result.invariant_failures.append(current_phase)
                        raise StatefulFlowError(f"invariant failed before {current_phase}")
                result.completed_phases.append(current_phase)
            await execute_step(step)
            result.executed_steps.append(step.name)
        if check_invariant is not None:
            passed = check_invariant("mutation", None)
            if hasattr(passed, "__await__"):
                passed = await passed
            if not passed:
                result.invariant_failures.append("mutation")
                raise StatefulFlowError("invariant failed after mutation")
        result.status = "completed"
    except Exception as exc:
        result.status = "failed"
        result.error = str(exc)
    finally:
        if cleanup_steps:
            result.cleanup_attempted = True
            for step in reversed(cleanup_steps):
                try:
                    await execute_step(step)
                    result.executed_steps.append(step.name)
                except Exception as exc:
                    result.cleanup_errors.append(str(exc))
            if result.status == "completed" and result.cleanup_errors:
                result.status = "cleanup_failed"
    return result
