import pytest

from sentinel_worker.modules.business_logic.stateful_executor import (
    StatefulFlowError,
    execute_stateful_flow,
    normalize_stateful_flow_steps,
)


@pytest.mark.asyncio
async def test_stateful_flow_runs_setup_mutation_and_reverse_cleanup():
    calls = []

    async def execute(step):
        calls.append(step.name)

    result = await execute_stateful_flow(
        [
            {"name": "create", "phase": "setup"},
            {"name": "mutate", "phase": "mutation"},
            {"name": "delete_child", "phase": "cleanup"},
            {"name": "delete_parent", "phase": "cleanup"},
        ],
        execute,
    )

    assert result.status == "completed"
    assert result.cleanup_attempted is True
    assert calls == ["create", "mutate", "delete_parent", "delete_child"]


@pytest.mark.asyncio
async def test_stateful_flow_attempts_cleanup_after_mutation_failure():
    calls = []

    async def execute(step):
        calls.append(step.name)
        if step.name == "mutate":
            raise RuntimeError("mutation rejected")

    result = await execute_stateful_flow(
        [
            {"name": "setup", "phase": "setup"},
            {"name": "mutate", "phase": "mutation"},
            {"name": "cleanup", "phase": "cleanup"},
        ],
        execute,
    )

    assert result.status == "failed"
    assert result.error == "mutation rejected"
    assert result.cleanup_attempted is True
    assert calls == ["setup", "mutate", "cleanup"]


def test_stateful_flow_rejects_unordered_or_unbounded_steps():
    with pytest.raises(StatefulFlowError, match="ordered"):
        # Cleanup cannot precede the mutation phase.
        normalize_stateful_flow_steps(
            [
                {"name": "cleanup", "phase": "cleanup"},
                {"name": "mutate", "phase": "mutation"},
            ]
        )
