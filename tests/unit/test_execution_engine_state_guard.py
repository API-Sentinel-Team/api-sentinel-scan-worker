import pytest

from sentinel_core.modules.business_logic.active_tests import build_active_business_logic_templates
from sentinel_worker.modules.test_executor.execution_engine import ExecutionEngine
from sentinel_core.modules.test_executor.state_change_guard import StateChangeBlocked, StateChangeGuard
from sentinel_core.modules.test_executor.target_guard import TargetGuard


def test_destructive_methods_require_profile_and_template_opt_in():
    engine = ExecutionEngine(
        allow_state_change=True,
        allow_destructive_methods=False,
    )

    assert engine._effective_allow_state_change({"allow_state_change": True}) is True
    assert engine._effective_allow_destructive_methods({"allow_destructive_methods": True}) is False

    fully_enabled = ExecutionEngine(
        allow_state_change=True,
        allow_destructive_methods=True,
    )
    assert fully_enabled._effective_allow_destructive_methods({"allow_destructive_methods": True}) is True
    assert fully_enabled._effective_allow_destructive_methods({"allow_destructive_methods": False}) is False


def test_state_change_guard_blocks_delete_without_destructive_arming():
    guard = StateChangeGuard(allow_state_change=True, allow_destructive_methods=False)

    with pytest.raises(StateChangeBlocked, match="destructive_method_blocked"):
        guard.validate_request({"method": "DELETE", "headers": {}})


def test_state_change_guard_blocks_post_without_state_change_arming():
    guard = StateChangeGuard(allow_state_change=False, allow_destructive_methods=False)

    with pytest.raises(StateChangeBlocked, match="state_change_blocked"):
        guard.validate_request({"method": "POST", "headers": {}})


def test_template_request_budget_cannot_exceed_profile_budget():
    engine = ExecutionEngine(max_active_requests_per_test=5)

    assert engine._effective_max_active_requests({"max_active_requests_per_test": 2}) == 2
    assert engine._effective_max_active_requests({"max_active_requests_per_test": 50}) == 5
    assert engine._effective_max_active_requests({}) == 5


def test_execution_engine_state_policy_preserves_redacted_block_reason():
    engine = ExecutionEngine()
    guard = StateChangeGuard(allow_state_change=True, allow_destructive_methods=False)

    policy = engine._state_change_policy_for_request(
        {
            "method": "GET",
            "headers": {"X-HTTP-Method-Override": "DELETE"},
        },
        guard,
        reason="destructive_method_blocked: DELETE token=raw-token",
    )

    assert policy["blocked"] is True
    assert policy["effective_method"] == "DELETE"
    assert policy["destructive_method"] is True
    assert policy["reason"] == "destructive_method_blocked: DELETE token=****"
    assert "raw-token" not in str(policy)


def test_execution_engine_state_policy_marks_blocked_post_as_destructive():
    engine = ExecutionEngine()
    guard = StateChangeGuard(allow_state_change=False, allow_destructive_methods=False)

    policy = engine._state_change_policy_for_request(
        {"method": "POST"},
        guard,
        reason="state_change_blocked: POST requires pentest profile allow_state_change=true",
    )

    assert policy["blocked"] is True
    assert policy["effective_method"] == "POST"
    assert policy["safe_method"] is False
    assert policy["destructive_method"] is True
    assert policy["allow_state_change"] is False
    assert policy["allow_destructive_methods"] is False


class _BusinessLogicResponse:
    status_code = 200
    headers = {"content-type": "application/json"}
    text = '{"accepted": true, "order_id": "raw-order"}'


class _BusinessLogicClient:
    calls = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, **kwargs):
        self.calls.append(kwargs)
        return _BusinessLogicResponse()


@pytest.mark.asyncio
async def test_execution_engine_propagates_active_business_logic_scenario_without_values(monkeypatch):
    endpoint = {
        "id": "reports-export",
        "account_id": 1000000,
        "method": "GET",
        "protocol": "https",
        "host": "api.example.com",
        "path": "/reports/export?token=raw-token",
        "url": "https://api.example.com/reports/export?token=raw-token",
        "private_variable_count": 1,
    }
    template = build_active_business_logic_templates([endpoint], test_intensity="safe")[0]
    _BusinessLogicClient.calls = []
    monkeypatch.setattr(
        "sentinel_worker.modules.test_executor.execution_engine.TargetGuard.from_settings",
        staticmethod(lambda: TargetGuard(allowlist=["api.example.com"], allow_private_targets=False)),
    )
    monkeypatch.setattr("sentinel_worker.modules.test_executor.execution_engine.httpx.AsyncClient", _BusinessLogicClient)

    engine = ExecutionEngine(
        allow_state_change=True,
        max_active_requests_per_test=2,
    )

    async def fake_baseline(*args, **kwargs):
        return {"status_code": 200, "headers": {}, "body": "{}"}

    engine.baseliner.capture = fake_baseline

    result = await engine.execute_test(endpoint, template)

    assert result["is_vulnerable"] is True
    assert result["security_category"] == "business_logic"
    assert result["active_business_logic"]["scenario_type"] == (
        template["active_business_logic"]["scenario_type"]
    )
    assert result["active_business_logic"]["abuse_family"] == (
        template["active_business_logic"]["abuse_family"]
    )
    assert result["active_business_logic"]["safe_throttle"]["max_requests"] == 1
    assert result["matched_rule"] == {
        "template_id": template["id"],
        "rule_id": template["active_business_logic"]["scenario_type"],
        "name": "Active business logic scenario accepted by target",
        "matcher": "business_logic_response_code",
        "condition": "scenario_response_code_matched",
    }
    assert result["similarity"] == {
        "scenario_type": template["active_business_logic"]["scenario_type"],
        "abuse_family": template["active_business_logic"]["abuse_family"],
        "confidence_score": 0.75,
    }
    assert "raw-" not in str(result["active_business_logic"])
