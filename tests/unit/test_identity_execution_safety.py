import pytest

from sentinel_core.modules.identity.bola_validator import BOLAValidator
from sentinel_worker.modules.identity.login_flow_executor import LoginFlowExecutor
from sentinel_core.modules.test_executor.target_guard import TargetGuard, TargetGuardError


class _AuthFlowResponse:
    status_code = 200
    headers = {"content-type": "application/json"}
    text = '{"token":"runtime-token"}'


class _AuthFlowClient:
    calls = []
    init_kwargs = []

    def __init__(self, *args, **kwargs):
        self.init_kwargs.append(kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, **kwargs):
        self.calls.append(kwargs)
        return _AuthFlowResponse()


class _BolaReplayResponse:
    status_code = 200
    headers = {"content-type": "application/json"}
    text = '{"id":42,"email":"victim@example.com"}'


class _BolaReplayClient:
    calls = []
    init_kwargs = []

    def __init__(self, *args, **kwargs):
        self.init_kwargs.append(kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, **kwargs):
        self.calls.append(kwargs)
        return _BolaReplayResponse()


@pytest.mark.asyncio
async def test_login_flow_executor_verifies_tls_and_uses_target_guard(monkeypatch):
    _AuthFlowClient.calls = []
    _AuthFlowClient.init_kwargs = []
    monkeypatch.setattr("sentinel_worker.modules.identity.login_flow_executor.httpx.AsyncClient", _AuthFlowClient)

    tokens = await LoginFlowExecutor(
        target_guard=TargetGuard(allowlist=["auth.example.com"], allow_private_targets=False)
    ).execute_login(
        {
            "steps": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://auth.example.com/login",
                        "headers": {"content-type": "application/json"},
                        "body": '{"username":"{{username}}","password":"{{password}}"}',
                    }
                }
            ]
        },
        {"username": "alice", "password": "wonderland"},
    )

    assert tokens == {}
    assert _AuthFlowClient.init_kwargs[0]["verify"] is True
    assert _AuthFlowClient.calls[0]["url"] == "https://auth.example.com/login"


@pytest.mark.asyncio
async def test_login_flow_executor_blocks_metadata_target_before_request(monkeypatch):
    _AuthFlowClient.calls = []
    _AuthFlowClient.init_kwargs = []
    monkeypatch.setattr("sentinel_worker.modules.identity.login_flow_executor.httpx.AsyncClient", _AuthFlowClient)

    with pytest.raises(TargetGuardError, match="metadata"):
        await LoginFlowExecutor(
            target_guard=TargetGuard(allow_private_targets=False)
        ).execute_login(
            {
                "steps": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "http://169.254.169.254/latest/meta-data",
                        }
                    }
                ]
            },
            {},
        )

    assert _AuthFlowClient.calls == []


@pytest.mark.asyncio
async def test_bola_validator_verifies_tls_before_replay(monkeypatch):
    _BolaReplayClient.calls = []
    _BolaReplayClient.init_kwargs = []
    monkeypatch.setattr("sentinel_core.modules.identity.bola_validator.httpx.AsyncClient", _BolaReplayClient)

    result = await BOLAValidator(
        "Bearer attacker-token",
        target_guard=TargetGuard(allowlist=["api.example.com"], allow_private_targets=False),
    ).validate(
        {
            "method": "GET",
            "url": "https://api.example.com/users/42",
            "headers": {"Authorization": "Bearer victim-token"},
        },
        {"status_code": 200, "body": '{"id":42,"email":"victim@example.com"}'},
        {"response_code": {"eq": 200}},
    )

    assert _BolaReplayClient.init_kwargs[0]["verify"] is True
    assert _BolaReplayClient.calls[0]["headers"]["Authorization"] == "Bearer attacker-token"
    assert result["attacker_status_code"] == 200


@pytest.mark.asyncio
async def test_bola_validator_blocks_target_guard_before_replay(monkeypatch):
    _BolaReplayClient.calls = []
    monkeypatch.setattr("sentinel_core.modules.identity.bola_validator.httpx.AsyncClient", _BolaReplayClient)

    result = await BOLAValidator(
        "Bearer attacker-token",
        target_guard=TargetGuard(allow_private_targets=False),
    ).validate(
        {
            "method": "GET",
            "url": "http://169.254.169.254/latest/meta-data?token=raw-token",
            "headers": {"Authorization": "Bearer victim-token"},
        },
        {"status_code": 200, "body": "{}"},
        {"response_code": {"eq": 200}},
    )

    assert _BolaReplayClient.calls == []
    assert result["skip_reason"] == "target_guard"
    assert result["error"].startswith("target_guard_blocked:")
    assert result["target_guard_policy"]["policy"] == "target_guard"
    assert result["target_guard_policy"]["blocked"] is True
    assert result["target_guard_policy"]["url"] == (
        "http://169.254.169.254/latest/meta-data?token=****"
    )
    assert "metadata" in result["target_guard_policy"]["reason"]
    assert "raw-token" not in str(result["target_guard_policy"])


@pytest.mark.asyncio
async def test_bola_validator_blocks_state_change_before_replay(monkeypatch):
    _BolaReplayClient.calls = []
    monkeypatch.setattr("sentinel_core.modules.identity.bola_validator.httpx.AsyncClient", _BolaReplayClient)

    result = await BOLAValidator(
        "Bearer attacker-token",
        target_guard=TargetGuard(allowlist=["api.example.com"], allow_private_targets=False),
    ).validate(
        {
            "method": "DELETE",
            "url": "https://api.example.com/users/42",
            "headers": {"Authorization": "Bearer victim-token"},
        },
        {"status_code": 200, "body": "{}"},
        {"response_code": {"eq": 200}},
    )

    assert _BolaReplayClient.calls == []
    assert result["skip_reason"] == "state_change_guard"
    assert result["error"].startswith("state_change_blocked:")
    assert result["state_change_policy"] == {
        "policy": "state_change_guard",
        "blocked": True,
        "method": "DELETE",
        "effective_method": "DELETE",
        "safe_method": False,
        "destructive_method": True,
        "allow_state_change": False,
        "allow_destructive_methods": False,
        "reason": "state_change_blocked: DELETE requires pentest profile allow_state_change=true",
    }
