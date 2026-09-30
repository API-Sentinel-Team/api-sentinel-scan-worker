"""Verify run_scan forwards configured TestAccounts into the agentic pass so
authenticated multi-identity BOLA/BFLA replay runs automatically (not just in
the manual demo)."""
from __future__ import annotations

import pytest

from sentinel_worker.modules.test_executor import run_executor


class _Endpoint:
    def __init__(self, id_):
        self.id = id_
        self.method = "GET"
        self.path = "/users/v1/x"
        self.host = "api.example.com"
        self.protocol = "https"
        self.auth_types_found = ["bearer"]
        self.private_variable_count = 1


class _Profile:
    allow_state_change = False
    allow_destructive_methods = False


@pytest.mark.asyncio
async def test_run_agentic_scan_pass_forwards_test_accounts(monkeypatch):
    captured = {}

    async def fake_run_agentic_scan_async(**kwargs):
        captured.update(kwargs)
        return {"enabled": True, "outcome": {"confirmed_findings": []}}

    # Patch the orchestration entry the helper imports lazily.
    import sentinel_worker.modules.agentic.orchestration as orch
    monkeypatch.setattr(orch, "run_agentic_scan_async", fake_run_agentic_scan_async)

    accounts = ["acct-a", "acct-b"]  # identity objects are opaque to this helper
    await run_executor._run_agentic_scan_pass(
        engine=object(),
        endpoints=[_Endpoint("ep1")],
        templates=[],
        account_id=1000000,
        pentest_profile=_Profile(),
        prior_findings=[{"type": "X", "endpoint_id": "ep1"}],
        test_accounts=accounts,
    )

    assert captured["test_accounts"] == accounts
    assert captured["prior_findings"] == [{"type": "X", "endpoint_id": "ep1"}]
    # endpoint ORM objects are translated to dicts for the agentic layer
    assert captured["endpoints"][0]["id"] == "ep1"
    assert captured["endpoints"][0]["method"] == "GET"
