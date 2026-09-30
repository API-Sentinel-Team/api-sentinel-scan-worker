"""Tests for the high-level agentic orchestration entry point."""
from __future__ import annotations

from sentinel_worker.modules.agentic.knowledge_graph import KnowledgeGraph
from sentinel_worker.modules.agentic.llm_client import StubLLMClient
from sentinel_worker.modules.agentic.orchestration import run_agentic_assessment


_ENDPOINTS = [
    {"id": "ep1", "method": "GET", "path": "/users/{user_id}", "auth_types_found": ["bearer"], "parameters": [{"name": "user_id"}], "host": "api.example.com", "protocol": "https"},
]


class _DisabledSettings:
    AGENTIC_LLM_ENABLED = False


class _EnabledSettings:
    AGENTIC_LLM_ENABLED = True
    AGENTIC_LLM_MODEL = "stub"
    AGENTIC_LOOP_MAX_ROUNDS = 2
    PENTEST_TARGET_ALLOWLIST = "api.example.com"
    PENTEST_ALLOW_PRIVATE_TARGETS = True
    PENTEST_ENFORCE_TARGET_GUARD = True
    PENTEST_RESOLVE_TARGET_HOSTS = False
    PENTEST_FAIL_CLOSED_ON_TARGET_DNS_ERROR = True
    DEBUG = True


def test_disabled_by_default_returns_well_formed_empty():
    result = run_agentic_assessment(
        endpoints=_ENDPOINTS,
        executor=lambda p, e: {},
        judge=lambda r: {"confirmed": True},
        settings=_DisabledSettings(),
    )
    assert result["enabled"] is False
    assert result["reason"] == "agentic_llm_disabled"
    assert result["outcome"]["confirmed_count"] == 0
    # Graph is still built so the recon model accrues even when the LLM is off.
    assert len(result["graph"]["endpoints"]) == 1


def test_enabled_path_runs_loop_with_stub():
    stub = StubLLMClient({"proposals": [
        {"category": "BOLA", "endpoint_id": "ep1", "rationale": "private id", "priority": 0.9},
    ]})

    result = run_agentic_assessment(
        endpoints=_ENDPOINTS,
        executor=lambda p, e: {"severity": "HIGH"},
        judge=lambda r: {"confirmed": True, "severity": "HIGH", "exposed_fields": ["user_id"]},
        settings=_EnabledSettings(),
        llm_client=stub,
    )
    assert result["enabled"] is True
    assert result["outcome"]["confirmed_count"] == 1
    assert result["outcome"]["confirmed_findings"][0]["type"] == "BOLA"


def test_confirmed_findings_feed_back_into_graph():
    # Provide two endpoints: ep1 exposes user_id (via finding), ep2 consumes it.
    endpoints = [
        {"id": "ep1", "method": "GET", "path": "/users", "host": "api.example.com", "protocol": "https"},
        {"id": "ep2", "method": "GET", "path": "/users/{user_id}", "parameters": [{"name": "user_id"}], "host": "api.example.com", "protocol": "https"},
    ]
    stub = StubLLMClient({"proposals": [
        {"category": "EXCESSIVE_DATA_EXPOSURE", "endpoint_id": "ep1", "rationale": "leaks ids", "priority": 0.9},
    ]})
    result = run_agentic_assessment(
        endpoints=endpoints,
        executor=lambda p, e: {"severity": "HIGH"},
        judge=lambda r: {"confirmed": True, "severity": "HIGH", "exposed_fields": ["user_id"]},
        settings=_EnabledSettings(),
        llm_client=stub,
    )
    # The confirmed finding made ep1 an exposer of user_id; ep2 consumes it ->
    # a chain now exists in the returned graph.
    chains = result["graph"]["chains"]
    assert any(c["source_endpoint_id"] == "ep1" and c["id_kind"] == "user_id" for c in chains)


def test_existing_graph_is_merged():
    prior = KnowledgeGraph()
    prior.add_endpoint({"id": "old", "method": "GET", "path": "/legacy", "host": "api.example.com"})
    result = run_agentic_assessment(
        endpoints=_ENDPOINTS,
        executor=lambda p, e: {},
        judge=lambda r: {"confirmed": False},
        settings=_DisabledSettings(),
        existing_graph=prior,
    )
    paths = {e["path"] for e in result["graph"]["endpoints"]}
    assert "/legacy" in paths
    assert "/users/{id}" in paths


# ── run_agentic_scan_async: deterministic detectors run without LLM ───────────

class _DisabledSettingsWithAllow:
    AGENTIC_LLM_ENABLED = False
    PENTEST_TARGET_ALLOWLIST = ""
    PENTEST_ALLOW_PRIVATE_TARGETS = True
    PENTEST_ENFORCE_TARGET_GUARD = True
    PENTEST_RESOLVE_TARGET_HOSTS = False
    PENTEST_FAIL_CLOSED_ON_TARGET_DNS_ERROR = True
    DEBUG = True


async def test_async_scan_disabled_llm_returns_chain_and_detector_keys():
    """chain_findings and detector_findings must be present even when AGENTIC_LLM_ENABLED=False."""
    from sentinel_worker.modules.agentic.orchestration import run_agentic_scan_async

    class _FakeEngine:
        async def execute_test(self, endpoint, template, **_):
            return {"is_vulnerable": False}

    result = await run_agentic_scan_async(
        engine=_FakeEngine(),
        endpoints=_ENDPOINTS,
        templates=[],
        settings=_DisabledSettingsWithAllow(),
    )
    assert result["enabled"] is False
    assert "chain_findings" in result, "chain_findings key missing in disabled-LLM path"
    assert "detector_findings" in result, "detector_findings key missing in disabled-LLM path"
    assert isinstance(result["chain_findings"], list)
    assert isinstance(result["detector_findings"], list)
