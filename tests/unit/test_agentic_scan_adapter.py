"""Tests for the agentic scan adapter and the async loop wired to a fake engine."""
from __future__ import annotations

import pytest

from sentinel_worker.modules.agentic.scan_adapter import (
    build_template_index,
    make_async_scan_executor,
    scan_judge,
    templates_for_category,
)
from sentinel_worker.modules.agentic.strategist import TestProposal as Proposal
from sentinel_worker.modules.agentic.orchestration import run_agentic_scan_async


def _templates():
    return [
        {"id": "BOLA_1", "info": {"category": {"shortName": "BOLA"}, "severity": "HIGH"}},
        {"id": "SQLI_1", "info": {"category": {"shortName": "Command Injection"}, "severity": "HIGH"}},
        {"id": "MISC_1", "info": {"category": {"shortName": "Misconfiguration"}, "severity": "LOW"}},
    ]


def test_template_index_groups_by_short_name():
    index = build_template_index(_templates())
    assert "BOLA" in index
    assert "Command Injection" in index
    assert len(index["BOLA"]) == 1


def test_templates_for_category_maps_injection_to_command_injection():
    index = build_template_index(_templates())
    matches = templates_for_category("INJECTION", index)
    assert any(t["id"] == "SQLI_1" for t in matches)


def test_templates_for_category_unknown_returns_empty():
    index = build_template_index(_templates())
    assert templates_for_category("NONSENSE", index) == []


def test_scan_judge_trusts_engine_vulnerability_signal():
    assert scan_judge({"is_vulnerable": True, "severity": "HIGH"})["confirmed"] is True
    assert scan_judge({"is_vulnerable": False})["confirmed"] is False
    assert scan_judge({"is_vulnerable": True})["confidence"] == "HIGH"


class _FakeEngine:
    """Async engine stand-in: marks injection (SQLI) templates vulnerable, others not.

    Uses a NON-authorization category because BOLA/BFLA are confirmed only by
    multi-identity replay (never the template path), so the template-execution
    path must be exercised with a template category like INJECTION.
    """

    def __init__(self):
        self.calls = []

    async def execute_test(self, endpoint, template, selection_context=None):
        self.calls.append((endpoint["id"], template["id"]))
        vulnerable = template["id"].startswith("SQLI")
        return {
            "is_vulnerable": vulnerable,
            "severity": "HIGH" if vulnerable else "INFO",
            "template_id": template["id"],
            "evidence": "fake" if vulnerable else None,
        }


@pytest.mark.asyncio
async def test_async_executor_returns_first_vulnerable():
    engine = _FakeEngine()
    executor = make_async_scan_executor(engine=engine, templates=_templates())
    ep = {"id": "ep1", "method": "GET", "path": "/users/{id}", "host": "api.example.com", "protocol": "https"}
    # INJECTION maps to the Command Injection template (SQLI_1) the fake marks vulnerable.
    result = await executor(Proposal("INJECTION", "ep1", "r"), ep)
    assert result["is_vulnerable"] is True


@pytest.mark.asyncio
async def test_async_executor_no_template_for_category():
    engine = _FakeEngine()
    executor = make_async_scan_executor(engine=engine, templates=_templates())
    ep = {"id": "ep1", "method": "GET", "path": "/x", "host": "api.example.com", "protocol": "https"}
    result = await executor(Proposal("RATE_LIMIT", "ep1", "r"), ep)
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "no_template_for_category"
    assert engine.calls == []  # nothing executed when no matching template


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


class _DisabledSettings:
    AGENTIC_LLM_ENABLED = False


@pytest.mark.asyncio
async def test_run_agentic_scan_async_disabled_is_noop():
    engine = _FakeEngine()
    result = await run_agentic_scan_async(
        engine=engine,
        endpoints=[{"id": "ep1", "method": "GET", "path": "/users/{id}", "host": "api.example.com", "protocol": "https"}],
        templates=_templates(),
        settings=_DisabledSettings(),
    )
    assert result["enabled"] is False
    assert engine.calls == []  # disabled -> engine never touched


@pytest.mark.asyncio
async def test_run_agentic_scan_async_enabled_confirms_via_real_engine_path():
    from sentinel_worker.modules.agentic.llm_client import StubLLMClient

    engine = _FakeEngine()
    # INJECTION is a template-confirmed category (BOLA/BFLA are replay-only and
    # would need live identities), so it exercises the real engine path here.
    stub = StubLLMClient({"proposals": [
        {"category": "INJECTION", "endpoint_id": "ep1", "rationale": "user-controlled param", "priority": 0.9},
    ]})
    result = await run_agentic_scan_async(
        engine=engine,
        endpoints=[{"id": "ep1", "method": "GET", "path": "/search", "auth_types_found": ["bearer"], "host": "api.example.com", "protocol": "https"}],
        templates=_templates(),
        settings=_EnabledSettings(),
        llm_client=stub,
        allow_state_change=True,  # INJECTION is a state-changing test category
    )
    assert result["enabled"] is True
    assert result["outcome"]["confirmed_count"] == 1
    # The real engine WAS exercised through the adapter (the injection template ran).
    assert any(tid == "SQLI_1" for _, tid in engine.calls)
