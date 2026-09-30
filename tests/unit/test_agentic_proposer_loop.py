"""Tests for the agentic proposer-confirmer layer.

The central guarantee under test: the LLM only PROPOSES; deterministic guards and
the judge DISPOSE. Malicious / malformed proposals must be dropped, never
executed, and the loop must converge.
"""
from __future__ import annotations

from sentinel_worker.modules.agentic.guard_adapter import make_guard
from sentinel_worker.modules.agentic.llm_client import (
    StubLLMClient,
    _safe_json,
    build_llm_client,
)
from sentinel_worker.modules.agentic.proposer_loop import GuardDecision, run_proposer_confirmer
from sentinel_worker.modules.agentic.strategist import (
    ALLOWED_CATEGORIES,
    build_strategy,
)
from sentinel_core.modules.test_executor.target_guard import TargetGuard


_ENDPOINTS = [
    {"id": "ep1", "method": "GET", "path": "/users/v1/{username}", "auth_types_found": ["bearer"], "private_variable_count": 1, "host": "api.example.com", "protocol": "https"},
    {"id": "ep2", "method": "DELETE", "path": "/users/v1/{username}", "auth_types_found": ["bearer"], "private_variable_count": 1, "host": "api.example.com", "protocol": "https"},
]

# Bare endpoints (no auth/private-id signals) so the deterministic guaranteed-BOLA
# does not fire — used by loop-mechanics tests that assert exact proposal counts.
_BARE_ENDPOINTS = [
    {"id": "ep1", "method": "GET", "path": "/a", "host": "api.example.com", "protocol": "https"},
    {"id": "ep2", "method": "GET", "path": "/b", "host": "api.example.com", "protocol": "https"},
]


# ── strategist validation ────────────────────────────────────────────────────

def test_strategist_accepts_valid_proposal():
    llm = StubLLMClient({"proposals": [
        {"category": "BOLA", "endpoint_id": "ep1", "rationale": "private id + auth", "intensity": 2, "priority": 0.9},
    ]})
    plan = build_strategy(llm_client=llm, endpoints=_ENDPOINTS, guarantee_authorization_tests=False)
    assert len(plan.proposals) == 1
    assert plan.proposals[0].category == "BOLA"
    assert plan.proposals[0].endpoint_id == "ep1"
    assert plan.dropped == []


def test_strategist_drops_invented_endpoint():
    # The LLM tries to target an endpoint not in scope -> dropped, not executed.
    llm = StubLLMClient({"proposals": [
        {"category": "BOLA", "endpoint_id": "evil-endpoint", "rationale": "x"},
    ]})
    plan = build_strategy(llm_client=llm, endpoints=_ENDPOINTS, guarantee_authorization_tests=False)
    assert plan.proposals == []
    assert plan.dropped[0]["reason"] == "endpoint_not_in_scope"


def test_strategist_drops_disallowed_category():
    llm = StubLLMClient({"proposals": [
        {"category": "rm_-rf_/", "endpoint_id": "ep1", "rationale": "x"},
    ]})
    plan = build_strategy(llm_client=llm, endpoints=_ENDPOINTS, guarantee_authorization_tests=False)
    assert plan.proposals == []
    assert plan.dropped[0]["reason"] == "category_not_allowed"


def test_strategist_normalizes_natural_language_categories():
    # Real models say "authorization"/"IDOR"/"SQL injection", not the enum names.
    from sentinel_worker.modules.agentic.strategist import canonical_category

    assert canonical_category("authorization") == "BFLA"
    assert canonical_category("IDOR") == "BOLA"
    assert canonical_category("Broken Object Level Authorization") == "BOLA"
    assert canonical_category("SQL injection") == "INJECTION"
    assert canonical_category("business-logic") == "BUSINESS_LOGIC"
    assert canonical_category("BOLA") == "BOLA"  # canonical passes through
    assert canonical_category("nonsense-xyz") is None  # allowlist still hard boundary

    llm = StubLLMClient({"proposals": [
        {"category": "authorization", "endpoint_id": "ep1", "rationale": "x", "priority": 0.8},
        {"category": "IDOR", "endpoint_id": "ep2", "rationale": "y", "priority": 0.9},
    ]})
    plan = build_strategy(llm_client=llm, endpoints=_ENDPOINTS)
    cats = {p.category for p in plan.proposals}
    assert cats == {"BFLA", "BOLA"}
    assert plan.dropped == []


def test_strategist_clamps_intensity_and_priority():
    llm = StubLLMClient({"proposals": [
        {"category": "BOLA", "endpoint_id": "ep1", "rationale": "x", "intensity": 999, "priority": 5.0},
    ]})
    plan = build_strategy(llm_client=llm, endpoints=_ENDPOINTS, guarantee_authorization_tests=False)
    assert plan.proposals[0].intensity == 5  # clamped to max
    assert plan.proposals[0].priority == 1.0  # clamped to max


def test_strategist_guarantees_bola_on_private_id_auth_endpoint():
    # Even if the model proposes nothing, an authenticated endpoint with a private
    # identifier ALWAYS gets a deterministic BOLA proposal (reliable recall).
    llm = StubLLMClient({})  # model proposes nothing
    eps = [{"id": "ep1", "method": "GET", "path": "/users/{id}", "auth_types_found": ["bearer"], "private_variable_count": 1}]
    plan = build_strategy(llm_client=llm, endpoints=eps)
    assert any(p.category == "BOLA" and p.endpoint_id == "ep1" for p in plan.proposals)


def test_strategist_no_guaranteed_bola_without_auth_or_private_id():
    llm = StubLLMClient({})
    # No auth -> no guaranteed BOLA.
    eps = [{"id": "ep1", "method": "GET", "path": "/public", "auth_types_found": [], "private_variable_count": 0}]
    plan = build_strategy(llm_client=llm, endpoints=eps)
    assert plan.proposals == []


def test_strategist_guaranteed_bola_does_not_duplicate_model_proposal():
    llm = StubLLMClient({"proposals": [
        {"category": "BOLA", "endpoint_id": "ep1", "rationale": "model said so", "priority": 0.5},
    ]})
    eps = [{"id": "ep1", "method": "GET", "path": "/users/{id}", "auth_types_found": ["bearer"], "private_variable_count": 1}]
    plan = build_strategy(llm_client=llm, endpoints=eps)
    bola = [p for p in plan.proposals if p.category == "BOLA" and p.endpoint_id == "ep1"]
    assert len(bola) == 1  # not duplicated


def test_strategist_empty_on_garbage_model_output():
    assert build_strategy(llm_client=StubLLMClient({}), endpoints=_ENDPOINTS, guarantee_authorization_tests=False).proposals == []
    assert build_strategy(llm_client=StubLLMClient({"proposals": "nope"}), endpoints=_ENDPOINTS, guarantee_authorization_tests=False).proposals == []


def test_strategist_orders_by_priority_desc():
    llm = StubLLMClient({"proposals": [
        {"category": "BOLA", "endpoint_id": "ep1", "rationale": "low", "priority": 0.2},
        {"category": "BFLA", "endpoint_id": "ep2", "rationale": "high", "priority": 0.95},
    ]})
    plan = build_strategy(llm_client=llm, endpoints=_ENDPOINTS, guarantee_authorization_tests=False)
    assert [p.category for p in plan.proposals] == ["BFLA", "BOLA"]


# ── llm client ───────────────────────────────────────────────────────────────

def test_safe_json_handles_markdown_fence():
    assert _safe_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert _safe_json("not json") == {}
    assert _safe_json('[1,2,3]') == {}  # non-object JSON -> {}


def test_build_llm_client_returns_stub_when_disabled():
    class _S:
        AGENTIC_LLM_ENABLED = False
        AGENTIC_LLM_MODEL = ""
    assert build_llm_client(_S()).name == "stub"


def test_build_llm_client_returns_openai_compat_when_api_base_set():
    # An api_base (NVIDIA NIM, Ollama, vLLM, OpenAI) -> the httpx client.
    class _S:
        AGENTIC_LLM_ENABLED = True
        AGENTIC_LLM_MODEL = "meta/llama-3.3-70b-instruct"
        AGENTIC_LLM_API_BASE = "https://integrate.api.nvidia.com/v1"
        AGENTIC_LLM_API_KEY = "nvapi-xxx"
        AGENTIC_LLM_TIMEOUT_SECONDS = 10.0
    client = build_llm_client(_S())
    assert client.name == "openai_compat:meta/llama-3.3-70b-instruct"


def test_build_llm_client_falls_back_to_litellm_without_api_base():
    class _S:
        AGENTIC_LLM_ENABLED = True
        AGENTIC_LLM_MODEL = "gpt-4o-mini"
        AGENTIC_LLM_API_BASE = ""
        AGENTIC_LLM_API_KEY = "k"
        AGENTIC_LLM_TIMEOUT_SECONDS = 10.0
    client = build_llm_client(_S())
    assert client.name == "litellm:gpt-4o-mini"


def test_openai_compat_client_returns_empty_on_network_error():
    from sentinel_worker.modules.agentic.llm_client import OpenAICompatLLMClient

    # Unreachable base -> {} (degrades to "no proposal"), never raises.
    client = OpenAICompatLLMClient(
        model="m", api_base="http://127.0.0.1:1/v1", api_key="k", timeout=0.5
    )
    assert client.complete_json(system="s", user="u", schema_hint="{}") == {}


# ── full loop ────────────────────────────────────────────────────────────────

def _allow_all_guard(proposal, endpoint) -> GuardDecision:
    return GuardDecision(allowed=True)


def test_loop_confirms_only_what_judge_confirms():
    llm = StubLLMClient({"proposals": [
        {"category": "BOLA", "endpoint_id": "ep1", "rationale": "x", "priority": 0.9},
        {"category": "BFLA", "endpoint_id": "ep2", "rationale": "y", "priority": 0.8},
    ]})

    def executor(proposal, endpoint):
        return {"category": proposal.category, "severity": "HIGH"}

    def judge(result):
        # Only BOLA is "confirmed"; BFLA is rejected by the deterministic judge.
        if result["category"] == "BOLA":
            return {"confirmed": True, "severity": "HIGH", "confidence": "HIGH"}
        return {"confirmed": False}

    outcome = run_proposer_confirmer(
        llm_client=llm, endpoints=_BARE_ENDPOINTS,
        guard=_allow_all_guard, executor=executor, judge=judge, max_rounds=2,
    )
    assert outcome.proposed == 2
    assert outcome.executed == 2
    assert len(outcome.confirmed_findings) == 1
    assert outcome.confirmed_findings[0]["type"] == "BOLA"
    assert outcome.unconfirmed == 1


def test_loop_never_executes_guard_blocked_proposal():
    llm = StubLLMClient({"proposals": [
        {"category": "BOLA", "endpoint_id": "ep1", "rationale": "x", "priority": 0.9},
    ]})
    executed = {"count": 0}

    def blocking_guard(proposal, endpoint):
        return GuardDecision(allowed=False, reason="target_guard: blocked")

    def executor(proposal, endpoint):
        executed["count"] += 1
        return {}

    outcome = run_proposer_confirmer(
        llm_client=llm, endpoints=_BARE_ENDPOINTS,
        guard=blocking_guard, executor=executor,
        judge=lambda r: {"confirmed": True}, max_rounds=1,
    )
    assert executed["count"] == 0  # guard prevented execution
    assert outcome.executed == 0
    assert len(outcome.guard_blocked) == 1
    assert outcome.confirmed_findings == []


def test_loop_converges_without_infinite_rounds():
    # Stub always proposes the same thing; loop must dedup and stop.
    llm = StubLLMClient({"proposals": [
        {"category": "BOLA", "endpoint_id": "ep1", "rationale": "x", "priority": 0.9},
    ]})
    outcome = run_proposer_confirmer(
        llm_client=llm, endpoints=_BARE_ENDPOINTS,
        guard=_allow_all_guard,
        executor=lambda p, e: {"severity": "LOW"},
        judge=lambda r: {"confirmed": False},
        max_rounds=10,
    )
    # One unique proposal -> proposed exactly once despite max_rounds=10.
    assert outcome.proposed == 1
    assert outcome.rounds <= 2


# ── real guard adapter (reuses platform TargetGuard + StateChangeGuard) ───────

def test_guard_adapter_blocks_out_of_scope_host():
    # Allowlist only api.example.com; a proposal on another host is blocked by the
    # SAME TargetGuard the deterministic engine uses.
    tguard = TargetGuard(allowlist=["api.example.com"], enforce=True)
    guard = make_guard(target_guard=tguard)
    from sentinel_worker.modules.agentic.strategist import TestProposal

    off_scope_ep = {"id": "x", "method": "GET", "path": "/", "host": "evil.com", "protocol": "https"}
    decision = guard(TestProposal("BOLA", "x", "r"), off_scope_ep)
    assert decision.allowed is False
    assert "target_guard" in decision.reason


def test_guard_adapter_blocks_state_change_when_not_armed():
    tguard = TargetGuard(allowlist=["api.example.com"], enforce=True)
    guard = make_guard(target_guard=tguard, allow_state_change=False)
    from sentinel_worker.modules.agentic.strategist import TestProposal

    delete_ep = {"id": "ep2", "method": "DELETE", "path": "/users/v1/{username}", "host": "api.example.com", "protocol": "https"}
    decision = guard(TestProposal("BFLA", "ep2", "r"), delete_ep)
    assert decision.allowed is False
    assert "state_change_guard" in decision.reason


def test_guard_adapter_allows_safe_in_scope_get():
    tguard = TargetGuard(allowlist=["api.example.com"], enforce=True)
    guard = make_guard(target_guard=tguard)
    from sentinel_worker.modules.agentic.strategist import TestProposal

    get_ep = {"id": "ep1", "method": "GET", "path": "/users/v1/{username}", "host": "api.example.com", "protocol": "https"}
    assert guard(TestProposal("BOLA", "ep1", "r"), get_ep).allowed is True


def test_allowed_categories_are_uppercase_and_nonempty():
    assert ALLOWED_CATEGORIES
    assert all(c == c.upper() for c in ALLOWED_CATEGORIES)
