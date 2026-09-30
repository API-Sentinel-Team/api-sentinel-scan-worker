"""Tests for the LLM client abstraction layer."""
import json
from unittest.mock import MagicMock

import pytest

from sentinel_worker.modules.agentic.llm_client import (
    OpenAICompatLLMClient,
    StubLLMClient,
    _safe_json,
    build_llm_client,
)


# ── _safe_json (pure) ─────────────────────────────────────────────────────────

def test_safe_json_parses_plain_json():
    assert _safe_json('{"key": "value"}') == {"key": "value"}


def test_safe_json_parses_markdown_fence():
    assert _safe_json('```json\n{"key": "value"}\n```') == {"key": "value"}


def test_safe_json_returns_empty_on_malformed():
    assert _safe_json("not json at all") == {}


def test_safe_json_returns_empty_on_list():
    assert _safe_json("[1, 2, 3]") == {}


def test_safe_json_passthrough_dict():
    assert _safe_json({"already": "parsed"}) == {"already": "parsed"}


# ── StubLLMClient ─────────────────────────────────────────────────────────────

def test_stub_returns_preset_response():
    client = StubLLMClient(response={"proposals": [{"type": "BOLA"}]})
    result = client.complete_json(system="sys", user="usr", schema_hint="{}")
    assert result == {"proposals": [{"type": "BOLA"}]}
    assert client.name == "stub"


def test_stub_returns_empty_dict_by_default():
    client = StubLLMClient()
    assert client.complete_json(system="sys", user="usr", schema_hint="{}") == {}


# ── OpenAICompatLLMClient ─────────────────────────────────────────────────────

def _mock_httpx_response(payload: dict) -> MagicMock:
    """Build a minimal fake httpx.Response returning ``payload`` from .json()."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": json.dumps(payload)}}]
    }
    mock_resp.raise_for_status.return_value = None
    return mock_resp


def test_openai_compat_happy_path_parses_proposal(monkeypatch):
    """Client correctly extracts and parses the JSON proposal from the model response."""
    expected = {"proposals": [{"type": "SQLI", "endpoint_id": "get-user", "priority": 8}]}

    import httpx
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: _mock_httpx_response(expected))

    client = OpenAICompatLLMClient(
        model="meta/llama-3.1-8b-instruct",
        api_base="https://integrate.api.nvidia.com/v1",
        api_key="nvapi-test",
    )
    result = client.complete_json(
        system="You are a red-team expert.",
        user="Analyze this endpoint.",
        schema_hint="{}",
    )

    assert result == expected
    assert client.name == "openai_compat:meta/llama-3.1-8b-instruct"


def test_openai_compat_network_error_returns_empty(monkeypatch):
    """Network errors degrade to {} so a bad model call never aborts a scan."""
    import httpx

    def raise_error(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", raise_error)

    client = OpenAICompatLLMClient(
        model="meta/llama-3.1-8b-instruct",
        api_base="https://integrate.api.nvidia.com/v1",
    )
    assert client.complete_json(system="sys", user="usr", schema_hint="{}") == {}


def test_openai_compat_malformed_content_returns_empty(monkeypatch):
    """A model that returns a non-JSON string is handled gracefully."""
    import httpx

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": "sorry I cannot help with that"}}]
    }
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: mock_resp)

    client = OpenAICompatLLMClient(
        model="meta/llama-3.1-8b-instruct",
        api_base="https://integrate.api.nvidia.com/v1",
    )
    assert client.complete_json(system="sys", user="usr", schema_hint="{}") == {}


def test_openai_compat_markdown_fenced_json_is_parsed(monkeypatch):
    """Models that wrap JSON in ```json fences are still parsed correctly."""
    import httpx

    inner = {"proposals": [{"type": "BOLA", "priority": 9}]}
    fenced = f"```json\n{json.dumps(inner)}\n```"

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"choices": [{"message": {"content": fenced}}]}
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: mock_resp)

    client = OpenAICompatLLMClient(
        model="meta/llama-3.1-8b-instruct",
        api_base="https://integrate.api.nvidia.com/v1",
    )
    assert client.complete_json(system="sys", user="usr", schema_hint="{}") == inner


def test_openai_compat_sends_bearer_token(monkeypatch):
    """Authorization header is sent when api_key is provided."""
    import httpx

    captured = {}

    def capture_post(url, *, headers, json, timeout):
        captured["headers"] = headers
        return _mock_httpx_response({"ok": True})

    monkeypatch.setattr(httpx, "post", capture_post)

    client = OpenAICompatLLMClient(
        model="test-model",
        api_base="https://example.com/v1",
        api_key="my-secret-key",
    )
    client.complete_json(system="sys", user="usr", schema_hint="{}")
    assert captured["headers"]["Authorization"] == "Bearer my-secret-key"


def test_openai_compat_no_auth_header_when_no_key(monkeypatch):
    """Authorization header is omitted when no api_key is given."""
    import httpx

    captured = {}

    def capture_post(url, *, headers, json, timeout):
        captured["headers"] = headers
        return _mock_httpx_response({})

    monkeypatch.setattr(httpx, "post", capture_post)

    client = OpenAICompatLLMClient(model="test-model", api_base="https://example.com/v1")
    client.complete_json(system="sys", user="usr", schema_hint="{}")
    assert "Authorization" not in captured["headers"]


def test_openai_compat_posts_to_correct_url(monkeypatch):
    """Completions URL is constructed as <api_base>/chat/completions."""
    import httpx

    captured = {}

    def capture_post(url, *, headers, json, timeout):
        captured["url"] = url
        return _mock_httpx_response({})

    monkeypatch.setattr(httpx, "post", capture_post)

    client = OpenAICompatLLMClient(
        model="test-model",
        api_base="https://example.com/v1/",  # trailing slash stripped
    )
    client.complete_json(system="sys", user="usr", schema_hint="{}")
    assert captured["url"] == "https://example.com/v1/chat/completions"


# ── build_llm_client ──────────────────────────────────────────────────────────

def test_build_llm_client_returns_stub_when_disabled():
    class FakeSettings:
        AGENTIC_LLM_ENABLED = False
        AGENTIC_LLM_MODEL = "test-model"

    assert isinstance(build_llm_client(FakeSettings()), StubLLMClient)


def test_build_llm_client_returns_stub_when_no_model():
    class FakeSettings:
        AGENTIC_LLM_ENABLED = True
        AGENTIC_LLM_MODEL = ""

    assert isinstance(build_llm_client(FakeSettings()), StubLLMClient)


def test_build_llm_client_returns_openai_compat_when_api_base_set():
    class FakeSettings:
        AGENTIC_LLM_ENABLED = True
        AGENTIC_LLM_MODEL = "meta/llama-3.1-8b-instruct"
        AGENTIC_LLM_API_BASE = "https://integrate.api.nvidia.com/v1"
        AGENTIC_LLM_API_KEY = "nvapi-test"
        AGENTIC_LLM_TIMEOUT_SECONDS = 30.0

    client = build_llm_client(FakeSettings())
    assert isinstance(client, OpenAICompatLLMClient)
    assert client.model == "meta/llama-3.1-8b-instruct"
