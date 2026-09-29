"""LLM client abstraction for the agentic reasoning layer.

The agentic layer follows the North Star principle "deterministic core,
probabilistic edge": the LLM may *propose and prioritize*, but it never touches
the network and never decides what becomes a confirmed finding. This module is
the only place the LLM is reached, behind a narrow interface so the rest of the
agentic code is testable without a live model.

Three implementations:

- ``LiteLLMClient`` — production. Calls a self-hosted or hosted model via the
  ``litellm`` SDK (Ollama, OpenAI, Anthropic, etc.) using settings. Imported
  lazily so the dependency is optional.
- ``StubLLMClient`` — deterministic, no network. Returns a fixed/echoed
  response. Used in tests and as a safe default when no model is configured.
- ``build_llm_client`` — factory that returns LiteLLM when configured, else stub.
"""
from __future__ import annotations

import json
from typing import Any, Protocol


class LLMClient(Protocol):
    """Minimal contract the agentic layer depends on."""

    def complete_json(self, *, system: str, user: str, schema_hint: str) -> dict[str, Any]:
        """Return a parsed JSON object from the model.

        Implementations MUST return a dict (never raise on a malformed model
        reply — return ``{}`` instead) so the caller can treat a bad proposal as
        "no proposal" rather than crash a scan.
        """
        ...

    @property
    def name(self) -> str: ...


class StubLLMClient:
    """Deterministic LLM stand-in. Returns a preset response; no network.

    Used in tests and whenever no model endpoint is configured. The default
    response is an empty proposal so the agentic loop safely degrades to the
    deterministic selection path when there is no model.
    """

    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self._response = response if response is not None else {}

    def complete_json(self, *, system: str, user: str, schema_hint: str) -> dict[str, Any]:
        # Echo back the configured response; ignore inputs deterministically.
        return dict(self._response)

    @property
    def name(self) -> str:
        return "stub"


class LiteLLMClient:
    """Production client backed by the ``litellm`` SDK.

    Lazily imports litellm so the dependency stays optional. Always returns a
    dict — a malformed or non-JSON model reply becomes ``{}``.
    """

    def __init__(self, *, model: str, api_base: str = "", api_key: str = "", timeout: float = 30.0) -> None:
        self.model = model
        self.api_base = api_base or None
        self.api_key = api_key or None
        self.timeout = timeout

    def complete_json(self, *, system: str, user: str, schema_hint: str) -> dict[str, Any]:
        try:
            import litellm  # type: ignore
        except ImportError:
            return {}

        messages = [
            {"role": "system", "content": f"{system}\n\nReturn ONLY valid JSON matching: {schema_hint}"},
            {"role": "user", "content": user},
        ]
        try:
            resp = litellm.completion(
                model=self.model,
                messages=messages,
                api_base=self.api_base,
                api_key=self.api_key,
                timeout=self.timeout,
                response_format={"type": "json_object"},
            )
            content = resp["choices"][0]["message"]["content"]
        except Exception:
            return {}

        return _safe_json(content)

    @property
    def name(self) -> str:
        return f"litellm:{self.model}"


class OpenAICompatLLMClient:
    """Production client for any OpenAI-compatible /chat/completions endpoint.

    Talks directly over httpx (already a project dependency), so it works with
    NVIDIA NIM (integrate.api.nvidia.com), Ollama, vLLM, OpenAI, etc. without
    pulling in the heavy litellm SDK. Always returns a dict — a network error or
    malformed reply becomes ``{}`` so a bad model call degrades to "no proposal".
    """

    def __init__(
        self,
        *,
        model: str,
        api_base: str,
        api_key: str = "",
        timeout: float = 30.0,
    ) -> None:
        self.model = model
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def complete_json(self, *, system: str, user: str, schema_hint: str) -> dict[str, Any]:
        import httpx

        url = f"{self.api_base}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": f"{system}\n\nReturn ONLY valid JSON matching: {schema_hint}",
                },
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        try:
            resp = httpx.post(url, headers=headers, json=body, timeout=self.timeout)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
        except Exception:
            return {}
        return _safe_json(content)

    @property
    def name(self) -> str:
        return f"openai_compat:{self.model}"


def _safe_json(content: Any) -> dict[str, Any]:
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        return {}
    text = content.strip()
    # Tolerate models that wrap JSON in markdown fences.
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def build_llm_client(settings: Any = None) -> LLMClient:
    """Return a real LLM client when configured, else a safe stub.

    Preference: when an ``AGENTIC_LLM_API_BASE`` is set (NVIDIA NIM, Ollama,
    vLLM, OpenAI, etc.), use the dependency-light OpenAI-compatible httpx client.
    Falls back to LiteLLM only when a model is set without an api_base. Always
    returns a stub when disabled or unconfigured.
    """
    if settings is None:
        from server.config import settings as default_settings

        settings = default_settings

    model = (getattr(settings, "AGENTIC_LLM_MODEL", "") or "").strip()
    enabled = bool(getattr(settings, "AGENTIC_LLM_ENABLED", False))
    if not enabled or not model:
        return StubLLMClient()

    api_base = (getattr(settings, "AGENTIC_LLM_API_BASE", "") or "").strip()
    api_key = (getattr(settings, "AGENTIC_LLM_API_KEY", "") or "").strip()
    timeout = float(getattr(settings, "AGENTIC_LLM_TIMEOUT_SECONDS", 30.0))

    if api_base:
        return OpenAICompatLLMClient(
            model=model, api_base=api_base, api_key=api_key, timeout=timeout
        )

    return LiteLLMClient(model=model, api_base=api_base, api_key=api_key, timeout=timeout)
