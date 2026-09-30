"""Runtime auth material resolution for each auth_mode.

RBAC (server/modules/auth/rbac.py) only accepts an Authorization header that
starts with "bearer ", so every mode that carries a token must emit the scheme
prefix — otherwise scans run unauthenticated and silently report a clean result.
"""
import types

import pytest

from sentinel_worker.modules.test_executor.execution_engine import ExecutionEngine


def _profile(**kwargs):
    defaults = {
        "id": "profile-1",
        "auth_mode": "header",
        "header_name": None,
        "header_value": None,
        "token": None,
        "username": None,
        "password": None,
        "cookie_name": None,
        "cookie_value": None,
        "cookies": [],
        "static_headers": {},
    }
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


@pytest.mark.asyncio
async def test_bearer_mode_emits_bearer_scheme_prefix():
    engine = ExecutionEngine(auth_profile=_profile(auth_mode="bearer", token="jwt-token-value"))

    resolved = await engine._resolve_runtime_auth({"host": "api.example.com", "path": "/v1/me"})

    assert resolved["headers"]["Authorization"] == "Bearer jwt-token-value"


@pytest.mark.asyncio
async def test_bearer_mode_does_not_double_prefix_existing_scheme():
    engine = ExecutionEngine(auth_profile=_profile(auth_mode="bearer", token="Bearer jwt-token-value"))

    resolved = await engine._resolve_runtime_auth({"host": "api.example.com", "path": "/v1/me"})

    assert resolved["headers"]["Authorization"] == "Bearer jwt-token-value"


@pytest.mark.asyncio
async def test_header_mode_sends_raw_value_without_bearer_prefix():
    """Custom-header auth must stay verbatim — it is not a bearer token."""
    engine = ExecutionEngine(
        auth_profile=_profile(auth_mode="header", header_name="X-API-Key", header_value="raw-key")
    )

    resolved = await engine._resolve_runtime_auth({"host": "api.example.com", "path": "/v1/me"})

    assert resolved["headers"]["X-API-Key"] == "raw-key"
