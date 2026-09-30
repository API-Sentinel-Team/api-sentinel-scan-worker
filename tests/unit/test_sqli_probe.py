"""Tests for the error-based and boolean-based SQL injection probes."""
from __future__ import annotations

import pytest

from sentinel_worker.modules.identity import sqli_probe as sp
from sentinel_worker.modules.identity.sqli_probe import (
    detect_boolean_based_sqli,
    detect_error_based_sqli,
    match_sql_error,
)
from sentinel_core.modules.test_executor.target_guard import TargetGuardError


_ENDPOINT = {
    "id": "get-user",
    "method": "GET",
    "path": "/users/v1/{username}",
    "host": "api.example.com",
    "protocol": "https",
}


class _AllowGuard:
    def validate_url(self, url, base_url=None):
        return None


class _BlockGuard:
    def validate_url(self, url, base_url=None):
        raise TargetGuardError("host is not in the pentest target allowlist")


# ── match_sql_error (pure) ────────────────────────────────────────────────────

def test_match_returns_signature_for_sqlite_error():
    body = 'sqlite3.OperationalError: near "\'": syntax error'
    assert match_sql_error(body, 200) == "sqlite3.OperationalError"


def test_match_returns_none_for_normal_json():
    assert match_sql_error('{"username":"alice","email":"a@x.com"}', 200) is None


def test_match_returns_signature_on_500_operationalerror():
    assert match_sql_error("Internal Server Error: OperationalError", 500) == "OperationalError"


# ── detect_error_based_sqli ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detect_flags_first_payload_sqli(monkeypatch):
    leaked_body = 'sqlite3.OperationalError: near "\'": syntax error'

    async def fake_http_get(url, headers, timeout):
        return {"status_code": 500, "headers": {}, "body": leaked_body, "url": url}

    monkeypatch.setattr(sp, "_http_get", fake_http_get)

    result = await detect_error_based_sqli(endpoint=_ENDPOINT, target_guard=_AllowGuard())

    assert result["is_vulnerable"] is True
    assert result["type"] == "SQLI"
    assert result["severity"] == "HIGH"
    assert result["evidence"]["matched_signature"] == "sqlite3.OperationalError"
    assert result["evidence"]["payload"]
    assert result["evidence"]["engine"] == "sqli_probe"
    assert result["evidence"]["status_code"] == 500
    # Raw response body must NOT leak into evidence.
    assert leaked_body not in str(result)


@pytest.mark.asyncio
async def test_detect_no_hit_returns_skip_reason(monkeypatch):
    async def fake_http_get(url, headers, timeout):
        return {"status_code": 200, "headers": {}, "body": '{"ok":true}', "url": url}

    monkeypatch.setattr(sp, "_http_get", fake_http_get)

    result = await detect_error_based_sqli(endpoint=_ENDPOINT, target_guard=_AllowGuard())

    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "no_sqli_signature"


@pytest.mark.asyncio
async def test_detect_target_guard_block_sends_no_traffic(monkeypatch):
    called = {"hits": 0}

    async def fake_http_get(url, headers, timeout):
        called["hits"] += 1
        return {"status_code": 200, "headers": {}, "body": "", "url": url}

    monkeypatch.setattr(sp, "_http_get", fake_http_get)

    result = await detect_error_based_sqli(endpoint=_ENDPOINT, target_guard=_BlockGuard())

    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "target_guard"
    assert called["hits"] == 0


# ── detect_boolean_based_sqli ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_boolean_sqli_detects_size_difference(monkeypatch):
    # Baseline and TRUE: return 200 with a medium-size body.
    # FALSE: return 200 with a very short body (empty result set).
    baseline_body = '{"users":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]}'
    true_body = baseline_body  # same data
    false_body = '{"users":[]}'  # empty — boolean-controlled

    call_count = {"n": 0}

    async def fake_http_get(url, headers, timeout):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return {"status_code": 200, "headers": {}, "body": baseline_body, "url": url}
        if call_count["n"] == 2:
            return {"status_code": 200, "headers": {}, "body": true_body, "url": url}
        return {"status_code": 200, "headers": {}, "body": false_body, "url": url}

    monkeypatch.setattr(sp, "_http_get", fake_http_get)

    result = await detect_boolean_based_sqli(endpoint=_ENDPOINT, target_guard=_AllowGuard())

    assert result["is_vulnerable"] is True
    assert result["type"] == "SQLI"
    assert result["evidence"]["sub_type"] == "boolean_based"
    assert result["evidence"]["size_delta_ratio"] >= 0.15


@pytest.mark.asyncio
async def test_boolean_sqli_no_finding_when_responses_similar(monkeypatch):
    # All responses return the same body → no boolean signal.
    async def fake_http_get(url, headers, timeout):
        return {"status_code": 200, "headers": {}, "body": '{"users":[{"id":1}]}', "url": url}

    monkeypatch.setattr(sp, "_http_get", fake_http_get)

    result = await detect_boolean_based_sqli(endpoint=_ENDPOINT, target_guard=_AllowGuard())

    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "no_boolean_sqli_signal"


@pytest.mark.asyncio
async def test_boolean_sqli_skipped_on_guard_block(monkeypatch):
    called = {"hits": 0}

    async def fake_http_get(url, headers, timeout):
        called["hits"] += 1
        return {"status_code": 200, "headers": {}, "body": "{}", "url": url}

    monkeypatch.setattr(sp, "_http_get", fake_http_get)

    result = await detect_boolean_based_sqli(endpoint=_ENDPOINT, target_guard=_BlockGuard())

    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "target_guard"
    assert called["hits"] == 0
