"""Unit tests for OTP-spam and coupon-reuse business abuse probes."""
import pytest

import sentinel_worker.modules.identity.business_abuse as ba_module
from sentinel_worker.modules.identity.business_abuse import detect_coupon_reuse, detect_otp_spam


class _AllowGuard:
    def validate_url(self, url, base_url=None):
        return None


def _otp_endpoint():
    return {"id": "ep1", "method": "POST", "path": "/api/otp/send",
            "host": "api.example.com", "protocol": "https"}


def _coupon_endpoint():
    return {"id": "ep2", "method": "POST", "path": "/api/cart/coupon/apply",
            "host": "api.example.com", "protocol": "https"}


# ── OTP spam ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_otp_spam_skipped_when_state_change_not_armed():
    result = await detect_otp_spam(endpoint=_otp_endpoint(), allow_state_change=False)
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "state_change_not_armed"


@pytest.mark.asyncio
async def test_otp_spam_skipped_on_non_otp_endpoint():
    ep = {"id": "ep1", "method": "POST", "path": "/api/users/create",
          "host": "api.example.com", "protocol": "https"}
    result = await detect_otp_spam(endpoint=ep, allow_state_change=True)
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "not_an_otp_endpoint"


@pytest.mark.asyncio
async def test_otp_spam_detects_no_rate_limiting(monkeypatch):
    async def fake_post(url, body, headers, timeout):
        return {"status_code": 200, "headers": {}, "body": '{"status":"sent"}', "url": url}

    monkeypatch.setattr(ba_module, "_http_post", fake_post)

    result = await detect_otp_spam(
        endpoint=_otp_endpoint(),
        burst_count=3,
        target_guard=_AllowGuard(),
        allow_state_change=True,
    )
    assert result["is_vulnerable"] is True
    assert result["type"] == "BUSINESS_LOGIC:OTP_SPAM"
    assert result["evidence"]["burst_count"] == 3
    assert result["evidence"]["rate_limited"] is False


@pytest.mark.asyncio
async def test_otp_spam_not_flagged_when_rate_limited(monkeypatch):
    call_count = {"n": 0}

    async def fake_post(url, body, headers, timeout):
        call_count["n"] += 1
        if call_count["n"] > 1:
            return {"status_code": 429, "headers": {}, "body": "Too many requests", "url": url}
        return {"status_code": 200, "headers": {}, "body": '{"status":"sent"}', "url": url}

    monkeypatch.setattr(ba_module, "_http_post", fake_post)

    result = await detect_otp_spam(
        endpoint=_otp_endpoint(),
        burst_count=3,
        target_guard=_AllowGuard(),
        allow_state_change=True,
    )
    assert result["is_vulnerable"] is False


# ── Coupon reuse ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_coupon_reuse_skipped_when_state_change_not_armed():
    result = await detect_coupon_reuse(endpoint=_coupon_endpoint(), allow_state_change=False)
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "state_change_not_armed"


@pytest.mark.asyncio
async def test_coupon_reuse_skipped_on_non_coupon_endpoint():
    ep = {"id": "ep1", "method": "POST", "path": "/api/users/profile",
          "host": "api.example.com", "protocol": "https"}
    result = await detect_coupon_reuse(endpoint=ep, allow_state_change=True)
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "not_a_coupon_endpoint"


@pytest.mark.asyncio
async def test_coupon_reuse_detects_missing_deduplication(monkeypatch):
    async def fake_post(url, body, headers, timeout):
        return {"status_code": 200, "headers": {}, "body": '{"discount":10}', "url": url}

    monkeypatch.setattr(ba_module, "_http_post", fake_post)

    result = await detect_coupon_reuse(
        endpoint=_coupon_endpoint(),
        target_guard=_AllowGuard(),
        allow_state_change=True,
    )
    assert result["is_vulnerable"] is True
    assert result["type"] == "BUSINESS_LOGIC:COUPON_REUSE"
    assert result["evidence"]["deduplication_present"] is False


@pytest.mark.asyncio
async def test_coupon_reuse_not_flagged_when_second_use_blocked(monkeypatch):
    call_count = {"n": 0}

    async def fake_post(url, body, headers, timeout):
        call_count["n"] += 1
        if call_count["n"] > 1:
            return {"status_code": 400, "headers": {}, "body": "Coupon already used", "url": url}
        return {"status_code": 200, "headers": {}, "body": '{"discount":10}', "url": url}

    monkeypatch.setattr(ba_module, "_http_post", fake_post)

    result = await detect_coupon_reuse(
        endpoint=_coupon_endpoint(),
        target_guard=_AllowGuard(),
        allow_state_change=True,
    )
    assert result["is_vulnerable"] is False
