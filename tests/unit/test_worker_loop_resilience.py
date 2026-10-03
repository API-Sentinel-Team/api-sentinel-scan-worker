"""The continuous worker must survive a database/DNS outage and must not be silent."""
import logging
import socket

import pytest

from sentinel_worker.modules.test_executor import scan_worker


@pytest.fixture
def no_sleep(monkeypatch):
    slept: list[float] = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(scan_worker.asyncio, "sleep", fake_sleep)
    return slept


def _flaky_poll(failures: int, exc: Exception):
    state = {"calls": 0}

    async def poll(**_kwargs):
        state["calls"] += 1
        if state["calls"] <= failures:
            raise exc
        return {"claimed": True, "status": "executed", "run_id": "run-42"}

    return state, poll


@pytest.mark.asyncio
async def test_a_dns_outage_is_retried_with_backoff_until_the_database_returns(monkeypatch, no_sleep, caplog):
    # The deployed worker died on exactly this error: socket.gaierror(-3) while Postgres did not exist yet.
    state, poll = _flaky_poll(3, socket.gaierror(-3, "Temporary failure in name resolution"))
    monkeypatch.setattr(scan_worker, "run_pending_scan_once", poll)
    caplog.set_level(logging.INFO, logger=scan_worker.logger.name)

    summary = await scan_worker.run_worker_loop(max_runs=1, retry_errors=True, poll_interval_seconds=2.0)

    assert summary["executed"] == 1
    assert state["calls"] == 4, "three failed polls then one success"
    assert len(no_sleep) == 3 and all(d > 0 for d in no_sleep)
    text = caplog.text
    assert "poll failed (3 in a row)" in text and "gaierror" in text
    assert "recovered after 3 failed polls" in text


@pytest.mark.asyncio
async def test_a_bounded_run_still_raises_so_tests_never_hide_errors(monkeypatch, no_sleep):
    _, poll = _flaky_poll(1, RuntimeError("boom"))
    monkeypatch.setattr(scan_worker, "run_pending_scan_once", poll)
    with pytest.raises(RuntimeError, match="boom"):
        await scan_worker.run_worker_loop(max_runs=1)


@pytest.mark.asyncio
async def test_cancellation_is_never_swallowed_by_the_retry(monkeypatch, no_sleep):
    import asyncio

    async def poll(**_kwargs):
        raise asyncio.CancelledError()

    monkeypatch.setattr(scan_worker, "run_pending_scan_once", poll)
    with pytest.raises(asyncio.CancelledError):
        await scan_worker.run_worker_loop(max_runs=1, retry_errors=True)


@pytest.mark.asyncio
async def test_the_worker_is_not_silent_start_and_claims_are_logged(monkeypatch, no_sleep, caplog):
    _, poll = _flaky_poll(0, RuntimeError("unused"))
    monkeypatch.setattr(scan_worker, "run_pending_scan_once", poll)
    caplog.set_level(logging.INFO, logger=scan_worker.logger.name)
    await scan_worker.run_worker_loop(max_runs=1, worker_id="w-1")
    assert "scan worker started worker_id=w-1" in caplog.text
    assert "finished run run_id=run-42 status=executed" in caplog.text


def test_backoff_grows_is_capped_and_never_below_half_the_ceiling():
    for failures in range(1, 12):
        for _ in range(50):
            d = scan_worker._poll_failure_delay(failures, 2.0)
            ceiling = min(scan_worker._WORKER_BACKOFF_CAP_SECONDS, 2.0 * 2 ** min(failures, 6))
            assert ceiling / 2 <= d <= ceiling
    assert scan_worker._poll_failure_delay(50, 2.0) <= scan_worker._WORKER_BACKOFF_CAP_SECONDS


def test_the_entrypoint_configures_logging_so_info_is_visible():
    import inspect

    src = inspect.getsource(scan_worker.main)
    assert "logging.basicConfig" in src and "LOG_LEVEL" in src
