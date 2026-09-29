"""Dedicated scheduler process.

This process owns APScheduler and all periodic scheduling processors.  The API
only validates and persists schedules; it does not need to run scheduler state.
"""
from __future__ import annotations

import asyncio
import logging
import signal

from server.config import settings
from server.modules.recon.scheduler import ReconScheduler
from server.modules.scheduler.continuous_testing import ContinuousTestingProcessor
from server.modules.scheduler.openapi_drift import OpenAPIDriftProcessor
from server.modules.scheduler.test_scheduler import TestScheduler

logger = logging.getLogger(__name__)


async def run_scheduler_service() -> None:
    scheduler = TestScheduler()
    components: list[object] = [scheduler]
    if settings.STARTUP_ENABLE_RECON_SCHEDULER and settings.RECON_SCHEDULER_ENABLED:
        components.append(ReconScheduler(interval_sec=settings.RECON_SCHEDULER_INTERVAL_SECONDS))
    if settings.STARTUP_ENABLE_CONTINUOUS_TESTING and settings.CONTINUOUS_TESTING_ENABLED:
        components.append(ContinuousTestingProcessor())
    if settings.STARTUP_ENABLE_OPENAPI_DRIFT and settings.OPENAPI_DRIFT_ENABLED:
        components.append(OpenAPIDriftProcessor())

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except (NotImplementedError, RuntimeError):
                pass

    scheduler.start()
    started_components: list[object] = []
    sync_interval = max(5, int(getattr(settings, "SCHEDULER_SYNC_INTERVAL_SECONDS", 30)))
    try:
        for component in components[1:]:
            await component.start()
            started_components.append(component)
        while not stop_event.is_set():
            try:
                summary = await scheduler.sync_persisted_schedules()
                logger.info("scheduler_sync", extra=summary)
            except Exception:
                logger.exception("scheduler_sync_failed")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=sync_interval)
            except asyncio.TimeoutError:
                continue
    finally:
        scheduler.stop()
        for component in reversed(started_components):
            await component.stop()


def main() -> None:
    asyncio.run(run_scheduler_service())


if __name__ == "__main__":
    main()
