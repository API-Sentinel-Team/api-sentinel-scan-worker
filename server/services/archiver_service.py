"""Dedicated archive and retention process."""
from __future__ import annotations

import asyncio
import logging
import signal

from server.config import settings
from server.modules.storage.archiver import ArchiveProcessor

logger = logging.getLogger(__name__)


async def run_archiver_service() -> None:
    processor = ArchiveProcessor(
        interval_sec=max(60, int(getattr(settings, "ARCHIVE_INTERVAL_SECONDS", 3600))),
        account_id=int(getattr(settings, "STARTUP_ARCHIVER_ACCOUNT_ID", 0)),
    )
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except (NotImplementedError, RuntimeError):
                pass

    await processor.start()
    try:
        await stop_event.wait()
    finally:
        await processor.stop()


def main() -> None:
    asyncio.run(run_archiver_service())


if __name__ == "__main__":
    main()
