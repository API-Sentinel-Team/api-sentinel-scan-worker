"""mitmdump addon entrypoint: ``mitmdump -s server/modules/traffic_capture/mitmproxy_integration.py``.

Deliberately thin — everything that can be unit-tested without the mitmproxy
package installed lives in flow_processor.py. This file's only job is
converting a live mitmproxy HTTPFlow into the HAR-shaped dict that module
consumes, and making sure one malformed flow can never crash a long-running
mitmdump process.
"""
import logging

from mitmproxy import http

from server.modules.persistence.database import AsyncSessionLocal
from server.modules.traffic_capture.deduplication import RequestDeduplicator
from server.modules.traffic_capture.flow_processor import process_captured_flow
from server.modules.traffic_capture.har_converter import HARConverter

logger = logging.getLogger(__name__)


class MitmproxyAddon:
    """Intercepts flows, normalizes them, and persists inventory + PII findings."""

    def __init__(self):
        self.converter = HARConverter()
        self.deduplicator = RequestDeduplicator()

    async def request(self, flow: http.HTTPFlow) -> None:
        """Called when a request is received."""
        pass

    async def response(self, flow: http.HTTPFlow) -> None:
        """Called when a response is received."""
        fingerprint = self.deduplicator.get_fingerprint(flow.request)
        if self.deduplicator.is_duplicate(fingerprint):
            return

        entry = self.converter.flow_to_har_entry(flow)
        try:
            async with AsyncSessionLocal() as db:
                result = await process_captured_flow(db, entry=entry)
                await db.commit()
        except Exception:
            logger.exception("mitmproxy_flow_processing_failed url=%s", flow.request.url)
            return

        if result.get("skipped"):
            logger.warning("mitmproxy_flow_skipped reason=%s", result.get("reason"))
        elif result.get("pii_findings"):
            logger.info(
                "mitmproxy_pii_findings count=%s endpoint=%s %s",
                result["pii_findings"],
                result.get("method"),
                result.get("path"),
            )


addons = [MitmproxyAddon()]
