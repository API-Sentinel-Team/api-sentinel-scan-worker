"""
AppSentinel Log Shipper Agent
==============================
Runs on the nginx server. Tails the nginx access log in real-time and ships
new lines to the SOC backend every 5 seconds.

Usage:
    python log_shipper.py --key <SENSOR_KEY> --log /var/log/nginx/access.log \
        --endpoint https://your-soc.example.com/api/stream/ingest

Install as a systemd service or run in background:
    nohup python log_shipper.py --key abc123 &

Requirements:
    pip install requests
"""

import argparse
import json
import os
import sys
import time
import logging
import signal
from pathlib import Path

try:
    import requests
except ImportError:
    print("Missing dependency: pip install requests")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────
DEFAULT_LOG_PATH   = "/var/log/nginx/access.log"
DEFAULT_ENDPOINT   = "http://localhost:8000/api/stream/ingest"
SHIP_INTERVAL_SEC  = 5       # how often to flush buffered lines
MAX_BATCH_SIZE     = 500     # max lines per request
HEARTBEAT_INTERVAL = 30      # send heartbeat every N seconds
RETRY_BACKOFF      = [1, 2, 5, 10, 30]  # retry delays on failure

logging.basicConfig(
    format="%(asctime)s [LOG-SHIPPER] %(levelname)s %(message)s",
    level=logging.INFO,
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("log_shipper")


class LogShipper:
    def __init__(self, sensor_key: str, log_path: str, endpoint: str):
        self.sensor_key  = sensor_key
        self.log_path    = Path(log_path)
        self.endpoint    = endpoint.rstrip("/")
        self.ingest_url  = f"{self.endpoint}"
        self.hb_url      = self._build_heartbeat_url()
        self._running    = True
        self._pos        = 0          # file byte offset
        self._buffer: list[str] = []
        self._lines_shipped   = 0
        self._events_detected = 0
        self._last_heartbeat  = 0.0
        self._retry_count     = 0

    def _build_heartbeat_url(self) -> str:
        # Derive heartbeat URL without placing the sensor credential in the URL.
        base = self.endpoint.replace("/stream/ingest", "")
        return f"{base}/sensors/heartbeat"

    def _open_log(self):
        """Open log file and seek to end on first run (only new lines)."""
        if not self.log_path.exists():
            logger.warning(f"Log file not found: {self.log_path} — waiting...")
            return None
        f = open(self.log_path, "r", encoding="utf-8", errors="replace")
        if self._pos == 0:
            f.seek(0, 2)   # seek to end — only ship new lines
            self._pos = f.tell()
            logger.info(f"Tailing {self.log_path} from byte {self._pos}")
        else:
            f.seek(self._pos)
        return f

    def _read_new_lines(self, f) -> list[str]:
        """Read any new lines written since last check. Handle log rotation."""
        try:
            current_size = self.log_path.stat().st_size
        except FileNotFoundError:
            return []

        if current_size < self._pos:
            # Log was rotated — reopen from start
            logger.info("Log rotation detected — reopening from start")
            f.close()
            self._pos = 0
            f = self._open_log()
            if f is None:
                return []

        lines = []
        for line in f:
            lines.append(line.rstrip("\n"))
        self._pos = f.tell()
        return lines

    def _ship(self, lines: list[str]) -> bool:
        """POST lines to SOC backend. Returns True on success."""
        if not lines:
            return True
        payload = {
            "lines": lines,
        }
        for attempt, delay in enumerate(RETRY_BACKOFF + [None]):
            try:
                resp = requests.post(
                    self.ingest_url,
                    json=payload,
                    headers={"X-Sensor-Key": self.sensor_key},
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self._lines_shipped   += data.get("lines_processed", len(lines))
                    self._events_detected += data.get("threats_detected", 0)
                    self._retry_count = 0
                    logger.info(
                        f"Shipped {len(lines)} lines | "
                        f"threats={data.get('threats_detected', 0)} | "
                        f"total_shipped={self._lines_shipped}"
                    )
                    return True
                else:
                    logger.warning(f"Server returned {resp.status_code}: {resp.text[:200]}")
            except requests.RequestException as e:
                logger.error(f"Ship failed (attempt {attempt+1}): {e}")

            if delay is None:
                break
            logger.info(f"Retrying in {delay}s...")
            time.sleep(delay)

        logger.error(f"Failed to ship {len(lines)} lines after all retries — dropping batch")
        return False

    def _heartbeat(self):
        """Send heartbeat to sensors endpoint."""
        now = time.time()
        if now - self._last_heartbeat < HEARTBEAT_INTERVAL:
            return
        try:
            requests.post(
                self.hb_url,
                json={
                    "lines_shipped": self._lines_shipped,
                    "events_detected": self._events_detected,
                },
                headers={"X-Sensor-Key": self.sensor_key},
                timeout=5,
            )
            self._last_heartbeat = now
            logger.debug("Heartbeat sent")
        except requests.RequestException as e:
            logger.warning(f"Heartbeat failed: {e}")

    def stop(self, *_):
        logger.info("Stopping log shipper...")
        self._running = False

    def run(self):
        signal.signal(signal.SIGINT,  self.stop)
        signal.signal(signal.SIGTERM, self.stop)

        logger.info(
            f"Log Shipper starting | log={self.log_path} | endpoint={self.endpoint}"
        )

        f = None
        while self._running:
            try:
                if f is None:
                    f = self._open_log()
                    if f is None:
                        time.sleep(5)
                        continue

                new_lines = self._read_new_lines(f)
                if new_lines:
                    self._buffer.extend(new_lines)

                # Flush when buffer reaches max or on interval
                if len(self._buffer) >= MAX_BATCH_SIZE:
                    batch = self._buffer[:MAX_BATCH_SIZE]
                    self._buffer = self._buffer[MAX_BATCH_SIZE:]
                    self._ship(batch)
                elif self._buffer:
                    self._ship(self._buffer)
                    self._buffer.clear()

                self._heartbeat()
                time.sleep(SHIP_INTERVAL_SEC)

            except Exception as e:
                logger.exception(f"Unexpected error: {e}")
                time.sleep(5)

        # Final flush
        if self._buffer:
            logger.info(f"Final flush: {len(self._buffer)} lines")
            self._ship(self._buffer)

        if f:
            f.close()
        logger.info(
            f"Stopped. Total shipped: {self._lines_shipped} lines, "
            f"{self._events_detected} threats detected."
        )


def main():
    parser = argparse.ArgumentParser(
        description="AppSentinel nginx log shipper — tails nginx access.log and ships to SOC"
    )
    parser.add_argument(
        "--key", required=True,
        help="Sensor key from SOC dashboard (Settings → Sensors → Register)"
    )
    parser.add_argument(
        "--log", default=DEFAULT_LOG_PATH,
        help=f"Path to nginx access log (default: {DEFAULT_LOG_PATH})"
    )
    parser.add_argument(
        "--endpoint", default=DEFAULT_ENDPOINT,
        help=f"SOC ingest endpoint URL (default: {DEFAULT_ENDPOINT})"
    )
    parser.add_argument(
        "--from-start", action="store_true",
        help="Ship entire log file from start (not just new lines)"
    )
    args = parser.parse_args()

    shipper = LogShipper(
        sensor_key=args.key,
        log_path=args.log,
        endpoint=args.endpoint,
    )
    if args.from_start:
        shipper._pos = 0  # read from beginning

    shipper.run()


if __name__ == "__main__":
    main()
