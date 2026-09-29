"""Parse timestamps from eBPF sensor payloads (epoch seconds/ms or ISO-8601)."""

from __future__ import annotations

import datetime


def _utc_now_ms() -> int:
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)


def coerce_sensor_ts_ms(ts_raw: object | None) -> int:
    if ts_raw is None:
        return _utc_now_ms()
    if isinstance(ts_raw, bool):
        return _utc_now_ms()
    if isinstance(ts_raw, (int, float)):
        value = int(ts_raw)
        return value if value > 9_999_999_999 else value * 1000
    if isinstance(ts_raw, str):
        text = ts_raw.strip()
        if not text:
            return _utc_now_ms()
        if text.isdigit():
            return coerce_sensor_ts_ms(int(text))
        parsed = _parse_iso8601(text)
        if parsed is not None:
            return int(parsed.timestamp() * 1000)
    return _utc_now_ms()


def clamp_sensor_ts_ms(ms: int, *, max_skew_s: int = 300) -> int:
    """Replace sensor timestamps that are clearly not 'now' (stuck BPF clock)."""
    now = _utc_now_ms()
    if abs(now - int(ms)) > max_skew_s * 1000:
        return now
    return int(ms)


def _parse_iso8601(value: str) -> datetime.datetime | None:
    text = value.replace("Z", "+00:00")
    if "." in text:
        head, rest = text.split(".", 1)
        digits = []
        tz = ""
        for index, char in enumerate(rest):
            if char.isdigit():
                digits.append(char)
            else:
                tz = rest[index:]
                break
        frac = "".join(digits)[:6].ljust(6, "0")
        text = f"{head}.{frac}{tz}"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed
