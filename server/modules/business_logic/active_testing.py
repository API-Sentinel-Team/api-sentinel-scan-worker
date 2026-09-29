from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse


_FAMILY_MARKERS: tuple[dict[str, object], ...] = (
    {
        "family": "coupon_abuse",
        "template_markers": ("coupon", "promo", "discount", "referral"),
        "endpoint_markers": {
            "coupon": ("coupon", "promo", "discount", "voucher", "referral"),
        },
    },
    {
        "family": "otp_spam",
        "template_markers": ("otp", "mfa", "2fa", "captcha", "verification", "auth_code", "security_code"),
        "endpoint_markers": {
            "otp": ("otp", "mfa", "2fa", "captcha", "verification", "auth_code", "security_code"),
        },
    },
    {
        "family": "workflow_bypass",
        "template_markers": (
            "workflow",
            "sequence",
            "bypass",
            "minimum_spend",
            "limited_time",
            "subscription",
            "deposit",
            "handoff",
            "transaction_reversal",
        ),
        "endpoint_markers": {
            "cart": ("cart",),
            "coupon": ("coupon", "promo", "discount", "voucher"),
            "invoice": ("invoice",),
            "order": ("order", "orders"),
            "otp": ("otp", "mfa", "2fa", "verify", "verification"),
            "payment": ("payment", "refund", "transfer", "payout"),
            "subscription": ("subscription",),
        },
    },
    {
        "family": "monetary_abuse",
        "template_markers": (
            "monetary",
            "amount",
            "price",
            "quantity",
            "currency",
            "payment",
            "refund",
            "transfer",
            "payout",
            "billing",
        ),
        "endpoint_markers": {
            "amount": ("amount", "price", "subtotal", "total", "unit_price"),
            "currency": ("currency",),
            "payment": ("checkout", "payment", "refund", "transfer", "payout", "billing", "invoice"),
            "quantity": ("quantity", "qty"),
        },
    },
    {
        "family": "resource_exhaustion",
        "template_markers": ("resource_exhaustion", "rate_limit", "rate-limiting", "brute_force", "dos", "page_dos"),
        "endpoint_markers": {
            "bulk": ("bulk", "batch"),
            "export": ("export", "report", "reports", "download"),
            "search": ("search", "query"),
            "upload": ("upload", "import"),
        },
    },
)


def business_abuse_family_coverage(
    *,
    templates: list[dict] | tuple[dict, ...],
    endpoints: list[dict] | tuple[dict, ...],
) -> dict[str, dict[str, object]]:
    """Return non-secret readiness for active business-logic abuse families."""
    template_list = [template for template in (templates or []) if isinstance(template, dict)]
    endpoint_list = [endpoint for endpoint in (endpoints or []) if isinstance(endpoint, dict)]
    template_counts = {str(item["family"]): 0 for item in _FAMILY_MARKERS}
    endpoint_signals = {str(item["family"]): set() for item in _FAMILY_MARKERS}
    endpoint_counts = {str(item["family"]): 0 for item in _FAMILY_MARKERS}

    for template in template_list:
        for family in _template_families(template):
            template_counts[family] += 1

    for endpoint in endpoint_list:
        matched = _endpoint_family_signals(endpoint)
        for family, signals in matched.items():
            if signals:
                endpoint_counts[family] += 1
                endpoint_signals[family].update(signals)

    coverage: dict[str, dict[str, object]] = {}
    for item in _FAMILY_MARKERS:
        family = str(item["family"])
        template_count = int(template_counts[family])
        endpoint_signal_count = int(endpoint_counts[family])
        ready = template_count > 0 and endpoint_signal_count > 0
        coverage[family] = {
            "template_count": template_count,
            "endpoint_signal_count": endpoint_signal_count,
            "ready": ready,
            "status": _family_status(template_count=template_count, endpoint_signal_count=endpoint_signal_count),
            "signals": sorted(endpoint_signals[family]),
        }
    return coverage


def _template_families(template: dict[str, Any]) -> set[str]:
    text = _normalized_text(_template_text_parts(template))
    families = set()
    for item in _FAMILY_MARKERS:
        family = str(item["family"])
        markers = tuple(str(marker) for marker in item["template_markers"])
        if _contains_marker(text, markers):
            families.add(family)
    return families


def _endpoint_family_signals(endpoint: dict[str, Any]) -> dict[str, set[str]]:
    if str(endpoint.get("method") or "GET").upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return {}
    text = _normalized_text(_endpoint_text_parts(endpoint))
    matches: dict[str, set[str]] = {}
    for item in _FAMILY_MARKERS:
        family = str(item["family"])
        marker_groups = item["endpoint_markers"]
        if not isinstance(marker_groups, dict):
            continue
        for signal, markers in marker_groups.items():
            if _contains_marker(text, tuple(str(marker) for marker in markers)):
                matches.setdefault(family, set()).add(str(signal))
    return matches


def _template_text_parts(template: dict[str, Any]) -> list[str]:
    parts = []
    for key in ("id", "security_category", "category", "type", "test_category", "subCategory"):
        if template.get(key):
            parts.append(str(template[key]))
    info = template.get("info")
    if isinstance(info, dict):
        for key in ("name", "description", "details", "category", "subCategory", "severity"):
            if info.get(key):
                parts.append(str(info[key]))
        tags = info.get("tags")
        if isinstance(tags, str):
            parts.append(tags)
        elif isinstance(tags, list):
            parts.extend(str(tag) for tag in tags)
    return parts


def _endpoint_text_parts(endpoint: dict[str, Any]) -> list[str]:
    parts = []
    if endpoint.get("path"):
        parts.append(str(endpoint["path"]))
    if endpoint.get("url"):
        parsed = urlparse(str(endpoint["url"]))
        parts.append(parsed.path)
        parts.extend(key for key, _ in parse_qsl(parsed.query, keep_blank_values=False))
    if endpoint.get("last_query_string"):
        parts.extend(key for key, _ in parse_qsl(str(endpoint["last_query_string"]).lstrip("?")))
    for value in (
        endpoint.get("last_request_body"),
        endpoint.get("last_response_body"),
        endpoint.get("parameters"),
        endpoint.get("request_schema"),
        endpoint.get("response_schema"),
        endpoint.get("schema_json"),
    ):
        parts.extend(_json_key_paths(value))
    return parts


def _json_key_paths(value: Any) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value) if value else {}
        except Exception:
            return []
    parts: list[str] = []

    def walk(node: Any, prefix: str = "") -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                key_text = str(key)
                parts.append(key_text if not prefix else f"{prefix}.{key_text}")
                if isinstance(child, (dict, list)):
                    walk(child, key_text if not prefix else f"{prefix}.{key_text}")
        elif isinstance(node, list):
            for child in node[:20]:
                if isinstance(child, (dict, list)):
                    walk(child, prefix)

    walk(value)
    return parts


def _normalized_text(parts: list[str]) -> str:
    text = " ".join(str(part or "") for part in parts)
    text = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()
    return f"_{text}_"


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    return any(f"_{_normalize_marker(marker)}_" in text for marker in markers if marker)


def _normalize_marker(marker: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", str(marker or "")).strip("_").lower()


def _family_status(*, template_count: int, endpoint_signal_count: int) -> str:
    if template_count > 0 and endpoint_signal_count > 0:
        return "ready"
    if template_count <= 0:
        return "missing_template"
    return "missing_endpoint_context"
