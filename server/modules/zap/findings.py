from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.pentest.target_policy import (
    validate_pentest_evidence_url,
    validate_pentest_target,
    validated_pentest_evidence_scope,
)
from server.modules.test_executor.evidence import finalize_finding_evidence
from server.modules.utils.finding_fingerprint import zap_fingerprint
from server.modules.utils.redactor import Redactor
from server.modules.vulnerability_detector.store import create_or_merge_vulnerability

_RISK_BY_CODE = {
    "0": "INFO",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
    "4": "CRITICAL",
}
_RISK_BY_TEXT = (
    ("CRITICAL", "CRITICAL"),
    ("HIGH", "HIGH"),
    ("MEDIUM", "MEDIUM"),
    ("LOW", "LOW"),
    ("INFORMATIONAL", "INFO"),
    ("INFO", "INFO"),
)
_CONFIDENCE_BY_TEXT = {
    "FALSE POSITIVE": "LOW",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CONFIRMED": "HIGH",
}


def _text(value: Any, *, default: str = "") -> str:
    text = str(value or default).strip()
    return text or default


def _truncate(value: Any, limit: int) -> str:
    return _text(value)[:limit]


def _severity(alert: dict[str, Any]) -> str:
    risk_code = _text(alert.get("riskcode") or alert.get("riskCode"))
    if risk_code in _RISK_BY_CODE:
        return _RISK_BY_CODE[risk_code]
    risk = _text(alert.get("risk") or alert.get("riskdesc") or alert.get("riskDesc"), default="INFO").upper()
    for key, value in _RISK_BY_TEXT:
        if risk.startswith(key) or f" {key}" in risk:
            return value
    return "INFO"


def _confidence(alert: dict[str, Any]) -> str:
    confidence = _text(alert.get("confidence"), default="MEDIUM").upper()
    for key, value in _CONFIDENCE_BY_TEXT.items():
        if key in confidence:
            return value
    return "MEDIUM"


def _alert_id(alert: dict[str, Any]) -> str:
    return _truncate(
        alert.get("pluginid")
        or alert.get("pluginId")
        or alert.get("id")
        or alert.get("alertRef")
        or "zap-unknown",
        80,
    )


def _instance_url(alert: dict[str, Any], instance: dict[str, Any], site_url: str | None, target_url: str) -> str:
    return _text(
        instance.get("uri")
        or instance.get("url")
        or alert.get("url")
        or site_url,
        default=target_url,
    )


def iter_zap_alert_instances(report: dict[str, Any]) -> Iterable[tuple[dict[str, Any], dict[str, Any], str | None]]:
    sites = report.get("site")
    if isinstance(sites, dict):
        sites = [sites]
    if isinstance(sites, list):
        for site in sites:
            if not isinstance(site, dict):
                continue
            site_name = site.get("@name") or site.get("name")
            alerts = site.get("alerts") or []
            if isinstance(alerts, dict):
                alerts = [alerts]
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                instances = alert.get("instances") or []
                if isinstance(instances, dict):
                    instances = [instances]
                if not instances:
                    yield alert, {}, _text(site_name) or None
                    continue
                for instance in instances:
                    yield alert, instance if isinstance(instance, dict) else {}, _text(site_name) or None
        return

    alerts = report.get("alerts") or report.get("results") or []
    if isinstance(alerts, dict):
        alerts = [alerts]
    if isinstance(alerts, list):
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances") or alert.get("instancesData") or []
            if isinstance(instances, dict):
                instances = [instances]
            if not instances:
                yield alert, {}, None
                continue
            for instance in instances:
                yield alert, instance if isinstance(instance, dict) else {}, None


def build_zap_vulnerability_data(
    alert: dict[str, Any],
    instance: dict[str, Any],
    *,
    account_id: int,
    target_url: str,
    site_url: str | None = None,
) -> dict[str, Any]:
    plugin_id = _alert_id(alert)
    alert_name = _text(alert.get("alert") or alert.get("name") or plugin_id)
    url, scope_validation = validated_pentest_evidence_scope(
        _instance_url(alert, instance, site_url, target_url),
        target_url=target_url,
    )
    method = _text(instance.get("method") or alert.get("method"), default="GET").upper()[:10]
    severity = _severity(alert)
    redacted_alert = Redactor.redact_json(alert)
    redacted_instance = Redactor.redact_json(instance)
    source_fingerprint = zap_fingerprint(
        alert,
        instance,
        target=target_url,
        account_id=account_id,
        site_url=site_url,
    )
    confidence = _confidence(alert)
    remediation = alert.get("solution") or alert.get("reference") or (
        "Review the ZAP alert, fix the affected control, and rerun the API scan."
    )

    return {
        "account_id": account_id,
        "template_id": _truncate(f"zap-{plugin_id}", 100),
        "endpoint_id": None,
        "url": Redactor.redact_url(url),
        "method": method,
        "severity": severity,
        "type": _truncate(f"ZAP:{plugin_id}", 100),
        "description": f"ZAP finding: {_text(alert.get('desc') or alert.get('description') or alert_name)}",
        "status": "OPEN",
        "confidence": confidence,
        "remediation": Redactor.redact_text(str(remediation)),
        "evidence": finalize_finding_evidence({
            "engine": "zap",
            "confirmation": {
                "confirmed": None,
                "status": "UNCONFIRMED",
                "reason": "external_engine_single_observation",
            },
            "source_fingerprint": source_fingerprint,
            "scope_validation": scope_validation,
            "plugin_id": plugin_id,
            "target": Redactor.redact_url(target_url),
            "site": Redactor.redact_url(site_url or target_url),
            "alert": redacted_alert,
            "instance": redacted_instance,
        },
            method=method,
            url=url,
            matched_rule={
                "plugin_id": plugin_id,
                "name": alert_name,
                "risk": severity,
            },
            received_response=_zap_received_response(alert, instance),
            similarity={
                "source": "zap_confidence",
                "confidence": confidence,
            },
            remediation=str(remediation),
        ),
    }


def _zap_received_response(alert: dict[str, Any], instance: dict[str, Any]) -> dict[str, Any]:
    response: dict[str, Any] = {}
    status_code = instance.get("statusCode") or instance.get("status_code") or alert.get("statusCode")
    if status_code not in (None, ""):
        try:
            response["status_code"] = int(status_code)
        except (TypeError, ValueError):
            pass
    headers = instance.get("responseHeader") or alert.get("responseHeader")
    if headers not in (None, ""):
        response["headers"] = {"raw": str(headers)}
    body = instance.get("evidence") or instance.get("responseBody") or alert.get("evidence")
    if body not in (None, ""):
        response["body"] = body
    return response


async def persist_zap_report(
    db: AsyncSession,
    *,
    account_id: int,
    target_url: str,
    report: dict[str, Any],
) -> dict[str, Any]:
    created_count = 0
    merged_count = 0
    imported_count = 0
    vulnerabilities: list[dict[str, Any]] = []

    validate_pentest_target(target_url)
    for alert, instance, site_url in iter_zap_alert_instances(report):
        validate_pentest_evidence_url(
            _instance_url(alert, instance, site_url, target_url),
            target_url=target_url,
        )
        if site_url:
            validate_pentest_evidence_url(site_url, target_url=target_url)
        vulnerability_data = build_zap_vulnerability_data(
            alert,
            instance,
            account_id=account_id,
            target_url=target_url,
            site_url=site_url,
        )
        vulnerability, created, fingerprint = await create_or_merge_vulnerability(db, vulnerability_data)
        imported_count += 1
        if created:
            created_count += 1
        else:
            merged_count += 1
        vulnerabilities.append(
            {
                "id": vulnerability.id,
                "created": created,
                "fingerprint": fingerprint,
                "source_fingerprint": vulnerability_data["evidence"]["source_fingerprint"],
                "template_id": vulnerability.template_id,
                "severity": vulnerability.severity,
                "url": vulnerability.url,
                "method": vulnerability.method,
                "occurrence_count": int(vulnerability.occurrence_count or 1),
            }
        )

    return {
        "imported_alert_instances": imported_count,
        "created_count": created_count,
        "merged_count": merged_count,
        "vulnerabilities": vulnerabilities,
    }
