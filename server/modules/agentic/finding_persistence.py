"""Promote agentic/detector/chain findings into evidence-grade Vulnerability records.

``_run_targeted_detectors`` and ``_run_attack_chains`` (orchestration.py) and the
LLM proposer-confirmer loop (proposer_loop.py) each produce ad-hoc finding dicts
shaped for in-memory SARIF/summary use. Historically those findings were surfaced
in a per-run ``TestResult`` row (or not persisted at all) but never promoted to a
``Vulnerability`` — so they never reached the dashboard, compliance reports, or
portfolio exports the way a deterministic template finding does. This module is
the one place that builds a ``create_or_merge_vulnerability``-ready payload from
any of the three finding shapes, using the same evidence-grade contract
(``finalize_finding_evidence``) the passive/business-logic findings already use.
"""
from __future__ import annotations

from typing import Any

from server.modules.test_executor.evidence import finalize_finding_evidence
from server.modules.utils.redactor import Redactor

_DEFAULT_REMEDIATION = (
    "Validate and enforce authorization/business-logic controls for the affected "
    "endpoint, then rerun the API Sentinel confirmatory retest."
)

# Keys, in priority order, that carry an HTTP-status-like signal across the
# different finding evidence shapes (sqli_probe/business_abuse use "status_code";
# attack_chain uses the victim/attacker step statuses).
_STATUS_CODE_KEYS = (
    "status_code",
    "attacker_target_status",
    "attacker_status",
    "victim_target_status",
)


def build_agentic_vulnerability_data(
    *,
    finding: dict[str, Any],
    endpoint: dict[str, Any],
    account_id: int,
    source: str,
) -> dict[str, Any]:
    """Build a vulnerability payload from a detector/chain/agentic finding dict.

    ``finding`` is one of the three shapes produced by orchestration.py /
    proposer_loop.py: a detector/agentic finding carries an ``evidence`` dict; a
    chain finding carries a ``chain`` dict instead. ``source`` is
    ``"detector" | "chain" | "agentic"`` and only affects the template_id prefix
    and matched_rule.detector, so the three origins stay distinguishable in the
    vulnerabilities list.
    """
    finding_type = str(finding.get("type") or "UNKNOWN").upper()
    severity = str(finding.get("severity") or "MEDIUM").upper()
    method = str(endpoint.get("method") or "GET").upper()
    url = str(endpoint.get("url") or endpoint.get("path") or "")

    raw_evidence = finding.get("evidence")
    if not isinstance(raw_evidence, dict):
        chain = finding.get("chain")
        raw_evidence = chain if isinstance(chain, dict) else {}
    safe_details = Redactor.redact_json(raw_evidence) if raw_evidence else {}
    safe_details = safe_details if isinstance(safe_details, dict) else {}

    matched_rule: dict[str, Any] = {
        "detector": str(raw_evidence.get("engine") or f"agentic_{source}"),
        "finding_type": finding_type,
    }
    if raw_evidence.get("sub_type"):
        matched_rule["sub_type"] = raw_evidence["sub_type"]

    received_response: dict[str, Any] = {}
    for key in _STATUS_CODE_KEYS:
        if raw_evidence.get(key) is not None:
            received_response = {"status_code": raw_evidence[key]}
            break
    if not received_response and safe_details:
        # Prefer keys beyond engine/sub_type (already captured in matched_rule),
        # but fall back to the full details dict when that's all the detector
        # gave us — an empty received_response would fail evidence-completeness
        # even though the finding is genuinely evidenced by its detector/sub_type.
        remainder = {
            key: value for key, value in safe_details.items() if key not in {"engine", "sub_type"}
        }
        received_response = remainder or dict(safe_details)

    confidence = str(finding.get("confidence") or "MEDIUM").upper()
    similarity = {"source": f"agentic_{source}", "confidence": confidence}

    remediation = _DEFAULT_REMEDIATION
    rationale = finding.get("rationale")
    if rationale:
        remediation = f"{_DEFAULT_REMEDIATION} Context: {Redactor.redact_text(str(rationale))}"

    evidence = finalize_finding_evidence(
        {
            "engine": f"agentic_{source}",
            "finding_type": finding_type,
            "details": safe_details,
        },
        method=method,
        url=url,
        matched_rule=matched_rule,
        received_response=received_response,
        similarity=similarity,
        remediation=remediation,
        finding_status="CONFIRMED",
    )

    return {
        "account_id": account_id,
        "template_id": f"AGENTIC:{source.upper()}:{finding_type}"[:100],
        "endpoint_id": endpoint.get("id"),
        "url": Redactor.redact_url(url),
        "method": method,
        "severity": severity,
        "type": finding_type,
        "status": "OPEN",
        "confidence": confidence,
        "remediation": evidence.get("remediation"),
        "evidence": evidence,
    }
