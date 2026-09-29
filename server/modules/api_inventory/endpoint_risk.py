"""Shared risk memory between Testing and Runtime Detection.

This closes the pipeline gap where the DAST scanner and the runtime detector were
two separate brains. When a scan confirms a vulnerability on an endpoint, we lift
that endpoint's ``risk_score`` (and stamp ``last_tested``). Runtime detection then
reads that score (see ``endpoint_risk_multiplier``) to weight live-traffic risk
toward endpoints we have *proven* are vulnerable.

Deterministic and pure-ish: the only side effect is updating the APIEndpoint row.
Severity maps to a confirmed-vulnerability risk floor; multiple confirmed vulns
push the score up but never past 1.0.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import APIEndpoint

# Risk floor a single confirmed vulnerability of each severity establishes on its
# endpoint. A confirmed CRITICAL means "treat live traffic here as high-risk".
_CONFIRMED_VULN_RISK_FLOOR = {
    "CRITICAL": 0.95,
    "HIGH": 0.80,
    "MEDIUM": 0.55,
    "LOW": 0.30,
    "INFO": 0.15,
}
# Additional bump per repeat confirmation so an endpoint with several distinct
# confirmed vulns scores higher than one with a single finding.
_REPEAT_CONFIRMATION_BUMP = 0.05


def confirmed_vuln_risk_floor(severity: str | None) -> float:
    return _CONFIRMED_VULN_RISK_FLOOR.get(str(severity or "").upper(), 0.15)


def elevate_risk_score(current: float | None, severity: str | None) -> float:
    """Return the new endpoint risk_score after a confirmed vuln of ``severity``.

    Never lowers an existing score; raises it to at least the severity floor and
    adds a small bump (capped at 1.0) so repeat confirmations accumulate.
    """
    base = float(current or 0.0)
    floor = confirmed_vuln_risk_floor(severity)
    if base >= floor:
        return min(1.0, base + _REPEAT_CONFIRMATION_BUMP)
    return min(1.0, floor)


async def record_confirmed_vulnerability_risk(
    db: AsyncSession,
    *,
    account_id: int,
    endpoint_id: str | None,
    severity: str | None,
    now=None,
) -> float | None:
    """Lift the target endpoint's risk_score for a confirmed vulnerability.

    Returns the new risk_score, or None if the endpoint cannot be found (e.g. a
    finding whose endpoint_id is not in inventory). Safe to call inside the same
    transaction as the vulnerability upsert.
    """
    if not endpoint_id:
        return None

    result = await db.execute(
        select(APIEndpoint).where(
            APIEndpoint.account_id == account_id,
            APIEndpoint.id == endpoint_id,
        )
    )
    endpoint = result.scalar_one_or_none()
    if endpoint is None:
        return None

    new_score = elevate_risk_score(endpoint.risk_score, severity)
    endpoint.risk_score = new_score
    if now is not None:
        endpoint.last_tested = now
    await db.flush()
    return new_score


async def endpoint_risk_multiplier(
    db: AsyncSession,
    *,
    account_id: int,
    endpoint_id: str | None,
    max_multiplier: float = 3.0,
) -> float:
    """Return a >=1.0 multiplier for live-traffic risk on a known endpoint.

    Runtime detection uses this to amplify an actor's risk increment when the
    targeted endpoint has a high confirmed-vulnerability risk_score. An endpoint
    we proved is BOLA-vulnerable should make hostile traffic against it count for
    more than the same traffic against an untested endpoint.

    multiplier = 1.0 + risk_score * (max_multiplier - 1.0)
    so risk_score 0 -> 1.0x (no change), risk_score 1.0 -> max_multiplier.
    """
    if not endpoint_id:
        return 1.0
    result = await db.execute(
        select(APIEndpoint.risk_score).where(
            APIEndpoint.account_id == account_id,
            APIEndpoint.id == endpoint_id,
        )
    )
    risk_score = result.scalar_one_or_none()
    if not risk_score:
        return 1.0
    return 1.0 + float(risk_score) * (max_multiplier - 1.0)
