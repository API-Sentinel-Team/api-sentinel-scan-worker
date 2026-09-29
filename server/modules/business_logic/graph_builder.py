"""Business logic graph construction and anomaly detection."""
from __future__ import annotations

import datetime
from collections import defaultdict
from typing import Optional

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import (
    RequestLog,
    BusinessLogicGraph,
    BusinessLogicViolation,
    EvidenceRecord,
)
from server.modules.passive.findings import persist_business_logic_violation
from server.modules.utils.redactor import Redactor


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


async def get_latest_graph(db: AsyncSession, account_id: int) -> Optional[BusinessLogicGraph]:
    result = await db.execute(
        select(BusinessLogicGraph)
        .where(BusinessLogicGraph.account_id == account_id)
        .order_by(desc(BusinessLogicGraph.built_at), desc(BusinessLogicGraph.version))
        .limit(1)
    )
    return result.scalar_one_or_none()


async def build_graph(
    db: AsyncSession,
    account_id: int,
    window_days: int = 14,
    min_transitions: int = 3,
) -> BusinessLogicGraph:
    since = _now() - datetime.timedelta(days=window_days)
    logs_result = await db.execute(
        select(RequestLog)
        .where(RequestLog.account_id == account_id, RequestLog.created_at >= since)
        .order_by(RequestLog.source_ip, RequestLog.created_at)
    )
    logs = logs_result.scalars().all()

    # Group by actor to build ordered sequences.
    sequences: dict[str, list[RequestLog]] = defaultdict(list)
    for log in logs:
        sequences[log.source_ip or "unknown"].append(log)

    edge_counts: dict[tuple[str, str], list[int]] = defaultdict(list)
    node_counts: dict[str, int] = defaultdict(int)

    for _, seq in sequences.items():
        for idx, entry in enumerate(seq):
            path = _safe_path(entry.path)
            if not path:
                continue
            node_counts[path] += 1
            if idx == 0:
                continue
            prev = seq[idx - 1]
            prev_path = _safe_path(prev.path)
            if not prev_path:
                continue
            delta_ms = int((entry.created_at - prev.created_at).total_seconds() * 1000)
            edge_counts[(prev_path, path)].append(delta_ms)

    edges = []
    total_transitions = sum(len(v) for v in edge_counts.values()) or 1
    for (src, dst), deltas in edge_counts.items():
        if len(deltas) < min_transitions:
            continue
        edges.append({
            "from": src,
            "to": dst,
            "count": len(deltas),
            "weight": len(deltas) / total_transitions,
            "min_time_ms": min(deltas),
            "max_time_ms": max(deltas),
        })

    nodes = [{"path": path, "count": count} for path, count in node_counts.items()]

    prev_graph = await get_latest_graph(db, account_id)
    next_version = (prev_graph.version + 1) if prev_graph else 1
    graph = BusinessLogicGraph(
        account_id=account_id,
        version=next_version,
        nodes_json=nodes,
        edges_json=edges,
    )
    db.add(graph)
    await db.flush()
    return graph


async def detect_transition_violation(
    db: AsyncSession,
    account_id: int,
    actor_id: str,
    prev_path: Optional[str],
    curr_path: Optional[str],
    elapsed_ms: int | None = None,
) -> Optional[BusinessLogicViolation]:
    prev_path = _safe_path(prev_path)
    curr_path = _safe_path(curr_path)
    actor_id = _safe_text(actor_id)
    if not curr_path:
        return None

    graph = await get_latest_graph(db, account_id)
    if not graph or not graph.edges_json:
        return None

    allowed_edges = {
        (_safe_path(e.get("from")), _safe_path(e.get("to"))): e
        for e in graph.edges_json
        if e.get("count", 0) >= 3
    }
    if not prev_path:
        expected_predecessors = sorted(
            from_path
            for from_path, to_path in allowed_edges
            if to_path == curr_path and from_path
        )
        if not expected_predecessors:
            return None
        violation_type = "MISSING_PREREQUISITE"
        confidence = 0.75
        details = {
            "graph_version": graph.version,
            "expected_predecessors": expected_predecessors[:10],
            "expected_predecessor_count": len(expected_predecessors),
        }
        violation = BusinessLogicViolation(
            account_id=account_id,
            actor_id=actor_id,
            from_path=None,
            to_path=curr_path,
            violation_type=violation_type,
            confidence=confidence,
            details=details,
        )
        await _persist_violation_with_evidence(db, account_id=account_id, violation=violation)
        return violation

    edge = allowed_edges.get((prev_path, curr_path))
    if edge:
        timing_violation = _too_fast_transition(edge, elapsed_ms)
        if timing_violation is None:
            return None
        violation_type = "TOO_FAST_TRANSITION"
        confidence = 0.8
        details = {
            "graph_version": graph.version,
            **timing_violation,
        }
    else:
        violation_type = "FORBIDDEN_TRANSITION"
        confidence = 0.7
        details = {"graph_version": graph.version}

    violation = BusinessLogicViolation(
        account_id=account_id,
        actor_id=actor_id,
        from_path=prev_path,
        to_path=curr_path,
        violation_type=violation_type,
        confidence=confidence,
        details=details,
    )
    await _persist_violation_with_evidence(db, account_id=account_id, violation=violation)
    return violation


async def _persist_violation_with_evidence(
    db: AsyncSession,
    *,
    account_id: int,
    violation: BusinessLogicViolation,
) -> None:
    db.add(violation)
    await db.flush()

    from_label = violation.from_path if violation.from_path else "direct_entry"
    db.add(EvidenceRecord(
        account_id=account_id,
        evidence_type="bizlogic",
        ref_id=violation.id,
        severity="HIGH",
        summary=Redactor.redact_text(f"Unexpected transition {from_label} -> {violation.to_path}"),
        details={
            "actor_id": violation.actor_id,
            "from_path": violation.from_path,
            "to_path": violation.to_path,
            "violation_type": violation.violation_type,
            "details": violation.details or {},
        },
    ))
    await persist_business_logic_violation(db, account_id=account_id, violation=violation)


def _safe_path(path: Optional[str]) -> Optional[str]:
    if path is None:
        return None
    return Redactor.redact_text(path)


def _safe_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return Redactor.redact_text(value)


def _too_fast_transition(edge: dict, elapsed_ms: int | None) -> dict[str, int] | None:
    if elapsed_ms is None or elapsed_ms < 0:
        return None
    try:
        expected_min_time_ms = int(edge.get("min_time_ms") or 0)
        edge_count = int(edge.get("count") or 0)
    except (TypeError, ValueError):
        return None
    if expected_min_time_ms <= 0:
        return None
    threshold_ms = max(250, int(expected_min_time_ms * 0.5))
    if elapsed_ms >= threshold_ms:
        return None
    return {
        "observed_elapsed_ms": int(elapsed_ms),
        "expected_min_time_ms": expected_min_time_ms,
        "threshold_ms": threshold_ms,
        "edge_count": edge_count,
    }
