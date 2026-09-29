from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_SCORES: dict[str, float] = {
    "LOW": 0.25,
    "MEDIUM": 0.50,
    "HIGH": 0.75,
    "CRITICAL": 1.00,
}


class DetectorMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")

    detector_id: str
    name: str
    description: str
    tags: list[str] = Field(default_factory=list)
    threshold_keys: list[str] = Field(default_factory=list)
    enabled: bool = True


class DetectionEnvelope(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_type: str
    event_type: str = "traffic"
    account_id: int
    observed_at_ms: int
    actor_id: str = "anonymous"
    source_ip: str = ""
    method: str = "GET"
    path: str = "/"
    host: str = "unknown"
    protocol: str = "HTTP/1.1"
    endpoint_id: Optional[str] = None
    endpoint_scope: Optional[str] = None
    status_code: int = 200
    latency_ms: Optional[int] = None
    request_size: int = 0
    response_size: int = 0
    request_headers: dict[str, Any] = Field(default_factory=dict)
    response_headers: dict[str, Any] = Field(default_factory=dict)
    query_params: dict[str, Any] = Field(default_factory=dict)
    request_body_text: str = ""
    response_body_text: str = ""
    role: Optional[str] = None
    session_id: Optional[str] = None
    token_jti: Optional[str] = None
    user_id: Optional[str] = None
    geo_country: Optional[str] = None
    object_key: Optional[str] = None
    object_key_hash: Optional[str] = None
    context_source: str = "UNIFIED_PIPELINE"
    request_log_id: Optional[str] = None
    raw_ref: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionSignal(BaseModel):
    model_config = ConfigDict(extra="allow")

    detector_id: str
    incident_type: str
    category: str
    severity: Severity
    confidence: float = 0.5
    summary: str
    actor_id: str = "anonymous"
    source_ip: str = ""
    endpoint_id: Optional[str] = None
    endpoint_scope: Optional[str] = None
    dedupe_key: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    scores: dict[str, float] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    suggested_actions: list[str] = Field(default_factory=list)


class EnforcementAction(BaseModel):
    model_config = ConfigDict(extra="allow")

    action_type: str
    status: str = "PENDING"
    params: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)


class IncidentDecision(BaseModel):
    model_config = ConfigDict(extra="allow")

    alert_id: Optional[str] = None
    created_alert: bool = False
    actor_id: str = "anonymous"
    source_ip: str = ""
    severity: Severity = "LOW"
    category: str = "ANOMALY"
    risk_score: float = 0.0
    fingerprint: str = ""
    auto_blocked: bool = False
    actions: list[EnforcementAction] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    signals: list[DetectionSignal] = Field(default_factory=list)
    scores: dict[str, float] = Field(default_factory=dict)
    shadow: bool = False
    alert_title: Optional[str] = None


class NormalizationResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    envelope: DetectionEnvelope
    persisted_request_log: bool = False
    persisted_endpoint: bool = False
