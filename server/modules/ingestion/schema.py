from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class EventType(str, Enum):
    API_TRAFFIC = "api_traffic"
    GATEWAY_LOG = "gateway_log"
    TEST_RESULT = "test_result"


class BaseEvent(BaseModel):
    version: str = Field(default="v1")
    event_type: EventType
    source: str = Field(default="unknown")  # log_shipper | gateway | mirror | scanner
    account_id: int
    observed_at: int = 0  # unix ms


class APIRequest(BaseModel):
    method: str
    path: str
    host: Optional[str] = None
    scheme: Optional[str] = "http"
    headers: Dict[str, str] = Field(default_factory=dict)
    query: Dict[str, Any] = Field(default_factory=dict)
    body: Any = None


class APIResponse(BaseModel):
    status_code: int = 200
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Any = None
    latency_ms: Optional[int] = None


class ContainerContext(BaseModel):
    pod_name: Optional[str] = None
    pod_namespace: Optional[str] = None
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    node_name: Optional[str] = None
    service_name: Optional[str] = None
    workload_type: Optional[str] = None


class APITrafficEvent(BaseEvent):
    event_type: EventType = EventType.API_TRAFFIC
    request: APIRequest
    response: APIResponse
    collection_id: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    netns_ino: Optional[int] = None
    cgroup_id: Optional[int] = None
    container: Optional[ContainerContext] = None
    protocol: str = Field(default="HTTP/1.1")


class GatewayLogEvent(BaseEvent):
    event_type: EventType = EventType.GATEWAY_LOG
    lines: List[str] = Field(default_factory=list)


class TestResultEvent(BaseEvent):
    event_type: EventType = EventType.TEST_RESULT
    run_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    template_id: Optional[str] = None
    is_vulnerable: bool = False
    severity: str = "MEDIUM"
    evidence: Dict[str, Any] = Field(default_factory=dict)
    request: Optional[APIRequest] = None
    response: Optional[APIResponse] = None


EventUnion = Union[APITrafficEvent, GatewayLogEvent, TestResultEvent]


class EventBatch(BaseModel):
    version: str = Field(default="v1")
    events: List[EventUnion] = Field(default_factory=list)
