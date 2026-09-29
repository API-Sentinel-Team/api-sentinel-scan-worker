"""
Threat Detection Schemas
========================
Python/Pydantic equivalents of Akto's protobuf threat_detection messages.

Covers:
  - malicious_event/v1/message.proto
  - sample_request/v1/message.proto
  - agentic_session/v1/message.proto
  - malicious_alert_service/v1/service.proto
  - agentic_session_service/v1/service.proto
  - dashboard_service/v1/service.proto  (all request/response messages)
"""
from __future__ import annotations
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────

class EventType(str, Enum):
    UNSPECIFIED = "EVENT_TYPE_UNSPECIFIED"
    SINGLE      = "EVENT_TYPE_SINGLE"
    AGGREGATED  = "EVENT_TYPE_AGGREGATED"


class SchemaConformanceLocation(str, Enum):
    UNSPECIFIED = "LOCATION_UNSPECIFIED"
    URL         = "LOCATION_URL"
    HEADER      = "LOCATION_HEADER"
    BODY        = "LOCATION_BODY"


# ── sample_request/v1 ────────────────────────────────────────────────────────

class SchemaConformanceError(BaseModel):
    schema_path:   str = ""
    instance_path: str = ""
    attribute:     str = ""
    message:       str = ""
    location:      SchemaConformanceLocation = SchemaConformanceLocation.UNSPECIFIED
    start:         int = 0   # start position of threat in text
    end:           int = 0   # end position of threat in text
    phrase:        str = ""  # actual threat phrase/keyword


class SampleRequestMetadata(BaseModel):
    country_code:      str = ""
    schema_errors:     List[SchemaConformanceError] = Field(default_factory=list)
    policy_name:       str = ""
    rule_violated:     str = ""
    risk_score:        str = ""
    reason:            str = ""
    dest_country_code: str = ""


class SampleMaliciousRequest(BaseModel):
    ip:                str = ""
    timestamp:         int = 0
    url:               str = ""
    method:            str = ""
    api_collection_id: int = 0
    payload:           str = ""
    filter_id:         str = ""
    metadata:          Optional[SampleRequestMetadata] = None
    successful_exploit: bool = False
    status:            str = ""


class SampleRequestKafkaEnvelope(BaseModel):
    account_id:        str = ""
    actor:             str = ""
    malicious_request: Optional[SampleMaliciousRequest] = None


# ── malicious_event/v1 ───────────────────────────────────────────────────────

class MaliciousEventMessage(BaseModel):
    actor:                  str = ""
    filter_id:              str = ""
    detected_at:            int = 0
    latest_api_ip:          str = ""
    latest_api_endpoint:    str = ""
    latest_api_method:      str = ""
    latest_api_collection_id: int = 0
    latest_api_payload:     str = ""
    event_type:             EventType = EventType.UNSPECIFIED
    category:               str = ""
    sub_category:           str = ""
    severity:               str = ""
    type:                   str = ""
    metadata:               Optional[SampleRequestMetadata] = None
    successful_exploit:     bool = False
    label:                  str = ""    # "threat" | "guardrail"
    host:                   str = ""
    status:                 str = ""
    context_source:         str = ""    # API | MCP | GEN_AI | AGENTIC | DAST | ENDPOINT
    session_id:             str = ""


class MaliciousEventKafkaEnvelope(BaseModel):
    account_id:     str = ""
    actor:          str = ""
    malicious_event: Optional[MaliciousEventMessage] = None


# ── agentic_session/v1 ───────────────────────────────────────────────────────

class ConversationEntry(BaseModel):
    request_id:       str = ""
    request_payload:  str = ""
    response_payload: str = ""
    timestamp:        int = 0


class SessionDocumentMessage(BaseModel):
    session_identifier:  str = ""
    session_summary:     str = ""
    conversation_info:   List[ConversationEntry] = Field(default_factory=list)
    is_malicious:        bool = False
    blocked_reason:      str = ""
    created_at:          int = 0
    updated_at:          int = 0


# ── malicious_alert_service/v1 ───────────────────────────────────────────────

class RecordMaliciousEventRequest(BaseModel):
    malicious_event:  Optional[MaliciousEventMessage] = None
    sample_requests:  List[SampleMaliciousRequest] = Field(default_factory=list)


class RecordMaliciousEventResponse(BaseModel):
    pass


# ── agentic_session_service/v1 ───────────────────────────────────────────────

class BulkUpdateAgenticSessionContextRequest(BaseModel):
    session_documents: List[SessionDocumentMessage] = Field(default_factory=list)


class BulkUpdateAgenticSessionContextResponse(BaseModel):
    success:       bool = False
    error_message: str = ""
    updated_count: int = 0


# ── dashboard_service/v1 ─────────────────────────────────────────────────────

class TimeRangeFilter(BaseModel):
    start: Optional[int] = None
    end:   Optional[int] = None


# -- List malicious requests

class MaliciousRequestFilter(BaseModel):
    actors:                  List[str] = Field(default_factory=list)
    urls:                    List[str] = Field(default_factory=list)
    ips:                     List[str] = Field(default_factory=list)
    detected_at_time_range:  Optional[TimeRangeFilter] = None
    types:                   List[str] = Field(default_factory=list)
    sub_category:            List[str] = Field(default_factory=list)
    latest_attack:           List[str] = Field(default_factory=list)
    status_filter:           Optional[str] = None
    successful_exploit:      Optional[bool] = None
    label:                   Optional[str] = None
    hosts:                   List[str] = Field(default_factory=list)
    latest_api_orig_regex:   Optional[str] = None
    api_collection_id:       List[int] = Field(default_factory=list)
    method:                  List[str] = Field(default_factory=list)
    sort_by_severity:        Optional[bool] = None


class ListMaliciousRequestsRequest(BaseModel):
    skip:   Optional[int] = 0
    limit:  int = 50
    sort:   Dict[str, int] = Field(default_factory=dict)
    filter: MaliciousRequestFilter = Field(default_factory=MaliciousRequestFilter)


class MaliciousEventEntry(BaseModel):
    id:                 str = ""
    actor:              str = ""
    filter_id:          str = ""
    detected_at:        int = 0
    ip:                 str = ""
    endpoint:           str = ""
    method:             str = ""
    api_collection_id:  int = 0
    payload:            str = ""
    country:            str = ""
    event_type:         EventType = EventType.UNSPECIFIED
    category:           str = ""
    sub_category:       str = ""
    type:               str = ""
    ref_id:             str = ""
    event_type_val:     str = ""
    metadata:           str = ""
    status:             str = ""
    successful_exploit: bool = False
    label:              str = ""
    host:               str = ""
    jira_ticket_url:    str = ""
    severity:           str = ""
    dest_country:       str = ""
    session_id:         str = ""


class ListMaliciousRequestsResponse(BaseModel):
    malicious_events: List[MaliciousEventEntry] = Field(default_factory=list)
    total:            int = 0


# -- Fetch alert filters

class FetchAlertFiltersRequest(BaseModel):
    detected_at_time_range: Optional[TimeRangeFilter] = None


class FetchAlertFiltersResponse(BaseModel):
    actors:       List[str] = Field(default_factory=list)
    urls:         List[str] = Field(default_factory=list)
    sub_category: List[str] = Field(default_factory=list)
    hosts:        List[str] = Field(default_factory=list)


# -- List threat actors

class ThreatActorFilter(BaseModel):
    actors:                 List[str] = Field(default_factory=list)
    latest_ips:             List[str] = Field(default_factory=list)
    detected_at_time_range: Optional[TimeRangeFilter] = None
    latest_attack:          List[str] = Field(default_factory=list)
    country:                List[str] = Field(default_factory=list)
    hosts:                  List[str] = Field(default_factory=list)


class ListThreatActorsRequest(BaseModel):
    skip:     Optional[int] = 0
    limit:    int = 50
    sort:     Dict[str, int] = Field(default_factory=dict)
    filter:   ThreatActorFilter = Field(default_factory=ThreatActorFilter)
    start_ts: int = 0
    end_ts:   int = 0
    cursor:   Optional[str] = None


class ThreatActorActivityData(BaseModel):
    url:          str = ""
    sub_category: str = ""
    detected_at:  int = 0
    severity:     str = ""
    method:       str = ""
    host:         str = ""
    metadata:     str = ""


class ThreatActorEntry(BaseModel):
    id:                 str = ""
    latest_api_ip:      str = ""
    latest_api_endpoint: str = ""
    latest_api_method:  str = ""
    discovered_at:      int = 0
    country:            str = ""
    activity_data:      List[ThreatActorActivityData] = Field(default_factory=list)
    latest_subcategory: str = ""
    latest_api_host:    str = ""
    latest_metadata:    str = ""
    object_id:          Optional[str] = None


class ListThreatActorResponse(BaseModel):
    actors: List[ThreatActorEntry] = Field(default_factory=list)
    total:  int = 0


# -- Fetch malicious events (payloads for an actor/filter)

class FetchMaliciousEventsRequest(BaseModel):
    ref_id:     str = ""
    event_type: str = ""
    actor:      str = ""
    filter_id:  str = ""


class MaliciousPayloadsResponse(BaseModel):
    orig:     str = ""
    ts:       int = 0
    metadata: str = ""


class FetchMaliciousEventsResponse(BaseModel):
    malicious_payloads_response: List[MaliciousPayloadsResponse] = Field(default_factory=list)


# -- List threat APIs

class ThreatApiFilter(BaseModel):
    urls:                   List[str] = Field(default_factory=list)
    methods:                List[str] = Field(default_factory=list)
    detected_at_time_range: Optional[TimeRangeFilter] = None
    latest_attack:          List[str] = Field(default_factory=list)


class ListThreatApiRequest(BaseModel):
    skip:   Optional[int] = 0
    limit:  int = 50
    sort:   Dict[str, int] = Field(default_factory=dict)
    filter: ThreatApiFilter = Field(default_factory=ThreatApiFilter)


class ThreatApiEntry(BaseModel):
    endpoint:       str = ""
    method:         str = ""
    discovered_at:  int = 0
    actors_count:   int = 0
    requests_count: int = 0
    host:           str = ""


class ListThreatApiResponse(BaseModel):
    apis:  List[ThreatApiEntry] = Field(default_factory=list)
    total: int = 0


# -- Country / category / severity aggregations

class ThreatActorByCountryRequest(BaseModel):
    start_ts:      int = 0
    end_ts:        int = 0
    latest_attack: List[str] = Field(default_factory=list)


class CountryCount(BaseModel):
    code:  str = ""
    count: int = 0


class ThreatActorByCountryResponse(BaseModel):
    countries: List[CountryCount] = Field(default_factory=list)


class ThreatCategoryWiseCountRequest(BaseModel):
    start_ts:      int = 0
    end_ts:        int = 0
    latest_attack: List[str] = Field(default_factory=list)


class SubCategoryCount(BaseModel):
    category:     str = ""
    sub_category: str = ""
    count:        int = 0


class ThreatCategoryWiseCountResponse(BaseModel):
    category_wise_counts: List[SubCategoryCount] = Field(default_factory=list)


class ThreatSeverityWiseCountRequest(BaseModel):
    start_ts:      int = 0
    end_ts:        int = 0
    latest_attack: List[str] = Field(default_factory=list)


class SeverityCount(BaseModel):
    severity: str = ""
    count:    int = 0


class ThreatSeverityWiseCountResponse(BaseModel):
    category_wise_counts: List[SeverityCount] = Field(default_factory=list)


class DailyActorsCountRequest(BaseModel):
    start_ts:      int = 0
    end_ts:        int = 0
    latest_attack: List[str] = Field(default_factory=list)


class DailyActorsCount(BaseModel):
    ts:             int = 0
    total_actors:   int = 0
    critical_actors: int = 0


class DailyActorsCountResponse(BaseModel):
    actors_counts:         List[DailyActorsCount] = Field(default_factory=list)
    total_analysed:        int = 0
    total_attacks:         int = 0
    critical_actors_count: int = 0
    total_active:          int = 0
    total_ignored:         int = 0
    total_under_review:    int = 0


# -- Activity timeline

class ThreatActivityTimelineRequest(BaseModel):
    start_ts:      int = 0
    end_ts:        int = 0
    latest_attack: List[str] = Field(default_factory=list)


class SubCategoryData(BaseModel):
    sub_category:   str = ""
    activity_count: int = 0


class ActivityTimeline(BaseModel):
    ts:                    int = 0
    sub_category_wise_data: List[SubCategoryData] = Field(default_factory=list)


class ThreatActivityTimelineResponse(BaseModel):
    threat_activity_timeline: List[ActivityTimeline] = Field(default_factory=list)


# -- Actor status mutations

class ModifyThreatActorStatusRequest(BaseModel):
    ip:         str = ""
    status:     str = ""
    updated_ts: int = 0


class ModifyThreatActorStatusResponse(BaseModel):
    pass


class BulkModifyThreatActorStatusRequest(BaseModel):
    ips:        List[str] = Field(default_factory=list)
    status:     str = ""
    updated_ts: int = 0


class BulkModifyThreatActorStatusResponse(BaseModel):
    pass


# -- Event status mutations

class UpdateMaliciousEventStatusRequest(BaseModel):
    event_id:        Optional[str] = None
    event_ids:       List[str] = Field(default_factory=list)
    filter:          Optional[MaliciousRequestFilter] = None
    status:          Optional[str] = None
    jira_ticket_url: Optional[str] = None


class UpdateMaliciousEventStatusResponse(BaseModel):
    success:       bool = False
    message:       str = ""
    updated_count: int = 0


class DeleteMaliciousEventsRequest(BaseModel):
    event_ids: List[str] = Field(default_factory=list)
    filter:    Optional[MaliciousRequestFilter] = None


class DeleteMaliciousEventsResponse(BaseModel):
    success:       bool = False
    message:       str = ""
    deleted_count: int = 0


# -- Threat configuration

class ActorId(BaseModel):
    type:    str = ""   # "ip" or "header"
    key:     str = ""   # "ip" or header name
    kind:    str = ""   # hostname | endpoint | collection
    pattern: str = ""   # regex or collection id


class Actor(BaseModel):
    actor_id: List[ActorId] = Field(default_factory=list)


class AutomatedThreshold(BaseModel):
    percentile:          str = ""
    overflow_percentage: int = 0
    baseline_period:     int = 0


class RatelimitConfigItem(BaseModel):
    name:                str = ""
    period:              int = 0
    max_requests:        int = 0
    mitigation_period:   int = 0
    action:              str = ""
    type:                str = ""   # default | custom
    auto_threshold:      Optional[AutomatedThreshold] = None
    behaviour:           str = ""   # dynamic | static
    rate_limit_confidence: float = 0.0


class RatelimitConfig(BaseModel):
    rules: List[RatelimitConfigItem] = Field(default_factory=list)


class ParamEnumerationConfig(BaseModel):
    unique_param_threshold: int = 50
    window_size_minutes:    int = 5


class ThreatConfiguration(BaseModel):
    actor:                    Optional[Actor] = None
    ratelimit_config:         Optional[RatelimitConfig] = None
    archival_days:            int = 30
    archival_enabled:         bool = False
    param_enumeration_config: Optional[ParamEnumerationConfig] = None


class GetThreatConfigurationRequest(BaseModel):
    pass


class ToggleArchivalEnabledRequest(BaseModel):
    enabled: bool = False


class ToggleArchivalEnabledResponse(BaseModel):
    enabled: bool = False


# -- Top-N data

class FetchTopNDataRequest(BaseModel):
    start_ts:      int = 0
    end_ts:        int = 0
    latest_attack: List[str] = Field(default_factory=list)
    limit:         int = 10


class TopApiData(BaseModel):
    endpoint: str = ""
    method:   str = ""
    attacks:  int = 0
    severity: str = ""


class TopHostData(BaseModel):
    host:    str = ""
    attacks: int = 0


class FetchTopNDataResponse(BaseModel):
    top_apis:  List[TopApiData]  = Field(default_factory=list)
    top_hosts: List[TopHostData] = Field(default_factory=list)


# -- Threats for a single actor

class FetchThreatsForActorRequest(BaseModel):
    actor: str = ""
    limit: int = 20


class FetchThreatsForActorResponse(BaseModel):
    activities: List[ThreatActorActivityData] = Field(default_factory=list)


# -- Actor counts

class ActorCountsFromActorInfoRequest(BaseModel):
    start_ts:      int = 0
    end_ts:        int = 0
    latest_attack: List[str] = Field(default_factory=list)


class ActorCountsFromActorInfoResponse(BaseModel):
    critical_actors: int = 0
    active_actors:   int = 0


# -- Actor filter

class ThreatActorFilterRequest(BaseModel):
    pass


class ThreatActorFilterResponse(BaseModel):
    sub_categories: List[str] = Field(default_factory=list)
    countries:      List[str] = Field(default_factory=list)
    actor_id:       List[str] = Field(default_factory=list)
    host:           List[str] = Field(default_factory=list)
