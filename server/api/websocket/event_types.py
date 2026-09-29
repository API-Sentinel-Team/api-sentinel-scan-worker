"""
WebSocket event types for the API Security Engine dashboard.
Ensures consistency between Backend push and Frontend consumption.
"""

from enum import Enum

class WSEventType(str, Enum):
    VULNERABILITY_FOUND = "VULNERABILITY_FOUND"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_PROGRESS = "SCAN_PROGRESS"
    THREAT_ACTOR_FLAGGED = "THREAT_ACTOR_FLAGGED"
    TRAFFIC_INGESTED = "TRAFFIC_INGESTED"
    IP_BLOCKED = "IP_BLOCKED"
    ENDPOINT_BLOCKED = "ENDPOINT_BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
