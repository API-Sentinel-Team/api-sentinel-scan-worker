from .auth_anomaly_detector import AuthAnomalyDetector
from .behavioral_baseline_detector import BehavioralBaselineDetector
from .bfla_detector import BFLADetector
from .bola_detector import BOLADetector
from .bot_detector import BotDetector
from .burst_detector import BurstDetector
from .exfiltration_detector import ExfiltrationDetector
from .injection_detector import InjectionDetector
from .resource_abuse_detector import ResourceAbuseDetector
from .schema_validator import SchemaValidatorDetector
from .sensitive_data_detector import SensitiveDataDetector
from .ssrf_detector import SSRFDetector

ALL_DETECTORS = [
    InjectionDetector,
    SSRFDetector,
    BOLADetector,
    BFLADetector,
    ResourceAbuseDetector,
    BotDetector,
    AuthAnomalyDetector,
    ExfiltrationDetector,
    BurstDetector,
    BehavioralBaselineDetector,
    SensitiveDataDetector,
    SchemaValidatorDetector,
]

__all__ = [
    "ALL_DETECTORS",
    "InjectionDetector",
    "SSRFDetector",
    "BOLADetector",
    "BFLADetector",
    "ResourceAbuseDetector",
    "BotDetector",
    "AuthAnomalyDetector",
    "ExfiltrationDetector",
    "BurstDetector",
    "BehavioralBaselineDetector",
    "SensitiveDataDetector",
    "SchemaValidatorDetector",
]
