"""Core data types for the ForceField SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Action(Enum):
    """Action taken on scanned content."""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REDACT = "redact"


class Severity(Enum):
    """Threat severity level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(Enum):
    """Categories of detected threats."""
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    ROLE_ESCALATION = "role_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    CODE_EXECUTION = "code_execution"
    TOKEN_SMUGGLING = "token_smuggling"
    INDIRECT_INJECTION = "indirect_injection"
    PAYLOAD_SPLITTING = "payload_splitting"
    TEMPLATE_BACKDOOR = "template_backdoor"
    OBFUSCATION = "obfuscation"
    OVERSIZED_PROMPT = "oversized_prompt"
    JAILBREAK = "jailbreak"
    PII_DETECTED = "pii_detected"
    HATE_SPEECH = "hate_speech"
    VIOLENCE = "violence"
    SELF_HARM = "self_harm"
    ILLEGAL_ACTIVITY = "illegal_activity"
    DANGEROUS_INFO = "dangerous_info"
    MALWARE_CODE = "malware_code"
    CREDENTIAL_LEAK = "credential_leak"
    SEXUAL_CONTENT = "sexual_content"
    JAILBREAK_SUCCESS = "jailbreak_success"
    PERSONA_DEVIATION = "persona_deviation"
    TOOL_BLOCKED = "tool_blocked"
    TOOL_NEEDS_APPROVAL = "tool_needs_approval"


class PIIType(Enum):
    """Types of PII detected."""
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    POSTAL_ADDRESS = "postal_address"
    PERSON_NAME = "person_name"
    MEDICAL_RECORD = "medical_record"
    DRIVERS_LICENSE = "drivers_license"
    PASSPORT = "passport"
    BANK_ACCOUNT = "bank_account"
    DATE_OF_BIRTH = "date_of_birth"
    COORDINATES = "coordinates"
    SENSITIVE_URL = "sensitive_url"
    IBAN = "iban"
    TAX_ID = "tax_id"
    VEHICLE_REGISTRATION = "vehicle_registration"


class RedactionStrategy(Enum):
    """How to redact PII."""
    MASK = "mask"
    HASH = "hash"
    TOKENIZE = "tokenize"
    REMOVE = "remove"
    PARTIAL = "partial"


@dataclass
class Threat:
    """A single detected threat."""
    code: str
    category: ThreatCategory
    severity: float
    description: str = ""


@dataclass
class PIIMatch:
    """A single PII detection."""
    pii_type: PIIType
    value: str
    start: int
    end: int
    confidence: float


@dataclass
class ScanResult:
    """Result of scanning a prompt or message."""
    blocked: bool
    action: Action
    risk_score: float
    threats: List[Threat] = field(default_factory=list)
    rules_triggered: List[str] = field(default_factory=list)
    pii_found: List[PIIMatch] = field(default_factory=list)
    sanitized_text: Optional[str] = None
    latency_ms: float = 0.0
    metadata: Dict = field(default_factory=dict)

    @property
    def safe(self) -> bool:
        return not self.blocked

    @property
    def threat_count(self) -> int:
        return len(self.threats)


@dataclass
class RedactResult:
    """Result of PII redaction."""
    text: str
    pii_found: List[PIIMatch] = field(default_factory=list)
    redaction_count: int = 0
    latency_ms: float = 0.0


@dataclass
class ModerationResult:
    """Result of output content moderation."""
    passed: bool
    action: Action
    categories: List[str] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    flags: List[str] = field(default_factory=list)
    modified_text: Optional[str] = None


@dataclass
class ToolEvalResult:
    """Result of tool call security evaluation."""
    allowed: bool
    reason: str
    tool_name: str


@dataclass
class SelftestResult:
    """Result of running the built-in attack selftest."""
    total: int = 0
    detected: int = 0
    missed: int = 0
    detection_rate: float = 0.0
    results: List[Dict] = field(default_factory=list)
