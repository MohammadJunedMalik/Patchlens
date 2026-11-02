from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Optional

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        return str(self.value)

class Confidence(str, Enum):
    TENTATIVE = "TENTATIVE"
    FIRM = "FIRM"
    CERTAIN = "CERTAIN"

    def __str__(self) -> str:
        return str(self.value)

class FindingStatus(str, Enum):
    NEW = "NEW"
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"

    def __str__(self) -> str:
        return str(self.value)

def compute_fingerprint(check_id: str, url: str, target_key: str="") -> str:
    check = check_id.strip()
    clean_url  = url.strip().lower()
    key = target_key.strip().lower()
    identity = f"{check}:{clean_url}:{key}"
    fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return fingerprint


@dataclass
class Finding:
    check_id: str
    title: str 
    url: str
    severity: Severity | str
    confidence: Confidence | str
    description: str 
    evidence: str
    expected: str
    actual: str 
    recommendation: str

    target_key: str = ""
    references: list[str] = field(default_factory=list)
    status: FindingStatus | str = FindingStatus.NEW
    scan_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    fingerprint: str = ""
    finding_id: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.upper())

        if isinstance(self.confidence, str):
            self.confidence = Confidence(self.confidence.upper())

        if isinstance(self.status, str):
            self.status = FindingStatus(self.status.upper())

        if not isinstance(self.references, list):
            self.references = list(self.references)
        
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(self.check_id, self.url, self.target_key)

        if not self.finding_id:
            self.finding_id = self.fingerprint   

    def to_dict(self) -> dict[str, Any]:
            data = asdict(self)
            data["severity"] = self.severity.value
            data["confidence"] = self.confidence.value
            data["status"] = self.status.value
            return data 
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
            return cls(**data)




