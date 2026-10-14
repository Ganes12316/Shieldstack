from dataclasses import dataclass, field
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Finding:
    category: str          # e.g. "hardcoded_secret", "open_cors"
    file_path: str
    line_number: int
    evidence: str           # the actual matched snippet (redacted for secrets)
    severity: Severity
    confidence: float        # 0.0–1.0, phase 5 will refine this
    description: str
    recommended_fix: str