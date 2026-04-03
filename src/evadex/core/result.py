from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time


class PayloadCategory(Enum):
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    SIN = "sin"
    IBAN = "iban"
    AWS_KEY = "aws_key"
    JWT = "jwt"
    EMAIL = "email"
    PHONE = "phone"
    UNKNOWN = "unknown"


class CategoryType(Enum):
    STRUCTURED = "structured"
    HEURISTIC = "heuristic"


CATEGORY_TYPES: dict[PayloadCategory, CategoryType] = {
    PayloadCategory.CREDIT_CARD: CategoryType.STRUCTURED,
    PayloadCategory.SSN:         CategoryType.STRUCTURED,
    PayloadCategory.SIN:         CategoryType.STRUCTURED,
    PayloadCategory.IBAN:        CategoryType.STRUCTURED,
    PayloadCategory.EMAIL:       CategoryType.STRUCTURED,
    PayloadCategory.PHONE:       CategoryType.STRUCTURED,
    PayloadCategory.AWS_KEY:     CategoryType.HEURISTIC,
    PayloadCategory.JWT:         CategoryType.HEURISTIC,
    PayloadCategory.UNKNOWN:     CategoryType.STRUCTURED,
}


class SeverityLevel(Enum):
    PASS = "pass"      # scanner DETECTED the evasion attempt (good — scanner caught it)
    FAIL = "fail"      # scanner did NOT detect (bad — evasion succeeded)
    ERROR = "error"    # adapter error


@dataclass
class Payload:
    value: str
    category: PayloadCategory
    label: str

    def to_dict(self):
        return {
            "value": self.value,
            "category": self.category.value,
            "category_type": CATEGORY_TYPES.get(self.category, CategoryType.STRUCTURED).value,
            "label": self.label,
        }


@dataclass
class Variant:
    value: str
    generator: str          # e.g. "unicode_encoding"
    technique: str          # e.g. "zero_width_injection"
    transform_name: str     # human-readable e.g. "Zero-width space between digits"
    strategy: str = "text"  # "text", "docx", "pdf", "xlsx"

    def to_dict(self):
        return {
            "value": self.value,
            "generator": self.generator,
            "technique": self.technique,
            "transform_name": self.transform_name,
            "strategy": self.strategy,
        }


@dataclass
class ScanResult:
    payload: Payload
    variant: Variant
    detected: bool
    raw_response: dict = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0

    @property
    def severity(self) -> SeverityLevel:
        if self.error:
            return SeverityLevel.ERROR
        return SeverityLevel.PASS if self.detected else SeverityLevel.FAIL

    def to_dict(self):
        return {
            "payload": self.payload.to_dict(),
            "variant": self.variant.to_dict(),
            "detected": self.detected,
            "severity": self.severity.value,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
        }
