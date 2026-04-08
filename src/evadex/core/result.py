from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PayloadCategory(Enum):
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    SIN = "sin"
    IBAN = "iban"
    SWIFT_BIC = "swift_bic"
    ABA_ROUTING = "aba_routing"
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    US_PASSPORT = "us_passport"
    AU_TFN = "au_tfn"
    DE_TAX_ID = "de_tax_id"
    FR_INSEE = "fr_insee"
    GITHUB_TOKEN = "github_token"
    STRIPE_KEY = "stripe_key"
    SLACK_TOKEN = "slack_token"
    CLASSIFICATION = "classification"
    AWS_KEY = "aws_key"
    JWT = "jwt"
    EMAIL = "email"
    PHONE = "phone"
    # Canadian regional IDs
    CA_RAMQ = "ca_ramq"
    CA_ONTARIO_HEALTH = "ca_ontario_health"
    CA_BC_CARECARD = "ca_bc_carecard"
    CA_AB_HEALTH = "ca_ab_health"
    CA_QC_DRIVERS = "ca_qc_drivers"
    CA_ON_DRIVERS = "ca_on_drivers"
    CA_BC_DRIVERS = "ca_bc_drivers"
    CA_PASSPORT = "ca_passport"
    UNKNOWN = "unknown"


class CategoryType(Enum):
    STRUCTURED = "structured"
    HEURISTIC = "heuristic"


CATEGORY_TYPES: dict[PayloadCategory, CategoryType] = {
    PayloadCategory.CREDIT_CARD:    CategoryType.STRUCTURED,
    PayloadCategory.SSN:            CategoryType.STRUCTURED,
    PayloadCategory.SIN:            CategoryType.STRUCTURED,
    PayloadCategory.IBAN:           CategoryType.STRUCTURED,
    PayloadCategory.SWIFT_BIC:      CategoryType.STRUCTURED,
    PayloadCategory.ABA_ROUTING:    CategoryType.STRUCTURED,
    PayloadCategory.BITCOIN:        CategoryType.STRUCTURED,
    PayloadCategory.ETHEREUM:       CategoryType.STRUCTURED,
    PayloadCategory.US_PASSPORT:    CategoryType.STRUCTURED,
    PayloadCategory.AU_TFN:         CategoryType.STRUCTURED,
    PayloadCategory.DE_TAX_ID:      CategoryType.STRUCTURED,
    PayloadCategory.FR_INSEE:       CategoryType.STRUCTURED,
    PayloadCategory.GITHUB_TOKEN:   CategoryType.HEURISTIC,
    PayloadCategory.STRIPE_KEY:     CategoryType.HEURISTIC,
    PayloadCategory.SLACK_TOKEN:    CategoryType.HEURISTIC,
    PayloadCategory.CLASSIFICATION: CategoryType.HEURISTIC,
    PayloadCategory.EMAIL:          CategoryType.STRUCTURED,
    PayloadCategory.PHONE:          CategoryType.STRUCTURED,
    PayloadCategory.AWS_KEY:        CategoryType.HEURISTIC,
    PayloadCategory.JWT:            CategoryType.HEURISTIC,
    PayloadCategory.CA_RAMQ:           CategoryType.STRUCTURED,
    PayloadCategory.CA_ONTARIO_HEALTH: CategoryType.STRUCTURED,
    PayloadCategory.CA_BC_CARECARD:    CategoryType.STRUCTURED,
    PayloadCategory.CA_AB_HEALTH:      CategoryType.STRUCTURED,
    PayloadCategory.CA_QC_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_ON_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_BC_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.UNKNOWN:        CategoryType.STRUCTURED,
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


@dataclass(frozen=True)
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
            "raw_response": self.raw_response,
        }
