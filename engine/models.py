from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class DataClass(str, Enum):
    DIRECT_IDENTIFIER = "DIRECT_IDENTIFIER"
    NATIONAL_ID = "NATIONAL_ID"
    FINANCIAL_INFO = "FINANCIAL_INFO"
    CONTACT_LOCATION = "CONTACT_LOCATION"
    SENSITIVE_ATTRIBUTE = "SENSITIVE_ATTRIBUTE"
    NONE = "NONE"


PII_CLASSES: List[DataClass] = [
    DataClass.DIRECT_IDENTIFIER,
    DataClass.NATIONAL_ID,
    DataClass.FINANCIAL_INFO,
    DataClass.CONTACT_LOCATION,
    DataClass.SENSITIVE_ATTRIBUTE,
]

ALL_CLASSES: List[DataClass] = PII_CLASSES + [DataClass.NONE]

DATA_CLASS_DESCRIPTIONS: Dict[str, str] = {
    "DIRECT_IDENTIFIER": "Full name, email address, phone number, username/handle",
    "NATIONAL_ID": "Government/national ID numbers, passport, SSN, Aadhaar, PAN/tax ID patterns",
    "FINANCIAL_INFO": "Card/account numbers, IBAN/IFSC/routing codes, billing/salary figures",
    "CONTACT_LOCATION": "Street address, city, postal/PIN code, GPS coordinates",
    "SENSITIVE_ATTRIBUTE": "Health/medical notes, biometric hashes, religious/ethnic/demographic fields",
    "NONE": "Operational or non-personal technical fields (IDs, SKUs, counts, timestamps)",
}


class GapStatus(str, Enum):
    COMPLETE = "COMPLETE"
    MISSING_PURPOSE = "MISSING_PURPOSE"
    MISSING_RETENTION = "MISSING_RETENTION"
    MISSING_BOTH = "MISSING_BOTH"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class DetectionRule(BaseModel):
    id: str
    name: str
    data_class: DataClass
    column_pattern: str = ""
    value_pattern: str = ""
    column_weight: float = Field(default=0.6, ge=0.0, le=1.0)
    value_weight: float = Field(default=0.5, ge=0.0, le=1.0)
    min_value_match_ratio: float = Field(default=0.35, ge=0.0, le=1.0)
    enabled: bool = True
    notes: str = ""


class MetadataEntry(BaseModel):
    field_key: str
    source_type: str  # "CSV" | "SQL"
    container: str    # filename or table name
    column: str
    declared_purpose: str = ""
    retention_schedule: str = ""
    owner_team: str = ""


class GroundTruthEntry(BaseModel):
    field_key: str
    source_type: str
    container: str
    column: str
    true_class: DataClass
    rationale: str = ""


class RuleMatchDetail(BaseModel):
    rule_id: str
    rule_name: str
    data_class: DataClass
    column_matched: bool
    value_match_ratio: float
    score: float


class EvidenceRecord(BaseModel):
    field_key: str
    source_type: str  # "CSV" | "SQL"
    container: str
    column: str
    row_count: int
    non_null_count: int
    sample_values: List[str]
    masked_samples: List[str]
    predicted_class: DataClass
    confidence: float
    matched_rules: List[RuleMatchDetail]
    declared_purpose: str
    retention_schedule: str
    owner_team: str
    gap_status: GapStatus
    is_candidate_pii: bool
    review_notice: str = "Technical discovery evidence for human review; not a legal compliance determination."


class ClassMetrics(BaseModel):
    data_class: DataClass
    tp: int
    fp: int
    fn: int
    support: int
    precision: float
    recall: float
    f1: float


class FieldEvaluationRow(BaseModel):
    field_key: str
    source_type: str
    container: str
    column: str
    true_class: DataClass
    predicted_class: DataClass
    confidence: float
    verdict: str  # "MATCH" | "FALSE_POSITIVE" | "FALSE_NEGATIVE" | "MISCLASSIFIED"
    rationale: str = ""


class EvaluationReport(BaseModel):
    evaluated_field_count: int
    unlabelled_field_count: int
    exact_match_count: int
    overall_accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    micro_precision: float
    micro_recall: float
    micro_f1: float
    per_class: List[ClassMetrics]
    field_comparisons: List[FieldEvaluationRow]
    review_notice: str = "Evaluation measures heuristic rule accuracy against human-labelled ground truth; not a legal audit."
