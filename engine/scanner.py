from __future__ import annotations

import csv
import json
import re
import sqlite3
from pathlib import Path
from typing import Dict, List, Tuple

from .models import (
    DataClass,
    DetectionRule,
    EvidenceRecord,
    GapStatus,
    MetadataEntry,
    RuleMatchDetail,
)
from .seed_data import CSV_DIR, DB_PATH, METADATA_PATH, RULES_PATH


def load_rules(rules_path: Path = RULES_PATH) -> List[DetectionRule]:
    raw = json.loads(rules_path.read_text(encoding="utf-8"))
    return [DetectionRule(**item) for item in raw]


def save_rules(rules: List[DetectionRule], rules_path: Path = RULES_PATH) -> None:
    rules_path.write_text(
        json.dumps([r.model_dump(mode="json") for r in rules], indent=2),
        encoding="utf-8",
    )


def load_metadata(metadata_path: Path = METADATA_PATH) -> Dict[str, MetadataEntry]:
    raw = json.loads(metadata_path.read_text(encoding="utf-8"))
    entries = [MetadataEntry(**item) for item in raw]
    return {entry.field_key: entry for entry in entries}


def save_metadata(entries: Dict[str, MetadataEntry], metadata_path: Path = METADATA_PATH) -> None:
    ordered = sorted(entries.values(), key=lambda e: (e.source_type, e.container, e.column))
    metadata_path.write_text(
        json.dumps([e.model_dump(mode="json") for e in ordered], indent=2),
        encoding="utf-8",
    )


def mask_sample_value(value: str, data_class: DataClass) -> str:
    """Return a masked preview of synthetic sample values for safer evidence display."""
    v = value.strip()
    if not v:
        return ""
    if data_class == DataClass.NONE:
        return v[:42] + ("..." if len(v) > 42 else "")
    if "@" in v:
        local, domain = v.split("@", 1)
        head = local[:2] if len(local) >= 2 else local[:1]
        return f"{head}***@{domain}"
    if len(v) <= 4:
        return "*" * len(v)
    if data_class in (DataClass.NATIONAL_ID, DataClass.FINANCIAL_INFO):
        return f"{'*' * max(2, len(v) - 4)}{v[-4:]}"
    if data_class == DataClass.SENSITIVE_ATTRIBUTE:
        return f"{v[:6]}*** [redacted:{len(v)}c]"
    return f"{v[:3]}***{v[-2:]}" if len(v) > 6 else f"{v[:2]}***"


def _compute_gap_status(
    predicted_class: DataClass,
    declared_purpose: str,
    retention_schedule: str,
) -> GapStatus:
    has_purpose = bool(declared_purpose.strip())
    has_retention = bool(retention_schedule.strip())
    if predicted_class == DataClass.NONE and not has_purpose and not has_retention:
        return GapStatus.NOT_APPLICABLE
    if has_purpose and has_retention:
        return GapStatus.COMPLETE
    if not has_purpose and not has_retention:
        return GapStatus.MISSING_BOTH
    if not has_purpose:
        return GapStatus.MISSING_PURPOSE
    return GapStatus.MISSING_RETENTION


def _read_csv_sources(csv_dir: Path = CSV_DIR) -> List[Tuple[str, str, List[str], List[Dict[str, str]]]]:
    sources: List[Tuple[str, str, List[str], List[Dict[str, str]]]] = []
    if not csv_dir.exists():
        return sources
    for path in sorted(csv_dir.glob("*.csv")):
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            headers = list(reader.fieldnames or [])
            rows = [dict(r) for r in reader]
        sources.append(("CSV", path.name, headers, rows))
    return sources


def _read_sql_sources(db_path: Path = DB_PATH) -> List[Tuple[str, str, List[str], List[Dict[str, str]]]]:
    sources: List[Tuple[str, str, List[str], List[Dict[str, str]]]] = []
    if not db_path.exists():
        return sources
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        tables = [
            row[0]
            for row in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        for table in tables:
            cols_info = cur.execute(f'PRAGMA table_info("{table}")').fetchall()
            headers = [c[1] for c in cols_info]
            raw_rows = cur.execute(f'SELECT * FROM "{table}"').fetchall()
            rows = [{h: "" if r[h] is None else str(r[h]) for h in headers} for r in raw_rows]
            sources.append(("SQL", table, headers, rows))
    finally:
        conn.close()
    return sources


def _compile_regex(pattern: str) -> re.Pattern[str] | None:
    if not pattern or not pattern.strip():
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None


def classify_column(
    column: str,
    values: List[str],
    rules: List[DetectionRule],
    threshold: float = 0.45,
) -> Tuple[DataClass, float, List[RuleMatchDetail]]:
    """Evaluate all enabled rules against a column name and its non-null sample values."""
    non_null = [v.strip() for v in values if v is not None and str(v).strip() != ""]
    class_scores: Dict[DataClass, float] = {}
    matches: List[RuleMatchDetail] = []

    for rule in rules:
        if not rule.enabled:
            continue
        col_re = _compile_regex(rule.column_pattern)
        val_re = _compile_regex(rule.value_pattern)

        col_matched = bool(col_re and col_re.search(column))
        val_ratio = 0.0
        if val_re and non_null:
            hit_count = sum(1 for v in non_null if val_re.search(v))
            val_ratio = hit_count / len(non_null)

        val_triggered = val_ratio >= rule.min_value_match_ratio and val_ratio > 0.0
        score = 0.0
        if col_matched:
            score += rule.column_weight
        if val_triggered:
            score += rule.value_weight * val_ratio

        score = min(round(score, 4), 1.0)
        if col_matched or val_triggered:
            matches.append(
                RuleMatchDetail(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    data_class=rule.data_class,
                    column_matched=col_matched,
                    value_match_ratio=round(val_ratio, 3),
                    score=score,
                )
            )
            prev = class_scores.get(rule.data_class, 0.0)
            # Combine independent rule confidence smoothly without exceeding 1.0
            class_scores[rule.data_class] = min(1.0, round(max(prev, score) + 0.15 * min(prev, score), 4))

    matches.sort(key=lambda m: m.score, reverse=True)
    if not class_scores:
        return DataClass.NONE, 0.0, matches

    best_class, best_score = max(class_scores.items(), key=lambda kv: kv[1])
    if best_score < threshold:
        return DataClass.NONE, round(best_score, 3), matches
    return best_class, round(best_score, 3), matches


def run_scan(
    rules: List[DetectionRule] | None = None,
    metadata_map: Dict[str, MetadataEntry] | None = None,
    csv_dir: Path = CSV_DIR,
    db_path: Path = DB_PATH,
) -> List[EvidenceRecord]:
    """Scan all CSV files and SQLite tables and join findings with metadata registry."""
    active_rules = rules if rules is not None else load_rules()
    active_meta = metadata_map if metadata_map is not None else load_metadata()

    sources = _read_csv_sources(csv_dir) + _read_sql_sources(db_path)
    records: List[EvidenceRecord] = []

    for source_type, container, headers, rows in sources:
        for col in headers:
            col_values = [row.get(col, "") for row in rows]
            non_null = [v for v in col_values if str(v).strip() != ""]
            sample_vals = non_null[:3]

            predicted_class, confidence, matched_rules = classify_column(col, col_values, active_rules)
            masked_vals = [mask_sample_value(str(v), predicted_class) for v in sample_vals]

            field_key = f"{source_type}::{container}::{col}"
            meta = active_meta.get(field_key)
            declared_purpose = meta.declared_purpose if meta else ""
            retention_schedule = meta.retention_schedule if meta else ""
            owner_team = meta.owner_team if meta else ""

            gap_status = _compute_gap_status(predicted_class, declared_purpose, retention_schedule)
            records.append(
                EvidenceRecord(
                    field_key=field_key,
                    source_type=source_type,
                    container=container,
                    column=col,
                    row_count=len(rows),
                    non_null_count=len(non_null),
                    sample_values=sample_vals,
                    masked_samples=masked_vals,
                    predicted_class=predicted_class,
                    confidence=confidence,
                    matched_rules=matched_rules,
                    declared_purpose=declared_purpose,
                    retention_schedule=retention_schedule,
                    owner_team=owner_team,
                    gap_status=gap_status,
                    is_candidate_pii=predicted_class != DataClass.NONE,
                )
            )

    return records


def list_data_sources(csv_dir: Path = CSV_DIR, db_path: Path = DB_PATH) -> List[Dict]:
    """Return metadata & sample preview rows for all CSV files and SQLite tables."""
    sources = _read_csv_sources(csv_dir) + _read_sql_sources(db_path)
    output: List[Dict] = []
    for source_type, container, headers, rows in sources:
        output.append(
            {
                "source_type": source_type,
                "container": container,
                "column_count": len(headers),
                "row_count": len(rows),
                "columns": headers,
                "preview_rows": rows[:4],
            }
        )
    return output
