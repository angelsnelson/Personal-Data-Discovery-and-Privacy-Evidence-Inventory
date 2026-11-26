from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .models import (
    ALL_CLASSES,
    ClassMetrics,
    DataClass,
    EvaluationReport,
    EvidenceRecord,
    FieldEvaluationRow,
    GroundTruthEntry,
    PII_CLASSES,
)
from .seed_data import GROUND_TRUTH_PATH


def load_ground_truth(gt_path: Path = GROUND_TRUTH_PATH) -> Dict[str, GroundTruthEntry]:
    raw = json.loads(gt_path.read_text(encoding="utf-8"))
    entries = [GroundTruthEntry(**item) for item in raw]
    return {entry.field_key: entry for entry in entries}


def save_ground_truth(entries: Dict[str, GroundTruthEntry], gt_path: Path = GROUND_TRUTH_PATH) -> None:
    ordered = sorted(entries.values(), key=lambda e: (e.source_type, e.container, e.column))
    gt_path.write_text(
        json.dumps([e.model_dump(mode="json") for e in ordered], indent=2),
        encoding="utf-8",
    )


def evaluate_predictions(
    evidence_records: List[EvidenceRecord],
    ground_truth_map: Dict[str, GroundTruthEntry] | None = None,
) -> EvaluationReport:
    """Compute per-class Precision, Recall, F1, TP/FP/FN, and field-level comparisons."""
    gt_map = ground_truth_map if ground_truth_map is not None else load_ground_truth()

    evaluated_pairs: List[tuple[EvidenceRecord, GroundTruthEntry]] = []
    unlabelled_count = 0
    for rec in evidence_records:
        gt = gt_map.get(rec.field_key)
        if gt is None:
            unlabelled_count += 1
        else:
            evaluated_pairs.append((rec, gt))

    per_class: List[ClassMetrics] = []
    for cls in ALL_CLASSES:
        tp = sum(1 for rec, gt in evaluated_pairs if rec.predicted_class == cls and gt.true_class == cls)
        fp = sum(1 for rec, gt in evaluated_pairs if rec.predicted_class == cls and gt.true_class != cls)
        fn = sum(1 for rec, gt in evaluated_pairs if rec.predicted_class != cls and gt.true_class == cls)
        support = tp + fn

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        per_class.append(
            ClassMetrics(
                data_class=cls,
                tp=tp,
                fp=fp,
                fn=fn,
                support=support,
                precision=round(precision, 4),
                recall=round(recall, 4),
                f1=round(f1, 4),
            )
        )

    # Macro and micro averages are computed across the 5 Personal-Data Classes
    pii_metrics = [m for m in per_class if m.data_class in PII_CLASSES]
    macro_precision = sum(m.precision for m in pii_metrics) / len(pii_metrics) if pii_metrics else 0.0
    macro_recall = sum(m.recall for m in pii_metrics) / len(pii_metrics) if pii_metrics else 0.0
    macro_f1 = sum(m.f1 for m in pii_metrics) / len(pii_metrics) if pii_metrics else 0.0

    total_tp = sum(m.tp for m in pii_metrics)
    total_fp = sum(m.fp for m in pii_metrics)
    total_fn = sum(m.fn for m in pii_metrics)
    micro_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    micro_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    micro_f1 = (
        2 * micro_precision * micro_recall / (micro_precision + micro_recall)
        if (micro_precision + micro_recall) > 0
        else 0.0
    )

    exact_matches = sum(1 for rec, gt in evaluated_pairs if rec.predicted_class == gt.true_class)
    overall_accuracy = exact_matches / len(evaluated_pairs) if evaluated_pairs else 0.0

    field_comparisons: List[FieldEvaluationRow] = []
    for rec, gt in evaluated_pairs:
        if rec.predicted_class == gt.true_class:
            verdict = "MATCH"
        elif gt.true_class == DataClass.NONE and rec.predicted_class != DataClass.NONE:
            verdict = "FALSE_POSITIVE"
        elif gt.true_class != DataClass.NONE and rec.predicted_class == DataClass.NONE:
            verdict = "FALSE_NEGATIVE"
        else:
            verdict = "MISCLASSIFIED"

        field_comparisons.append(
            FieldEvaluationRow(
                field_key=rec.field_key,
                source_type=rec.source_type,
                container=rec.container,
                column=rec.column,
                true_class=gt.true_class,
                predicted_class=rec.predicted_class,
                confidence=rec.confidence,
                verdict=verdict,
                rationale=gt.rationale,
            )
        )

    return EvaluationReport(
        evaluated_field_count=len(evaluated_pairs),
        unlabelled_field_count=unlabelled_count,
        exact_match_count=exact_matches,
        overall_accuracy=round(overall_accuracy, 4),
        macro_precision=round(macro_precision, 4),
        macro_recall=round(macro_recall, 4),
        macro_f1=round(macro_f1, 4),
        micro_precision=round(micro_precision, 4),
        micro_recall=round(micro_recall, 4),
        micro_f1=round(micro_f1, 4),
        per_class=per_class,
        field_comparisons=field_comparisons,
    )
