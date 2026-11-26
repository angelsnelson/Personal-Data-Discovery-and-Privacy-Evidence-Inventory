from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Literal

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from engine.evaluator import evaluate_predictions, load_ground_truth, save_ground_truth
from engine.models import (
    ALL_CLASSES,
    DATA_CLASS_DESCRIPTIONS,
    DataClass,
    DetectionRule,
    GapStatus,
    GroundTruthEntry,
    MetadataEntry,
)
from engine.scanner import (
    list_data_sources,
    load_metadata,
    load_rules,
    run_scan,
    save_metadata,
    save_rules,
)
from engine.seed_data import (
    CSV_DIR,
    DEFAULT_RULES,
    RULES_PATH,
    ensure_seeded,
    generate_synthetic_csv,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="PS-019: Personal-Data Discovery & Privacy Evidence Inventory",
    version="1.0.0",
    description="Technical discovery evidence inventory for human review. Does not make legal compliance rulings.",
)

STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class MetadataUpdatePayload(BaseModel):
    field_key: str
    source_type: str
    container: str
    column: str
    declared_purpose: str = ""
    retention_schedule: str = ""
    owner_team: str = ""


class GroundTruthUpdatePayload(BaseModel):
    field_key: str
    source_type: str
    container: str
    column: str
    true_class: DataClass
    rationale: str = ""


class GenerateCsvPayload(BaseModel):
    filename: str | None = None
    rows: int = 8


def _build_full_state() -> Dict:
    ensure_seeded(force_reset=False)
    rules = load_rules()
    metadata_map = load_metadata()
    gt_map = load_ground_truth()
    inventory = run_scan(rules=rules, metadata_map=metadata_map)
    evaluation = evaluate_predictions(inventory, ground_truth_map=gt_map)
    sources = list_data_sources()

    gap_records = [
        r
        for r in inventory
        if r.is_candidate_pii and r.gap_status != GapStatus.COMPLETE
    ]
    class_counts = {cls.value: 0 for cls in ALL_CLASSES}
    for r in inventory:
        class_counts[r.predicted_class.value] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope_guardrail": {
            "banner": "TECHNICAL DISCOVERY EVIDENCE FOR HUMAN REVIEW — NOT A LEGAL COMPLIANCE DETERMINATION",
            "does": [
                "Scans structured CSV files and SQLite database tables for candidate personal-data fields across 5 classes.",
                "Links discovered fields to declared business purposes and retention schedules from the metadata registry.",
                "Flags missing or incomplete purpose/retention metadata as Evidence Gaps.",
                "Evaluates heuristic rules against a human-labelled ground-truth set using per-class Precision, Recall, and F1.",
            ],
            "does_not": [
                "Does NOT issue legal compliance rulings (e.g. GDPR/DPDP/CCPA pass/fail).",
                "Does NOT automatically determine lawful basis, consent validity, or cross-border transfer legality.",
                "Does NOT perform universal data-flow inference across external APIs, logs, or unstructured blobs.",
                "Does NOT replace human privacy/security review or Data Protection Officer sign-off.",
            ],
        },
        "class_descriptions": DATA_CLASS_DESCRIPTIONS,
        "summary": {
            "total_fields": len(inventory),
            "candidate_pii_fields": sum(1 for r in inventory if r.is_candidate_pii),
            "non_pii_fields": sum(1 for r in inventory if not r.is_candidate_pii),
            "csv_sources": sum(1 for s in sources if s["source_type"] == "CSV"),
            "sql_tables": sum(1 for s in sources if s["source_type"] == "SQL"),
            "gap_count": len(gap_records),
            "missing_purpose_count": sum(1 for r in gap_records if r.gap_status == GapStatus.MISSING_PURPOSE),
            "missing_retention_count": sum(1 for r in gap_records if r.gap_status == GapStatus.MISSING_RETENTION),
            "missing_both_count": sum(1 for r in gap_records if r.gap_status == GapStatus.MISSING_BOTH),
            "class_counts": class_counts,
        },
        "inventory": [r.model_dump(mode="json") for r in inventory],
        "gaps": [r.model_dump(mode="json") for r in gap_records],
        "evaluation": evaluation.model_dump(mode="json"),
        "rules": [r.model_dump(mode="json") for r in rules],
        "sources": sources,
        "ground_truth": [g.model_dump(mode="json") for g in gt_map.values()],
    }


@app.get("/")
def serve_index() -> FileResponse:
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend index.html not found.")
    return FileResponse(str(index_path))


@app.get("/api/state")
def get_state() -> JSONResponse:
    return JSONResponse(_build_full_state())


@app.post("/api/scan")
def trigger_scan() -> JSONResponse:
    return JSONResponse(_build_full_state())


@app.put("/api/metadata")
def upsert_metadata(payload: MetadataUpdatePayload) -> JSONResponse:
    ensure_seeded(force_reset=False)
    metadata_map = load_metadata()
    entry = MetadataEntry(**payload.model_dump())
    metadata_map[entry.field_key] = entry
    save_metadata(metadata_map)
    return JSONResponse(_build_full_state())


@app.put("/api/ground-truth")
def upsert_ground_truth(payload: GroundTruthUpdatePayload) -> JSONResponse:
    ensure_seeded(force_reset=False)
    gt_map = load_ground_truth()
    entry = GroundTruthEntry(**payload.model_dump())
    gt_map[entry.field_key] = entry
    save_ground_truth(gt_map)
    return JSONResponse(_build_full_state())


@app.put("/api/rules")
def update_rules(rules: List[DetectionRule]) -> JSONResponse:
    ensure_seeded(force_reset=False)
    save_rules(rules)
    return JSONResponse(_build_full_state())


@app.post("/api/rules/reset")
def reset_rules() -> JSONResponse:
    ensure_seeded(force_reset=False)
    RULES_PATH.write_text(json.dumps(DEFAULT_RULES, indent=2), encoding="utf-8")
    return JSONResponse(_build_full_state())


@app.post("/api/sources/csv/generate")
def api_generate_csv(payload: GenerateCsvPayload) -> JSONResponse:
    ensure_seeded(force_reset=False)
    rows = max(3, min(payload.rows, 50))
    created_name = generate_synthetic_csv(filename=payload.filename, rows=rows)
    state = _build_full_state()
    state["last_action"] = f"Generated synthetic CSV dataset: {created_name}"
    return JSONResponse(state)


@app.post("/api/sources/csv/upload")
def api_upload_csv(file: UploadFile = File(...)) -> JSONResponse:
    ensure_seeded(force_reset=False)
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are supported.")
    safe_name = Path(file.filename).name
    content_bytes = file.file.read()
    try:
        decoded = content_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="CSV file must be UTF-8 encoded.") from exc

    reader = csv.reader(io.StringIO(decoded))
    rows = list(reader)
    if len(rows) < 2 or not rows[0]:
        raise HTTPException(status_code=400, detail="CSV must include a header row and at least one data row.")

    target = CSV_DIR / safe_name
    target.write_text(decoded, encoding="utf-8")
    state = _build_full_state()
    state["last_action"] = f"Uploaded CSV dataset: {safe_name}"
    return JSONResponse(state)


@app.delete("/api/sources/csv/{filename}")
def api_delete_csv(filename: str) -> JSONResponse:
    ensure_seeded(force_reset=False)
    safe_name = Path(filename).name
    target = CSV_DIR / safe_name
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"CSV file '{safe_name}' not found.")
    target.unlink()
    state = _build_full_state()
    state["last_action"] = f"Removed CSV dataset: {safe_name}"
    return JSONResponse(state)


@app.post("/api/reset")
def api_reset_demo() -> JSONResponse:
    ensure_seeded(force_reset=True)
    state = _build_full_state()
    state["last_action"] = "Reset demo datasets, SQLite DB, rules, metadata, and ground truth to defaults."
    return JSONResponse(state)


def _rows_to_csv(headers: List[str], rows: List[List[str]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(headers)
    writer.writerows(rows)
    return buf.getvalue()


@app.get("/api/export/{artifact_type}")
def export_artifact(
    artifact_type: Literal["inventory", "gaps", "evaluation"],
    format: Literal["json", "csv"] = Query(default="json"),
) -> Response:
    state = _build_full_state()
    notice = state["scope_guardrail"]["banner"]

    if artifact_type == "inventory":
        records = state["inventory"]
        if format == "json":
            payload = {
                "artifact": "privacy_evidence_inventory",
                "generated_at": state["generated_at"],
                "scope_notice": notice,
                "records": records,
            }
            return PlainTextResponse(
                json.dumps(payload, indent=2),
                media_type="application/json",
                headers={"Content-Disposition": 'attachment; filename="privacy_evidence_inventory.json"'},
            )
        headers = [
            "field_key",
            "source_type",
            "container",
            "column",
            "predicted_class",
            "confidence",
            "matched_rule_names",
            "masked_samples",
            "declared_purpose",
            "retention_schedule",
            "owner_team",
            "gap_status",
            "review_notice",
        ]
        rows = [
            [
                r["field_key"],
                r["source_type"],
                r["container"],
                r["column"],
                r["predicted_class"],
                str(r["confidence"]),
                "; ".join(m["rule_name"] for m in r["matched_rules"]),
                " | ".join(r["masked_samples"]),
                r["declared_purpose"],
                r["retention_schedule"],
                r["owner_team"],
                r["gap_status"],
                r["review_notice"],
            ]
            for r in records
        ]
        return PlainTextResponse(
            _rows_to_csv(headers, rows),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="privacy_evidence_inventory.csv"'},
        )

    if artifact_type == "gaps":
        gaps = state["gaps"]
        if format == "json":
            payload = {
                "artifact": "missing_metadata_evidence_gap_report",
                "generated_at": state["generated_at"],
                "scope_notice": notice,
                "gap_count": len(gaps),
                "gaps": gaps,
            }
            return PlainTextResponse(
                json.dumps(payload, indent=2),
                media_type="application/json",
                headers={"Content-Disposition": 'attachment; filename="evidence_gap_report.json"'},
            )
        headers = [
            "field_key",
            "source_type",
            "container",
            "column",
            "predicted_class",
            "gap_status",
            "declared_purpose",
            "retention_schedule",
            "owner_team",
            "review_notice",
        ]
        rows = [
            [
                r["field_key"],
                r["source_type"],
                r["container"],
                r["column"],
                r["predicted_class"],
                r["gap_status"],
                r["declared_purpose"],
                r["retention_schedule"],
                r["owner_team"],
                r["review_notice"],
            ]
            for r in gaps
        ]
        return PlainTextResponse(
            _rows_to_csv(headers, rows),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="evidence_gap_report.csv"'},
        )

    # evaluation
    ev = state["evaluation"]
    if format == "json":
        payload = {
            "artifact": "precision_recall_evaluation",
            "generated_at": state["generated_at"],
            "scope_notice": notice,
            "evaluation": ev,
        }
        return PlainTextResponse(
            json.dumps(payload, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="precision_recall_evaluation.json"'},
        )
    headers = [
        "data_class",
        "tp",
        "fp",
        "fn",
        "support",
        "precision",
        "recall",
        "f1",
    ]
    rows = [
        [
            m["data_class"],
            str(m["tp"]),
            str(m["fp"]),
            str(m["fn"]),
            str(m["support"]),
            str(m["precision"]),
            str(m["recall"]),
            str(m["f1"]),
        ]
        for m in ev["per_class"]
    ]
    return PlainTextResponse(
        _rows_to_csv(headers, rows),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="precision_recall_evaluation.csv"'},
    )


if __name__ == "__main__":
    import uvicorn

    ensure_seeded(force_reset=False)
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
