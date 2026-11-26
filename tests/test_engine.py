from __future__ import annotations

import io
import json
import unittest

from starlette.datastructures import UploadFile

import app as fastapi_app
from engine.evaluator import evaluate_predictions
from engine.models import DataClass, GapStatus, PII_CLASSES
from engine.scanner import load_rules, run_scan
from engine.seed_data import ensure_seeded


def _run_sync_coro(coro):
    """Drive a coroutine that awaits only immediate/threadpool-free futures."""
    try:
        while True:
            coro.send(None)
    except StopIteration as exc:
        return exc.value


class PrivacyScannerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_seeded(force_reset=True)

    def tearDown(self) -> None:
        ensure_seeded(force_reset=True)

    def test_all_five_pii_classes_and_both_sources_scanned(self) -> None:
        records = run_scan()
        self.assertGreater(len(records), 40)

        source_types = {r.source_type for r in records}
        self.assertEqual(source_types, {"CSV", "SQL"})

        containers = {r.container for r in records}
        self.assertIn("customers.csv", containers)
        self.assertIn("employees.csv", containers)
        self.assertIn("support_tickets.csv", containers)
        self.assertIn("users", containers)
        self.assertIn("kyc_records", containers)
        self.assertIn("payroll_ledger", containers)

        found_classes = {r.predicted_class for r in records}
        for cls in PII_CLASSES:
            self.assertIn(cls, found_classes, f"Missing predicted class: {cls}")
        self.assertIn(DataClass.NONE, found_classes)

    def test_metadata_gap_flagging_and_live_resolution(self) -> None:
        records = run_scan()
        gaps = [r for r in records if r.is_candidate_pii and r.gap_status != GapStatus.COMPLETE]
        gap_statuses = {g.gap_status for g in gaps}
        self.assertIn(GapStatus.MISSING_PURPOSE, gap_statuses)
        self.assertIn(GapStatus.MISSING_RETENTION, gap_statuses)
        self.assertIn(GapStatus.MISSING_BOTH, gap_statuses)

        # Resolve bank_iban (MISSING_BOTH) via API handler
        res = fastapi_app.upsert_metadata(
            fastapi_app.MetadataUpdatePayload(
                field_key="CSV::employees.csv::bank_iban",
                source_type="CSV",
                container="employees.csv",
                column="bank_iban",
                declared_purpose="Direct payroll deposit",
                retention_schedule="8 years statutory",
                owner_team="Payroll",
            )
        )
        self.assertEqual(res.status_code, 200)
        state = json.loads(res.body.decode("utf-8"))
        iban_rec = next(r for r in state["inventory"] if r["field_key"] == "CSV::employees.csv::bank_iban")
        self.assertEqual(iban_rec["gap_status"], "COMPLETE")

    def test_precision_recall_and_rule_tuning_effect(self) -> None:
        records = run_scan()
        ev = evaluate_predictions(records)
        self.assertGreater(ev.evaluated_field_count, 40)
        self.assertGreater(ev.macro_precision, 0.75)
        self.assertGreater(ev.macro_recall, 0.75)

        # Verify intentional FP (account_tier) and FN (residential_pin) exist in baseline
        verdicts = {row.field_key: row.verdict for row in ev.field_comparisons}
        self.assertEqual(verdicts["CSV::customers.csv::account_tier"], "FALSE_POSITIVE")
        self.assertEqual(verdicts["SQL::kyc_records::residential_pin"], "FALSE_NEGATIVE")

        # Tune rules: tighten financial account keyword & add 'pin' to contact/location
        rules = load_rules()
        for r in rules:
            if r.id == "rule-financial-core":
                r.column_pattern = r.column_pattern.replace("|account", "|bank_account")
            if r.id == "rule-contact-location":
                r.column_pattern = r.column_pattern.replace("location)", "location|pin)")

        res = fastapi_app.update_rules(rules)
        self.assertEqual(res.status_code, 200)
        tuned_state = json.loads(res.body.decode("utf-8"))
        tuned_verdicts = {
            row["field_key"]: row["verdict"] for row in tuned_state["evaluation"]["field_comparisons"]
        }
        self.assertEqual(tuned_verdicts["CSV::customers.csv::account_tier"], "MATCH")
        self.assertEqual(tuned_verdicts["SQL::kyc_records::residential_pin"], "MATCH")
        self.assertEqual(tuned_state["evaluation"]["overall_accuracy"], 1.0)

    def test_ground_truth_update_and_scope_guardrail(self) -> None:
        res = fastapi_app.upsert_ground_truth(
            fastapi_app.GroundTruthUpdatePayload(
                field_key="CSV::customers.csv::account_tier",
                source_type="CSV",
                container="customers.csv",
                column="account_tier",
                true_class=DataClass.FINANCIAL_INFO,
                rationale="Re-labelled during test.",
            )
        )
        self.assertEqual(res.status_code, 200)
        state = json.loads(res.body.decode("utf-8"))
        self.assertIn("NOT A LEGAL COMPLIANCE", state["scope_guardrail"]["banner"])
        verdicts = {row["field_key"]: row["verdict"] for row in state["evaluation"]["field_comparisons"]}
        self.assertEqual(verdicts["CSV::customers.csv::account_tier"], "MATCH")

    def test_csv_generation_upload_and_exports(self) -> None:
        gen_res = fastapi_app.api_generate_csv(fastapi_app.GenerateCsvPayload(filename="unit_gen.csv", rows=5))
        self.assertEqual(gen_res.status_code, 200)
        gen_state = json.loads(gen_res.body.decode("utf-8"))
        self.assertIn("unit_gen.csv", {s["container"] for s in gen_state["sources"]})

        upload_file = UploadFile(
            filename="uploaded_test.csv",
            file=io.BytesIO(b"id,email_addr,salary_usd\n1,test@example.org,75000\n"),
        )
        upload_res = fastapi_app.api_upload_csv(upload_file)
        self.assertEqual(upload_res.status_code, 200)
        upload_state = json.loads(upload_res.body.decode("utf-8"))
        self.assertIn("uploaded_test.csv", {s["container"] for s in upload_state["sources"]})

        for artifact in ("inventory", "gaps", "evaluation"):
            for fmt in ("json", "csv"):
                exp = fastapi_app.export_artifact(artifact, format=fmt)
                self.assertEqual(exp.status_code, 200)
                text = exp.body.decode("utf-8")
                self.assertGreater(len(text), 20)


if __name__ == "__main__":
    unittest.main()
