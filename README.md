# PS-019: Personal-Data Discovery & Privacy Evidence Inventory

A self-contained web application that scans **synthetic structured CSV files** and an **embedded SQLite database** to identify candidate personal-data fields across **five predefined personal-data classes**, links discovered fields to **declared business purposes and retention schedules**, flags **missing metadata as Evidence Gaps**, and evaluates heuristic detection rules against a **human-labelled ground-truth set** using per-class **Precision, Recall, and F1**.

> **Scope & Evidence Notice**: All outputs represent **technical discovery evidence for human review**. This tool does **not** make legal compliance rulings, determine lawful basis automatically, or perform universal data-flow inference.

---

## Features

1. **Five Predefined Personal-Data Classes (+ Operational `NONE`)**:
   - `DIRECT_IDENTIFIER` (full name, email, phone number, username/handle)
   - `NATIONAL_ID` (passport, SSN, Aadhaar, national tax ID / PAN patterns)
   - `FINANCIAL_INFO` (card token, IBAN, IFSC/routing, bank account number, salary/billing)
   - `CONTACT_LOCATION` (street address, city, postal/PIN code, GPS coordinates)
   - `SENSITIVE_ATTRIBUTE` (medical accommodations, health symptom notes, biometric hashes, religious preferences)
   - `NONE` (non-personal operational fields such as surrogate IDs, SKUs, counts, timestamps)

2. **Multi-Source Discovery (`CSV` + `SQLite`)**:
   - Pre-seeded synthetic CSVs: `data/csv/customers.csv`, `employees.csv`, `support_tickets.csv`
   - Pre-seeded SQLite database (`data/privacy_demo.db`): `users`, `kyc_records`, `payroll_ledger`
   - Upload custom `.csv` files or generate fresh synthetic CSV datasets directly from the UI

3. **Configurable Rules Engine**:
   - View, edit, toggle, add, delete, and reset regex/keyword rules (`column_pattern`, `value_pattern`, `column_weight`, `value_weight`, `min_value_match_ratio`) and immediately re-scan all sources.

4. **Purpose & Retention Metadata Registry + Gap Report**:
   - Inline editing of `declared_purpose`, `retention_schedule`, and `owner_team`
   - Live flagging of `MISSING_PURPOSE`, `MISSING_RETENTION`, and `MISSING_BOTH` gaps

5. **Precision & Recall Lab**:
   - Computes per-class TP, FP, FN, Precision, Recall, F1, Macro/Micro averages, and overall accuracy against `data/ground_truth.json`
   - Includes a disagreement inspector (`FALSE_POSITIVE`, `FALSE_NEGATIVE`, `MISCLASSIFIED`) and inline ground-truth editing
   - Ships with two realistic tunable edge cases (`account_tier` FP and `residential_pin` FN) so you can demonstrate Precision/Recall tuning live

6. **Exports & Pseudocode Walkthrough**:
   - Download JSON or CSV exports for **Evidence Inventory**, **Gap Report**, and **Precision/Recall Evaluation**
   - Built-in **Architecture & Pseudocode** tab for demo walkthroughs

---

## Running the Application

```powershell
# Optional: install dependencies if not already present
python -m pip install -r requirements.txt

# Start the web server (seeds data automatically on first launch)
python app.py
```

Then open **http://127.0.0.1:8000** in your browser.

---

## Running Tests

```powershell
python -m unittest discover -s tests -v
```
