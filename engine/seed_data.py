from __future__ import annotations

import csv
import json
import random
import sqlite3
from pathlib import Path
from typing import Dict, List

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CSV_DIR = DATA_DIR / "csv"
DB_PATH = DATA_DIR / "privacy_demo.db"
RULES_PATH = DATA_DIR / "rules.json"
METADATA_PATH = DATA_DIR / "metadata_registry.json"
GROUND_TRUTH_PATH = DATA_DIR / "ground_truth.json"


def _make_field_key(source_type: str, container: str, column: str) -> str:
    return f"{source_type}::{container}::{column}"


DEFAULT_RULES: List[Dict] = [
    {
        "id": "rule-direct-email",
        "name": "Direct Identifier: Email Address",
        "data_class": "DIRECT_IDENTIFIER",
        "column_pattern": r"(?:^|_)(?:email|e_mail|email_addr|mail)(?:$|_)",
        "value_pattern": r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
        "column_weight": 0.65,
        "value_weight": 0.70,
        "min_value_match_ratio": 0.4,
        "enabled": True,
        "notes": "Matches email column names and RFC-like email value patterns.",
    },
    {
        "id": "rule-direct-name-phone-handle",
        "name": "Direct Identifier: Name, Phone & Handle",
        "data_class": "DIRECT_IDENTIFIER",
        "column_pattern": r"(?:full_name|employee_name|first_name|last_name|username|phone|mobile|reporter_handle|handle)",
        "value_pattern": r"(?:^@[A-Za-z0-9_]{3,}$|^\+\d[\d\-\s]{7,15}\d$|^\(\d{3}\)\s?\d{3}-\d{4}$)",
        "column_weight": 0.72,
        "value_weight": 0.55,
        "min_value_match_ratio": 0.35,
        "enabled": True,
        "notes": "Detects personal names, phone numbers, and social/support handles.",
    },
    {
        "id": "rule-national-id",
        "name": "National ID: Passport, SSN, Aadhaar & Tax PAN",
        "data_class": "NATIONAL_ID",
        "column_pattern": r"(?:passport|ssn|aadhaar|national_tax_id|national_id|tax_pan|pan_ref|govt_id)",
        "value_pattern": r"(?:^\d{3}-\d{2}-\d{4}$|^\d{4}\s?\d{4}\s?\d{4}$|^[A-Z]{5}\d{4}[A-Z]$|^[A-Z]\d{7}$)",
        "column_weight": 0.70,
        "value_weight": 0.75,
        "min_value_match_ratio": 0.35,
        "enabled": True,
        "notes": "Identifies synthetic SSN, Aadhaar, Indian PAN, and passport number formats.",
    },
    {
        "id": "rule-financial-core",
        "name": "Financial Info: IBAN, Bank Account, Card, Salary & Billing",
        "data_class": "FINANCIAL_INFO",
        "column_pattern": r"(?:iban|ifsc|routing|card|salary|payout|dispute_amt|billing|account)",
        "value_pattern": r"(?:^[A-Z]{2}\d{2}[A-Z0-9]{10,24}$|^[A-Z]{4}0[A-Z0-9]{6}$|^\d{4}-[Xx*]{4}-[Xx*]{4}-\d{4}$|^\$?\d{2,6}\.\d{2}$|^\d{10,18}$)",
        "column_weight": 0.65,
        "value_weight": 0.45,
        "min_value_match_ratio": 0.4,
        "enabled": True,
        "notes": "Broad 'account' keyword intentionally demonstrates a tunable false positive on account_tier.",
    },
    {
        "id": "rule-contact-location",
        "name": "Contact & Location: Street, City, Postal & GPS",
        "data_class": "CONTACT_LOCATION",
        "column_pattern": r"(?:address|street|city|postal|zip|gps|coord|location)",
        "value_pattern": r"(?:^-?\d{1,2}\.\d{3,},\s*-?\d{1,3}\.\d{3,}$|^\d{5,6}$)",
        "column_weight": 0.70,
        "value_weight": 0.40,
        "min_value_match_ratio": 0.4,
        "enabled": True,
        "notes": "Note: excludes 'pin' by default to show a recall gap on residential_pin until tuned.",
    },
    {
        "id": "rule-sensitive-attribute",
        "name": "Sensitive Attribute: Health, Biometric & Religious Data",
        "data_class": "SENSITIVE_ATTRIBUTE",
        "column_pattern": r"(?:medical|health|symptom|biometric|religious|ethnicity|diagnosis|accommodation)",
        "value_pattern": r"(?:^bio_vec_[a-f0-9]+$|allergic|insulin|lumbar|halal|kosher|jain|migraine)",
        "column_weight": 0.72,
        "value_weight": 0.60,
        "min_value_match_ratio": 0.25,
        "enabled": True,
        "notes": "Flags special-category attributes including medical accommodations, health notes, biometrics, and religion.",
    },
]


CUSTOMERS_ROWS = [
    ["CUST-10041", "Aarav Mehta", "aarav.mehta@example.org", "+91-98201-44310", "42 MG Road, Indiranagar", "560038", "4111-XXXX-XXXX-8821", "GOLD", "4", "2026-03-14T09:12:00Z"],
    ["CUST-10042", "Priya Nair", "priya.nair@example.org", "+91-98450-11298", "18 Boat Club Rd, Adyar", "600028", "5500-XXXX-XXXX-1094", "SILVER", "11", "2026-04-02T14:25:00Z"],
    ["CUST-10043", "Liam O'Connor", "liam.oconnor@example.net", "+1-415-555-0148", "742 Evergreen Terrace", "94107", "4012-XXXX-XXXX-3310", "GOLD", "7", "2026-05-19T11:04:00Z"],
    ["CUST-10044", "Ananya Rao", "ananya.rao@example.com", "+91-99001-77654", "9 Jubilee Hills Rd 14", "500033", "5200-XXXX-XXXX-4402", "BASIC", "2", "2026-06-08T16:40:00Z"],
    ["CUST-10045", "Mateo Silva", "mateo.silva@example.org", "+1-512-555-0193", "310 Congress Ave Apt 4B", "78701", "4532-XXXX-XXXX-9915", "SILVER", "9", "2026-06-21T08:55:00Z"],
    ["CUST-10046", "Neha Verma", "neha.verma@example.net", "+91-98111-22309", "27 Golf Links Block C", "110003", "4916-XXXX-XXXX-7741", "GOLD", "15", "2026-07-11T19:30:00Z"],
    ["CUST-10047", "Hannah Brooks", "hannah.brooks@example.com", "+44-7700-900412", "14 Baker St, Marylebone", "10001", "5412-XXXX-XXXX-6038", "BASIC", "1", "2026-08-03T10:15:00Z"],
    ["CUST-10048", "Kabir Joshi", "kabir.joshi@example.org", "+91-97654-33218", "55 Koregaon Park Lane 7", "411001", "4111-XXXX-XXXX-5529", "SILVER", "6", "2026-09-12T12:48:00Z"],
]

EMPLOYEES_ROWS = [
    ["EMP-001", "Rohan Kulkarni", "ABCDE1234F", "DE89370400440532013000", "84500.00", "Bengaluru", "Ergonomic seating - lumbar support", "Engineering", "2024-06-01"],
    ["EMP-002", "Clara Jensen", "942-55-0192", "GB29NWBK60161331926819", "112000.00", "Austin", "None declared", "Security", "2023-11-15"],
    ["EMP-003", "Vikram Desai", "QWERT8812K", "FR1420041010050500013M02606", "96000.00", "Pune", "Insulin refrigeration access", "Data Platform", "2025-01-20"],
    ["EMP-004", "Elena Rostova", "318-44-7721", "NL91ABNA0417164300", "105400.00", "Berlin", "Visual contrast screen reader", "Product", "2022-09-05"],
    ["EMP-005", "Siddharth Iyer", "LMNOP4421R", "ES9121000418450200051332", "78900.00", "Chennai", "None declared", "Operations", "2025-04-10"],
    ["EMP-006", "Maya Lin", "601-29-8843", "CH9300762011623852957", "124000.00", "Seattle", "Migraine low-glare workspace", "Architecture", "2021-08-18"],
]

SUPPORT_TICKETS_ROWS = [
    ["TKT-88201", "@mira_kapoor", "12.9716, 77.5946", "Reported allergic skin reaction after wearable strap use", "SKU-WRB-440", "P2", "$249.00", "OPEN"],
    ["TKT-88202", "@dev_singh99", "19.0760, 72.8777", "Device battery overheated during sleep apnea tracking", "SKU-SEN-210", "P1", "$180.50", "ESCALATED"],
    ["TKT-88203", "@sophia_chen", "30.2672, -97.7431", "No health note; requested firmware reset", "SKU-HUB-105", "P3", "$45.00", "RESOLVED"],
    ["TKT-88204", "@arjun_bose", "28.6139, 77.2090", "Mild wrist rash noted with silicone band", "SKU-WRB-440", "P2", "$125.00", "OPEN"],
    ["TKT-88205", "@nina_patel", "13.0827, 80.2707", "Insulin pump Bluetooth sync timeout inquiry", "SKU-MED-902", "P1", "$310.00", "IN_PROGRESS"],
    ["TKT-88206", "@lucas_meyer", "52.5200, 13.4050", "Shipping box arrived dented, no injury", "SKU-CHG-018", "P4", "$29.99", "RESOLVED"],
]

USERS_SQL_ROWS = [
    ("USR-101", "aarav_m", "aarav.mehta@example.org", "Bengaluru", "Jain vegetarian", "web", 1),
    ("USR-102", "priya_n", "priya.nair@example.org", "Chennai", "None", "ios", 1),
    ("USR-103", "liam_oc", "liam.oconnor@example.net", "San Francisco", "None", "android", 1),
    ("USR-104", "tariq_h", "tariq.hassan@example.org", "Hyderabad", "Halal catering", "web", 1),
    ("USR-105", "miriam_g", "miriam.gold@example.net", "New York", "Kosher", "ios", 1),
    ("USR-106", "neha_v", "neha.verma@example.net", "New Delhi", "None", "web", 0),
]

KYC_SQL_ROWS = [
    ("KYC-7001", "USR-101", "P8841209", "4821 9012 3341", "560038", "bio_vec_a9f3e102", "VERIFIED"),
    ("KYC-7002", "USR-102", "K7719302", "9102 4418 7753", "600028", "bio_vec_77c81d44", "VERIFIED"),
    ("KYC-7003", "USR-103", "M3301948", "123-45-6789", "94107", "bio_vec_11b90e55", "VERIFIED"),
    ("KYC-7004", "USR-104", "N5529011", "7731 8820 1194", "500033", "bio_vec_98d20c31", "PENDING"),
    ("KYC-7005", "USR-105", "R4402819", "456-78-9012", "10001", "bio_vec_44a72f09", "VERIFIED"),
    ("KYC-7006", "USR-106", "T9910422", "6642 3319 8820", "110003", "bio_vec_61e39b80", "VERIFIED"),
]

PAYROLL_SQL_ROWS = [
    ("PAY-9001", "EMP-001", "HDFC0001234", "009182736455", "92500.00", "BNZPA4412K", "2026-10"),
    ("PAY-9002", "EMP-002", "SBIN0004521", "774411229900", "118400.00", "QWERT9981M", "2026-10"),
    ("PAY-9003", "EMP-003", "ICIC0000419", "330192837465", "98200.00", "ASDFG7712L", "2026-10"),
    ("PAY-9004", "EMP-004", "AXIS0002810", "556677889900", "105400.00", "ZXCVB2290P", "2026-11"),
    ("PAY-9005", "EMP-005", "KKBK0000912", "112233445566", "78900.00", "POIUY6614N", "2026-11"),
    ("PAY-9006", "EMP-006", "UTIB0001105", "998877665544", "124000.00", "MNBVC3381Q", "2026-11"),
]


DEFAULT_METADATA: List[Dict] = [
    # customers.csv
    {"field_key": _make_field_key("CSV", "customers.csv", "customer_id"), "source_type": "CSV", "container": "customers.csv", "column": "customer_id", "declared_purpose": "Primary customer surrogate key", "retention_schedule": "7 years post account closure", "owner_team": "Commerce Core"},
    {"field_key": _make_field_key("CSV", "customers.csv", "full_name"), "source_type": "CSV", "container": "customers.csv", "column": "full_name", "declared_purpose": "Customer account identity & order fulfillment", "retention_schedule": "7 years post last order", "owner_team": "Commerce Core"},
    {"field_key": _make_field_key("CSV", "customers.csv", "email_addr"), "source_type": "CSV", "container": "customers.csv", "column": "email_addr", "declared_purpose": "Transactional receipts & security notices", "retention_schedule": "", "owner_team": "Growth & Messaging"},
    {"field_key": _make_field_key("CSV", "customers.csv", "phone_number"), "source_type": "CSV", "container": "customers.csv", "column": "phone_number", "declared_purpose": "", "retention_schedule": "3 years post last interaction", "owner_team": "Customer Support"},
    {"field_key": _make_field_key("CSV", "customers.csv", "street_address"), "source_type": "CSV", "container": "customers.csv", "column": "street_address", "declared_purpose": "Physical parcel delivery", "retention_schedule": "5 years for tax & logistics audit", "owner_team": "Fulfillment Ops"},
    {"field_key": _make_field_key("CSV", "customers.csv", "postal_code"), "source_type": "CSV", "container": "customers.csv", "column": "postal_code", "declared_purpose": "Carrier zone routing & tax calculation", "retention_schedule": "", "owner_team": "Fulfillment Ops"},
    {"field_key": _make_field_key("CSV", "customers.csv", "card_last4_token"), "source_type": "CSV", "container": "customers.csv", "column": "card_last4_token", "declared_purpose": "Payment reconciliation & chargeback lookup", "retention_schedule": "7 years statutory ledger", "owner_team": "Payments"},
    {"field_key": _make_field_key("CSV", "customers.csv", "account_tier"), "source_type": "CSV", "container": "customers.csv", "column": "account_tier", "declared_purpose": "Loyalty tier entitlement", "retention_schedule": "Account lifetime", "owner_team": "Commerce Core"},
    # employees.csv
    {"field_key": _make_field_key("CSV", "employees.csv", "employee_name"), "source_type": "CSV", "container": "employees.csv", "column": "employee_name", "declared_purpose": "HR employee directory & payroll", "retention_schedule": "Employment + 5 years", "owner_team": "People Ops"},
    {"field_key": _make_field_key("CSV", "employees.csv", "national_tax_id"), "source_type": "CSV", "container": "employees.csv", "column": "national_tax_id", "declared_purpose": "Statutory income tax withholding", "retention_schedule": "8 years statutory", "owner_team": "Payroll"},
    {"field_key": _make_field_key("CSV", "employees.csv", "bank_iban"), "source_type": "CSV", "container": "employees.csv", "column": "bank_iban", "declared_purpose": "", "retention_schedule": "", "owner_team": "Payroll"},
    {"field_key": _make_field_key("CSV", "employees.csv", "annual_salary_usd"), "source_type": "CSV", "container": "employees.csv", "column": "annual_salary_usd", "declared_purpose": "Compensation administration", "retention_schedule": "8 years statutory", "owner_team": "People Ops"},
    {"field_key": _make_field_key("CSV", "employees.csv", "home_city"), "source_type": "CSV", "container": "employees.csv", "column": "home_city", "declared_purpose": "Workforce regional office planning", "retention_schedule": "", "owner_team": "People Ops"},
    {"field_key": _make_field_key("CSV", "employees.csv", "medical_accommodation"), "source_type": "CSV", "container": "employees.csv", "column": "medical_accommodation", "declared_purpose": "", "retention_schedule": "", "owner_team": "Workplace Safety"},
    # support_tickets.csv
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "reporter_handle"), "source_type": "CSV", "container": "support_tickets.csv", "column": "reporter_handle", "declared_purpose": "Support ticket requester attribution", "retention_schedule": "2 years post ticket closure", "owner_team": "Customer Support"},
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "gps_coordinates"), "source_type": "CSV", "container": "support_tickets.csv", "column": "gps_coordinates", "declared_purpose": "Field dispatch & telemetry debugging", "retention_schedule": "", "owner_team": "Hardware Ops"},
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "health_symptom_note"), "source_type": "CSV", "container": "support_tickets.csv", "column": "health_symptom_note", "declared_purpose": "Product safety incident triage", "retention_schedule": "", "owner_team": "Product Safety"},
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "billing_dispute_amt"), "source_type": "CSV", "container": "support_tickets.csv", "column": "billing_dispute_amt", "declared_purpose": "", "retention_schedule": "5 years audit", "owner_team": "Billing Support"},
    # SQL: users
    {"field_key": _make_field_key("SQL", "users", "username"), "source_type": "SQL", "container": "users", "column": "username", "declared_purpose": "User authentication & login display", "retention_schedule": "Account lifetime + 90 days", "owner_team": "Identity"},
    {"field_key": _make_field_key("SQL", "users", "email"), "source_type": "SQL", "container": "users", "column": "email", "declared_purpose": "Account recovery & verification", "retention_schedule": "Account lifetime + 90 days", "owner_team": "Identity"},
    {"field_key": _make_field_key("SQL", "users", "geo_city"), "source_type": "SQL", "container": "users", "column": "geo_city", "declared_purpose": "", "retention_schedule": "1 year", "owner_team": "Analytics"},
    {"field_key": _make_field_key("SQL", "users", "religious_observance_pref"), "source_type": "SQL", "container": "users", "column": "religious_observance_pref", "declared_purpose": "", "retention_schedule": "", "owner_team": "Events"},
    # SQL: kyc_records
    {"field_key": _make_field_key("SQL", "kyc_records", "passport_number"), "source_type": "SQL", "container": "kyc_records", "column": "passport_number", "declared_purpose": "Identity verification check", "retention_schedule": "5 years post closure", "owner_team": "Trust & Safety"},
    {"field_key": _make_field_key("SQL", "kyc_records", "govt_ssn_or_aadhaar"), "source_type": "SQL", "container": "kyc_records", "column": "govt_ssn_or_aadhaar", "declared_purpose": "Regulatory KYC verification", "retention_schedule": "", "owner_team": "Trust & Safety"},
    {"field_key": _make_field_key("SQL", "kyc_records", "residential_pin"), "source_type": "SQL", "container": "kyc_records", "column": "residential_pin", "declared_purpose": "Address postal verification", "retention_schedule": "5 years post closure", "owner_team": "Trust & Safety"},
    {"field_key": _make_field_key("SQL", "kyc_records", "biometric_liveness_hash"), "source_type": "SQL", "container": "kyc_records", "column": "biometric_liveness_hash", "declared_purpose": "Anti-spoofing liveness verification", "retention_schedule": "", "owner_team": "Trust & Safety"},
    # SQL: payroll_ledger
    {"field_key": _make_field_key("SQL", "payroll_ledger", "routing_ifsc_code"), "source_type": "SQL", "container": "payroll_ledger", "column": "routing_ifsc_code", "declared_purpose": "Salary bank clearing", "retention_schedule": "8 years statutory", "owner_team": "Payroll"},
    {"field_key": _make_field_key("SQL", "payroll_ledger", "bank_account_no"), "source_type": "SQL", "container": "payroll_ledger", "column": "bank_account_no", "declared_purpose": "", "retention_schedule": "8 years statutory", "owner_team": "Payroll"},
    {"field_key": _make_field_key("SQL", "payroll_ledger", "net_payout_inr"), "source_type": "SQL", "container": "payroll_ledger", "column": "net_payout_inr", "declared_purpose": "Payroll disbursement ledger", "retention_schedule": "8 years statutory", "owner_team": "Payroll"},
    {"field_key": _make_field_key("SQL", "payroll_ledger", "tax_pan_ref"), "source_type": "SQL", "container": "payroll_ledger", "column": "tax_pan_ref", "declared_purpose": "", "retention_schedule": "", "owner_team": "Payroll"},
]


DEFAULT_GROUND_TRUTH: List[Dict] = [
    # customers.csv (10 columns)
    {"field_key": _make_field_key("CSV", "customers.csv", "customer_id"), "source_type": "CSV", "container": "customers.csv", "column": "customer_id", "true_class": "NONE", "rationale": "Internal surrogate identifier, not direct human PII."},
    {"field_key": _make_field_key("CSV", "customers.csv", "full_name"), "source_type": "CSV", "container": "customers.csv", "column": "full_name", "true_class": "DIRECT_IDENTIFIER", "rationale": "Legal/display personal name."},
    {"field_key": _make_field_key("CSV", "customers.csv", "email_addr"), "source_type": "CSV", "container": "customers.csv", "column": "email_addr", "true_class": "DIRECT_IDENTIFIER", "rationale": "Personal email address."},
    {"field_key": _make_field_key("CSV", "customers.csv", "phone_number"), "source_type": "CSV", "container": "customers.csv", "column": "phone_number", "true_class": "DIRECT_IDENTIFIER", "rationale": "Personal telephone number."},
    {"field_key": _make_field_key("CSV", "customers.csv", "street_address"), "source_type": "CSV", "container": "customers.csv", "column": "street_address", "true_class": "CONTACT_LOCATION", "rationale": "Residential street address."},
    {"field_key": _make_field_key("CSV", "customers.csv", "postal_code"), "source_type": "CSV", "container": "customers.csv", "column": "postal_code", "true_class": "CONTACT_LOCATION", "rationale": "Postal delivery code."},
    {"field_key": _make_field_key("CSV", "customers.csv", "card_last4_token"), "source_type": "CSV", "container": "customers.csv", "column": "card_last4_token", "true_class": "FINANCIAL_INFO", "rationale": "Masked payment card token."},
    {"field_key": _make_field_key("CSV", "customers.csv", "account_tier"), "source_type": "CSV", "container": "customers.csv", "column": "account_tier", "true_class": "NONE", "rationale": "Operational loyalty tier label (GOLD/SILVER/BASIC), not financial account data."},
    {"field_key": _make_field_key("CSV", "customers.csv", "order_count"), "source_type": "CSV", "container": "customers.csv", "column": "order_count", "true_class": "NONE", "rationale": "Aggregate integer order count."},
    {"field_key": _make_field_key("CSV", "customers.csv", "created_at"), "source_type": "CSV", "container": "customers.csv", "column": "created_at", "true_class": "NONE", "rationale": "System creation timestamp."},
    # employees.csv (9 columns)
    {"field_key": _make_field_key("CSV", "employees.csv", "emp_code"), "source_type": "CSV", "container": "employees.csv", "column": "emp_code", "true_class": "NONE", "rationale": "Internal employee surrogate code."},
    {"field_key": _make_field_key("CSV", "employees.csv", "employee_name"), "source_type": "CSV", "container": "employees.csv", "column": "employee_name", "true_class": "DIRECT_IDENTIFIER", "rationale": "Employee full name."},
    {"field_key": _make_field_key("CSV", "employees.csv", "national_tax_id"), "source_type": "CSV", "container": "employees.csv", "column": "national_tax_id", "true_class": "NATIONAL_ID", "rationale": "National tax / SSN identifier."},
    {"field_key": _make_field_key("CSV", "employees.csv", "bank_iban"), "source_type": "CSV", "container": "employees.csv", "column": "bank_iban", "true_class": "FINANCIAL_INFO", "rationale": "International Bank Account Number."},
    {"field_key": _make_field_key("CSV", "employees.csv", "annual_salary_usd"), "source_type": "CSV", "container": "employees.csv", "column": "annual_salary_usd", "true_class": "FINANCIAL_INFO", "rationale": "Individual compensation figure."},
    {"field_key": _make_field_key("CSV", "employees.csv", "home_city"), "source_type": "CSV", "container": "employees.csv", "column": "home_city", "true_class": "CONTACT_LOCATION", "rationale": "Employee city of residence."},
    {"field_key": _make_field_key("CSV", "employees.csv", "medical_accommodation"), "source_type": "CSV", "container": "employees.csv", "column": "medical_accommodation", "true_class": "SENSITIVE_ATTRIBUTE", "rationale": "Health/medical workplace accommodation details."},
    {"field_key": _make_field_key("CSV", "employees.csv", "department"), "source_type": "CSV", "container": "employees.csv", "column": "department", "true_class": "NONE", "rationale": "Organizational business unit."},
    {"field_key": _make_field_key("CSV", "employees.csv", "hire_date"), "source_type": "CSV", "container": "employees.csv", "column": "hire_date", "true_class": "NONE", "rationale": "Employment start date."},
    # support_tickets.csv (8 columns)
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "ticket_id"), "source_type": "CSV", "container": "support_tickets.csv", "column": "ticket_id", "true_class": "NONE", "rationale": "Support ticket reference ID."},
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "reporter_handle"), "source_type": "CSV", "container": "support_tickets.csv", "column": "reporter_handle", "true_class": "DIRECT_IDENTIFIER", "rationale": "User handle identifying the ticket submitter."},
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "gps_coordinates"), "source_type": "CSV", "container": "support_tickets.csv", "column": "gps_coordinates", "true_class": "CONTACT_LOCATION", "rationale": "Precise latitude/longitude coordinates."},
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "health_symptom_note"), "source_type": "CSV", "container": "support_tickets.csv", "column": "health_symptom_note", "true_class": "SENSITIVE_ATTRIBUTE", "rationale": "Free-text health/symptom description."},
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "product_sku"), "source_type": "CSV", "container": "support_tickets.csv", "column": "product_sku", "true_class": "NONE", "rationale": "Hardware SKU identifier."},
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "severity_level"), "source_type": "CSV", "container": "support_tickets.csv", "column": "severity_level", "true_class": "NONE", "rationale": "Operational triage priority."},
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "billing_dispute_amt"), "source_type": "CSV", "container": "support_tickets.csv", "column": "billing_dispute_amt", "true_class": "FINANCIAL_INFO", "rationale": "Customer monetary dispute amount."},
    {"field_key": _make_field_key("CSV", "support_tickets.csv", "resolution_status"), "source_type": "CSV", "container": "support_tickets.csv", "column": "resolution_status", "true_class": "NONE", "rationale": "Workflow status."},
    # SQL: users (7 columns)
    {"field_key": _make_field_key("SQL", "users", "user_id"), "source_type": "SQL", "container": "users", "column": "user_id", "true_class": "NONE", "rationale": "Internal surrogate user key."},
    {"field_key": _make_field_key("SQL", "users", "username"), "source_type": "SQL", "container": "users", "column": "username", "true_class": "DIRECT_IDENTIFIER", "rationale": "Account username handle."},
    {"field_key": _make_field_key("SQL", "users", "email"), "source_type": "SQL", "container": "users", "column": "email", "true_class": "DIRECT_IDENTIFIER", "rationale": "Primary user email."},
    {"field_key": _make_field_key("SQL", "users", "geo_city"), "source_type": "SQL", "container": "users", "column": "geo_city", "true_class": "CONTACT_LOCATION", "rationale": "User geographic city."},
    {"field_key": _make_field_key("SQL", "users", "religious_observance_pref"), "source_type": "SQL", "container": "users", "column": "religious_observance_pref", "true_class": "SENSITIVE_ATTRIBUTE", "rationale": "Religious dietary/observance attribute."},
    {"field_key": _make_field_key("SQL", "users", "signup_channel"), "source_type": "SQL", "container": "users", "column": "signup_channel", "true_class": "NONE", "rationale": "Client platform channel (web/ios/android)."},
    {"field_key": _make_field_key("SQL", "users", "is_active"), "source_type": "SQL", "container": "users", "column": "is_active", "true_class": "NONE", "rationale": "Boolean operational flag."},
    # SQL: kyc_records (7 columns)
    {"field_key": _make_field_key("SQL", "kyc_records", "kyc_id"), "source_type": "SQL", "container": "kyc_records", "column": "kyc_id", "true_class": "NONE", "rationale": "Internal KYC record ID."},
    {"field_key": _make_field_key("SQL", "kyc_records", "user_id"), "source_type": "SQL", "container": "kyc_records", "column": "user_id", "true_class": "NONE", "rationale": "Foreign key reference to users."},
    {"field_key": _make_field_key("SQL", "kyc_records", "passport_number"), "source_type": "SQL", "container": "kyc_records", "column": "passport_number", "true_class": "NATIONAL_ID", "rationale": "Government passport identifier."},
    {"field_key": _make_field_key("SQL", "kyc_records", "govt_ssn_or_aadhaar"), "source_type": "SQL", "container": "kyc_records", "column": "govt_ssn_or_aadhaar", "true_class": "NATIONAL_ID", "rationale": "National identity / SSN / Aadhaar number."},
    {"field_key": _make_field_key("SQL", "kyc_records", "residential_pin"), "source_type": "SQL", "container": "kyc_records", "column": "residential_pin", "true_class": "CONTACT_LOCATION", "rationale": "Postal PIN code of residence."},
    {"field_key": _make_field_key("SQL", "kyc_records", "biometric_liveness_hash"), "source_type": "SQL", "container": "kyc_records", "column": "biometric_liveness_hash", "true_class": "SENSITIVE_ATTRIBUTE", "rationale": "Biometric template/liveness hash."},
    {"field_key": _make_field_key("SQL", "kyc_records", "verification_status"), "source_type": "SQL", "container": "kyc_records", "column": "verification_status", "true_class": "NONE", "rationale": "Operational KYC workflow status."},
    # SQL: payroll_ledger (7 columns)
    {"field_key": _make_field_key("SQL", "payroll_ledger", "ledger_id"), "source_type": "SQL", "container": "payroll_ledger", "column": "ledger_id", "true_class": "NONE", "rationale": "Ledger primary key."},
    {"field_key": _make_field_key("SQL", "payroll_ledger", "emp_code"), "source_type": "SQL", "container": "payroll_ledger", "column": "emp_code", "true_class": "NONE", "rationale": "Employee foreign key."},
    {"field_key": _make_field_key("SQL", "payroll_ledger", "routing_ifsc_code"), "source_type": "SQL", "container": "payroll_ledger", "column": "routing_ifsc_code", "true_class": "FINANCIAL_INFO", "rationale": "Bank routing / IFSC branch code."},
    {"field_key": _make_field_key("SQL", "payroll_ledger", "bank_account_no"), "source_type": "SQL", "container": "payroll_ledger", "column": "bank_account_no", "true_class": "FINANCIAL_INFO", "rationale": "Personal bank account number."},
    {"field_key": _make_field_key("SQL", "payroll_ledger", "net_payout_inr"), "source_type": "SQL", "container": "payroll_ledger", "column": "net_payout_inr", "true_class": "FINANCIAL_INFO", "rationale": "Net salary payout amount."},
    {"field_key": _make_field_key("SQL", "payroll_ledger", "tax_pan_ref"), "source_type": "SQL", "container": "payroll_ledger", "column": "tax_pan_ref", "true_class": "NATIONAL_ID", "rationale": "National Permanent Account Number (PAN) tax ID."},
    {"field_key": _make_field_key("SQL", "payroll_ledger", "pay_period"), "source_type": "SQL", "container": "payroll_ledger", "column": "pay_period", "true_class": "NONE", "rationale": "Accounting month string."},
]


def _write_csv(path: Path, headers: List[str], rows: List[List[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def _init_sqlite_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                geo_city TEXT,
                religious_observance_pref TEXT,
                signup_channel TEXT,
                is_active INTEGER
            )
            """
        )
        cur.executemany(
            "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)",
            USERS_SQL_ROWS,
        )

        cur.execute(
            """
            CREATE TABLE kyc_records (
                kyc_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                passport_number TEXT,
                govt_ssn_or_aadhaar TEXT,
                residential_pin TEXT,
                biometric_liveness_hash TEXT,
                verification_status TEXT
            )
            """
        )
        cur.executemany(
            "INSERT INTO kyc_records VALUES (?, ?, ?, ?, ?, ?, ?)",
            KYC_SQL_ROWS,
        )

        cur.execute(
            """
            CREATE TABLE payroll_ledger (
                ledger_id TEXT PRIMARY KEY,
                emp_code TEXT NOT NULL,
                routing_ifsc_code TEXT,
                bank_account_no TEXT,
                net_payout_inr TEXT,
                tax_pan_ref TEXT,
                pay_period TEXT
            )
            """
        )
        cur.executemany(
            "INSERT INTO payroll_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
            PAYROLL_SQL_ROWS,
        )
        conn.commit()
    finally:
        conn.close()


def ensure_seeded(force_reset: bool = False) -> None:
    """Create initial synthetic CSVs, SQLite database, rules, metadata, and ground truth."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CSV_DIR.mkdir(parents=True, exist_ok=True)

    if force_reset:
        for csv_file in CSV_DIR.glob("*.csv"):
            csv_file.unlink()

    customers_path = CSV_DIR / "customers.csv"
    if force_reset or not customers_path.exists():
        _write_csv(
            customers_path,
            [
                "customer_id",
                "full_name",
                "email_addr",
                "phone_number",
                "street_address",
                "postal_code",
                "card_last4_token",
                "account_tier",
                "order_count",
                "created_at",
            ],
            CUSTOMERS_ROWS,
        )

    employees_path = CSV_DIR / "employees.csv"
    if force_reset or not employees_path.exists():
        _write_csv(
            employees_path,
            [
                "emp_code",
                "employee_name",
                "national_tax_id",
                "bank_iban",
                "annual_salary_usd",
                "home_city",
                "medical_accommodation",
                "department",
                "hire_date",
            ],
            EMPLOYEES_ROWS,
        )

    tickets_path = CSV_DIR / "support_tickets.csv"
    if force_reset or not tickets_path.exists():
        _write_csv(
            tickets_path,
            [
                "ticket_id",
                "reporter_handle",
                "gps_coordinates",
                "health_symptom_note",
                "product_sku",
                "severity_level",
                "billing_dispute_amt",
                "resolution_status",
            ],
            SUPPORT_TICKETS_ROWS,
        )

    if force_reset or not DB_PATH.exists():
        _init_sqlite_db(DB_PATH)

    if force_reset or not RULES_PATH.exists():
        RULES_PATH.write_text(json.dumps(DEFAULT_RULES, indent=2), encoding="utf-8")

    if force_reset or not METADATA_PATH.exists():
        METADATA_PATH.write_text(json.dumps(DEFAULT_METADATA, indent=2), encoding="utf-8")

    if force_reset or not GROUND_TRUTH_PATH.exists():
        GROUND_TRUTH_PATH.write_text(json.dumps(DEFAULT_GROUND_TRUTH, indent=2), encoding="utf-8")


def generate_synthetic_csv(filename: str | None = None, rows: int = 8) -> str:
    """Generate a fresh synthetic CSV dataset on demand covering all 5 PII classes + NONE."""
    CSV_DIR.mkdir(parents=True, exist_ok=True)
    if not filename:
        existing = sorted(CSV_DIR.glob("synthetic_batch_*.csv"))
        idx = len(existing) + 1
        filename = f"synthetic_batch_{idx}.csv"
    if not filename.endswith(".csv"):
        filename = f"{filename}.csv"
    safe_name = Path(filename).name

    first_names = ["Sanya", "Karan", "Zara", "Nikhil", "Elena", "Omar", "Maya", "Devon", "Ishaan", "Claire"]
    last_names = ["Kapoor", "Deshmukh", "Patel", "Menon", "Weber", "Alvarez", "Lin", "Brooks", "Sharma", "Kim"]
    cities = ["Bengaluru", "Mumbai", "Austin", "Berlin", "Seattle", "Toronto", "Pune", "Singapore"]
    conditions = ["Asthma inhaler", "Peanut allergy", "None", "Lactose intolerance", "Insulin pen"]
    statuses = ["ACTIVE", "PENDING", "ARCHIVED"]

    headers = [
        "record_id",
        "full_name",
        "email_addr",
        "passport_number",
        "bank_iban",
        "home_city",
        "medical_note",
        "batch_status",
    ]
    data_rows: List[List[str]] = []
    for i in range(rows):
        fn = random.choice(first_names)
        ln = random.choice(last_names)
        num = random.randint(100, 999)
        data_rows.append(
            [
                f"SYN-{1000 + i}",
                f"{fn} {ln}",
                f"{fn.lower()}.{ln.lower()}{num}@example.org",
                f"P{random.randint(1000000, 9999999)}",
                f"DE{random.randint(10, 99)}37040044{random.randint(1000000000, 9999999999)}",
                random.choice(cities),
                random.choice(conditions),
                random.choice(statuses),
            ]
        )

    _write_csv(CSV_DIR / safe_name, headers, data_rows)
    return safe_name
