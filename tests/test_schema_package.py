from pathlib import Path
import json


SCHEMA_DIR = Path("src/safeagentsoc/schemas")


def test_required_schema_files_exist():
    required = [
        "normalized_alert.schema.json",
        "raw_alert_reference.schema.json",
        "evidence_reference.schema.json",
        "normalization_warning.schema.json",
        "normalization_error.schema.json",
        "siem_adapter_output.schema.json",
        "runtime_case_reference.schema.json",
        "evaluation_label_reference.schema.json",
    ]

    for filename in required:
        assert (SCHEMA_DIR / filename).exists(), f"Missing schema: {filename}"


def test_schema_files_are_valid_json():
    for path in SCHEMA_DIR.glob("*.schema.json"):
        with path.open("r", encoding="utf-8") as file:
            json.load(file)


def test_normalized_alert_schema_excludes_ground_truth_fields():
    schema_path = SCHEMA_DIR / "normalized_alert.schema.json"

    with schema_path.open("r", encoding="utf-8") as file:
        raw_text = file.read().lower()

    forbidden_terms = [
        "true_positive",
        "false_positive",
        "expected_conclusion",
        "gold_case",
        "casebook_answer",
    ]

    for term in forbidden_terms:
        assert term not in raw_text, f"Runtime schema leaks forbidden term: {term}"


def test_evaluation_label_schema_contains_label_fields():
    schema_path = SCHEMA_DIR / "evaluation_label_reference.schema.json"

    with schema_path.open("r", encoding="utf-8") as file:
        raw_text = file.read().lower()

    assert "label" in raw_text
    assert "event_role" in raw_text
    assert "evaluation-only" in raw_text or "evaluation only" in raw_text
