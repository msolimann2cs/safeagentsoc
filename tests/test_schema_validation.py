from pathlib import Path
import json


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO_ROOT / "src" / "safeagentsoc" / "schemas"


def test_required_phase3_schema_files_exist_and_load():
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
        path = SCHEMA_DIR / filename
        assert path.exists(), f"Missing schema: {filename}"
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
        assert data["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_runtime_normalized_schema_does_not_define_answer_key_terms():
    text = (SCHEMA_DIR / "normalized_alert.schema.json").read_text(encoding="utf-8").lower()

    for term in ["ground_truth", "expected_conclusion", "casebook_answer", "event_role", "true_positive", "false_positive"]:
        assert term not in text
