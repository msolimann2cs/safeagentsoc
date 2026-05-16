from __future__ import annotations

import json
from pathlib import Path


SCHEMA_DIR = Path("src/safeagentsoc/schemas")

REQUIRED_SCHEMAS = [
    "normalized_alert.schema.json",
    "raw_alert_reference.schema.json",
    "evidence_reference.schema.json",
    "normalization_warning.schema.json",
    "normalization_error.schema.json",
    "siem_adapter_output.schema.json",
    "runtime_case_reference.schema.json",
    "evaluation_label_reference.schema.json",
]


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def main() -> None:
    missing = []

    for schema_name in REQUIRED_SCHEMAS:
        schema_path = SCHEMA_DIR / schema_name

        if not schema_path.exists():
            missing.append(schema_name)
            continue

        try:
            data = load_json(schema_path)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"[FAIL] Invalid JSON in {schema_path}: {exc}") from exc

        required_top_fields = ["$schema", "$id", "title", "type", "properties"]
        for field in required_top_fields:
            if field not in data:
                raise SystemExit(f"[FAIL] {schema_name} missing top-level field: {field}")

        print(f"[OK] {schema_name}")

    if missing:
        raise SystemExit(f"[FAIL] Missing schemas: {', '.join(missing)}")

    print("[OK] Schema package validation completed.")


if __name__ == "__main__":
    main()
