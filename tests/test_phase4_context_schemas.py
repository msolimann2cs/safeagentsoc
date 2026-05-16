from pathlib import Path
import json
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT.parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.context_validator import validate_schema_package
from safeagentsoc.context.schemas import REQUIRED_CONTEXT_SCHEMA_FILES


SCHEMA_DIR = WORKSPACE_ROOT / "03_data" / "context" / "schemas"


def test_phase4_required_context_schemas_exist_and_load():
    errors = validate_schema_package(SCHEMA_DIR)
    assert errors == []

    for filename in REQUIRED_CONTEXT_SCHEMA_FILES:
        with (SCHEMA_DIR / filename).open("r", encoding="utf-8") as file:
            data = json.load(file)
        assert data["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert data["type"] == "object"


def test_context_enriched_alert_schema_preserves_alert_and_evidence_ids():
    with (SCHEMA_DIR / "context_enriched_alert.schema.json").open("r", encoding="utf-8") as file:
        data = json.load(file)

    assert "alert_uid" in data["required"]
    assert "evidence_id" in data["required"]
    assert "business_risk" in data["required"]
    assert "analyst_priority" in data["required"]
    assert "context_metadata" in data["required"]
