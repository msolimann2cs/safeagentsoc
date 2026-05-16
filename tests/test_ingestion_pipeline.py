from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.ingestion.pipeline import IngestionPaths, int_or_none, none_if_empty


def test_ingestion_paths_are_runtime_artifacts():
    paths = IngestionPaths(
        raw_alerts=Path("raw_alerts_full.jsonl"),
        lineage=Path("raw_alert_lineage.csv"),
        evidence=Path("evidence_reference.csv"),
        normalized=Path("normalized_alerts_v1.jsonl"),
        warnings=Path("normalization_warnings.csv"),
        errors=Path("normalization_errors.csv"),
    )

    assert paths.raw_alerts.name == "raw_alerts_full.jsonl"
    assert paths.normalized.name == "normalized_alerts_v1.jsonl"


def test_ingestion_value_helpers():
    assert none_if_empty("") is None
    assert none_if_empty("x") == "x"
    assert int_or_none("") is None
    assert int_or_none("7") == 7
