from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.storage.repository import ensure_runtime_query


SCHEMA_DIR = REPO_ROOT / "db" / "schemas"
MIGRATION_DIR = REPO_ROOT / "db" / "migrations"


def test_database_runtime_eval_schema_files_exist():
    for filename in ["runtime_schema.sql", "eval_schema.sql", "indexes.sql", "views_runtime.sql", "views_eval.sql"]:
        assert (SCHEMA_DIR / filename).exists(), f"Missing schema file: {filename}"


def test_runtime_schema_allows_repeated_raw_alert_hashes_with_lineage_key():
    runtime_sql = (SCHEMA_DIR / "runtime_schema.sql").read_text(encoding="utf-8").lower()
    migration_sql = (MIGRATION_DIR / "0001_allow_duplicate_raw_alert_hashes.sql").read_text(encoding="utf-8").lower()

    assert "unique (raw_file_sha256, raw_line_number)" in runtime_sql
    assert "raw_alert_sha256 text not null unique" not in runtime_sql
    assert "drop constraint if exists raw_alerts_raw_alert_sha256_key" in migration_sql


def test_runtime_repository_rejects_evaluation_queries():
    ensure_runtime_query("SELECT * FROM safeagentsoc_runtime.v_alerts_runtime")

    try:
        ensure_runtime_query("SELECT * FROM safeagentsoc_eval.ground_truth_labels")
    except ValueError:
        return

    raise AssertionError("Runtime repository allowed an evaluation-only query.")
