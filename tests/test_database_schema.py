from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.storage.repository import ensure_runtime_query


SCHEMA_DIR = REPO_ROOT / "db" / "schemas"


def read_schema(name: str) -> str:
    return (SCHEMA_DIR / name).read_text(encoding="utf-8").lower()


def test_required_database_schema_files_exist():
    required = [
        "runtime_schema.sql",
        "eval_schema.sql",
        "indexes.sql",
        "views_runtime.sql",
        "views_eval.sql",
    ]

    for filename in required:
        assert (SCHEMA_DIR / filename).exists(), f"Missing database schema file: {filename}"


def test_runtime_and_eval_schemas_are_separate():
    runtime_sql = read_schema("runtime_schema.sql")
    eval_sql = read_schema("eval_schema.sql")

    assert "create schema if not exists safeagentsoc_runtime" in runtime_sql
    assert "create schema if not exists safeagentsoc_eval" in eval_sql
    assert "ground_truth" not in runtime_sql
    assert "casebook" not in runtime_sql
    assert "expected_conclusion" not in runtime_sql


def test_runtime_views_do_not_expose_eval_data():
    runtime_views = read_schema("views_runtime.sql")

    forbidden = [
        "safeagentsoc_eval",
        "ground_truth",
        "casebook",
        "expected_conclusion",
        "gold_",
        "true_positive",
        "false_positive",
    ]

    for term in forbidden:
        assert term not in runtime_views, f"Runtime view exposes evaluation-only term: {term}"


def test_eval_views_are_allowed_to_join_runtime_and_eval():
    eval_views = read_schema("views_eval.sql")

    assert "safeagentsoc_eval" in eval_views
    assert "safeagentsoc_runtime" in eval_views
    assert "ground_truth_labels" in eval_views


def test_runtime_repository_rejects_eval_queries():
    ensure_runtime_query("SELECT * FROM safeagentsoc_runtime.v_alerts_runtime")

    try:
        ensure_runtime_query("SELECT * FROM safeagentsoc_eval.ground_truth_labels")
    except ValueError:
        return

    raise AssertionError("Runtime repository allowed an evaluation query.")
