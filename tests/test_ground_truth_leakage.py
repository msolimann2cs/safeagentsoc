from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.evaluation.qa_metrics import count_forbidden_terms_in_text


def test_leakage_scanner_flags_answer_key_terms():
    counts = count_forbidden_terms_in_text("This contains ground_truth and expected_conclusion fields.")

    assert counts["ground_truth"] == 1
    assert counts["expected_conclusion"] == 1


def test_runtime_docs_and_schema_do_not_expose_answer_key_terms():
    runtime_schema = REPO_ROOT / "db" / "schemas" / "runtime_schema.sql"
    runtime_views = REPO_ROOT / "db" / "schemas" / "views_runtime.sql"

    for path in [runtime_schema, runtime_views]:
        counts = count_forbidden_terms_in_text(path.read_text(encoding="utf-8"))
        assert counts == {}, f"Runtime artifact leaks evaluation terms: {path.name} {counts}"
