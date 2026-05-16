from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


API_DIR = REPO_ROOT / "src" / "safeagentsoc" / "api"


def test_required_api_files_exist():
    required = [
        "main.py",
        "dependencies.py",
        "utils.py",
        "routes_alerts.py",
        "routes_evidence.py",
        "routes_metrics.py",
        "routes_eval.py",
    ]

    for filename in required:
        assert (API_DIR / filename).exists(), f"Missing API file: {filename}"


def test_runtime_routes_do_not_query_eval_schema():
    runtime_files = [
        API_DIR / "routes_alerts.py",
        API_DIR / "routes_evidence.py",
        API_DIR / "routes_metrics.py",
    ]
    forbidden = [
        "safeagentsoc_eval",
        "ground_truth",
        "casebook",
        "expected_conclusion",
        "gold_",
        "true_positive",
        "false_positive",
    ]

    for path in runtime_files:
        text = path.read_text(encoding="utf-8").lower()
        for term in forbidden:
            assert term not in text, f"{path.name} exposes evaluation-only term: {term}"


def test_eval_routes_are_disabled_by_default():
    text = (
        (API_DIR / "routes_eval.py").read_text(encoding="utf-8")
        + "\n"
        + (API_DIR / "dependencies.py").read_text(encoding="utf-8")
    )

    assert "SAFEAGENTSOC_ENABLE_EVAL_API" in text
    assert "SAFEAGENTSOC_EVAL_API_TOKEN" in text
    assert "Evaluation API is disabled" in text
    assert "x_eval_token" in text


def test_api_reference_documents_py_commands():
    text = (REPO_ROOT / "docs" / "phase_03_alert_normalization_storage" / "api_reference.md").read_text(encoding="utf-8")

    assert "py -m pip install" in text
    assert "py -m uvicorn" in text
