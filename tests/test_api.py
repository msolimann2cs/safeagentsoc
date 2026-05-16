from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
API_DIR = REPO_ROOT / "src" / "safeagentsoc" / "api"


def test_runtime_api_route_files_exist():
    for filename in ["main.py", "routes_alerts.py", "routes_evidence.py", "routes_metrics.py"]:
        assert (API_DIR / filename).exists(), f"Missing API route file: {filename}"


def test_runtime_api_routes_do_not_reference_eval_schema_or_answer_keys():
    forbidden = ["safeagentsoc_eval", "ground_truth", "expected_conclusion", "casebook", "gold_", "true_positive", "false_positive"]

    for filename in ["routes_alerts.py", "routes_evidence.py", "routes_metrics.py"]:
        text = (API_DIR / filename).read_text(encoding="utf-8").lower()
        for term in forbidden:
            assert term not in text, f"{filename} exposes evaluation-only term: {term}"


def test_eval_api_is_present_but_guarded():
    text = (
        (API_DIR / "routes_eval.py").read_text(encoding="utf-8")
        + "\n"
        + (API_DIR / "dependencies.py").read_text(encoding="utf-8")
    )

    assert "SAFEAGENTSOC_ENABLE_EVAL_API" in text
    assert "SAFEAGENTSOC_EVAL_API_TOKEN" in text
    assert "Evaluation API is disabled" in text
