from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = REPO_ROOT.parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.evaluation.qa_metrics import QaPaths, run_qa


def default_private_root() -> Path:
    return WORKSPACE_ROOT / "06_data" / "phase_03_alert_normalization_storage"


def default_raw_alerts() -> Path:
    return REPO_ROOT / "data" / "phase_02_scenario_dataset" / "Metadata" / "sprint_08_ground_truth" / "raw_alerts_full.jsonl"


def build_arg_parser() -> argparse.ArgumentParser:
    private_root = default_private_root()
    parser = argparse.ArgumentParser(description="Generate Sprint 9 QA metrics and runtime leakage audit CSVs.")
    parser.add_argument("--raw-alerts", default=default_raw_alerts(), type=Path)
    parser.add_argument("--lineage", default=private_root / "lineage" / "raw_alert_lineage.csv", type=Path)
    parser.add_argument("--evidence", default=private_root / "lineage" / "evidence_reference.csv", type=Path)
    parser.add_argument("--normalized", default=private_root / "normalized" / "normalized_alerts_v1.jsonl", type=Path)
    parser.add_argument("--warnings", default=private_root / "normalized" / "normalization_warnings.csv", type=Path)
    parser.add_argument("--errors", default=private_root / "normalized" / "normalization_errors.csv", type=Path)
    parser.add_argument("--metrics-output", default=private_root / "qa" / "normalization_metrics.csv", type=Path)
    parser.add_argument("--leakage-output", default=private_root / "qa" / "leakage_audit_report.csv", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    paths = QaPaths(
        raw_alerts=args.raw_alerts,
        lineage=args.lineage,
        evidence=args.evidence,
        normalized=args.normalized,
        warnings=args.warnings,
        errors=args.errors,
        runtime_schema=REPO_ROOT / "db" / "schemas" / "runtime_schema.sql",
        runtime_views=REPO_ROOT / "db" / "schemas" / "views_runtime.sql",
        runtime_api_files=[
            REPO_ROOT / "src" / "safeagentsoc" / "api" / "routes_alerts.py",
            REPO_ROOT / "src" / "safeagentsoc" / "api" / "routes_evidence.py",
            REPO_ROOT / "src" / "safeagentsoc" / "api" / "routes_metrics.py",
        ],
        metrics_output=args.metrics_output,
        leakage_output=args.leakage_output,
    )

    missing = [
        str(path)
        for value in paths.__dict__.values()
        for path in (value if isinstance(value, list) else [value])
        if isinstance(path, Path) and not path.exists() and path not in {paths.metrics_output, paths.leakage_output}
    ]
    if missing:
        print(f"[FAIL] Missing required QA input artifacts: {', '.join(missing)}", file=sys.stderr)
        return 1

    result = run_qa(paths)
    for key, value in result.items():
        print(f"[OK] {key}: {value}")
    return 0 if result["failed_metric_count"] == 0 and result["failed_leakage_check_count"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
