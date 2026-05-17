from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compute Phase 8 offline-style graph validation metrics from runtime outputs.")
    parser.add_argument("--output-root", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase8" / "graph_validation")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary_path = args.output_root / "exports" / "graph_validation_summary.json"
    if not summary_path.exists():
        print(f"[FAIL] Summary not found: {summary_path}")
        return 2
    metrics = json.loads(summary_path.read_text(encoding="utf-8"))
    report_path = args.output_root / "reports" / "graph_validation_evaluation.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        "\n".join(
            [
                "# Phase 8 Graph Validation Evaluation",
                "",
                "This evaluation uses runtime Phase 8 outputs only. Hidden labels may be added later in this script, "
                "but they must not be written into runtime artifacts.",
                "",
                f"- Total hypotheses validated: {metrics.get('total_hypotheses_validated', 0)}",
                f"- Total claims validated: {metrics.get('total_claims_validated', 0)}",
                f"- Average feasibility score: {metrics.get('average_feasibility_score', 0)}",
                f"- Explanation coverage: {metrics.get('graph_explanation_coverage', 0)}",
                f"- Runtime leakage count: {metrics.get('runtime_ground_truth_exposure_count', 0)}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"[OK] Wrote {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
