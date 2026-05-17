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

from safeagentsoc.graph.hallucination_report import write_hallucination_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Regenerate the Phase 8 hallucination rejection report from metrics.")
    parser.add_argument("--output-root", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase8" / "graph_validation")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    metrics_path = args.output_root / "exports" / "graph_validation_summary.json"
    if not metrics_path.exists():
        print(f"[FAIL] Metrics file not found: {metrics_path}")
        return 2
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    report_path = args.output_root / "reports" / "hallucination_rejection_report.md"
    write_hallucination_report(report_path, metrics)
    print(f"[OK] Wrote {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
