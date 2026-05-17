from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.cases.evaluation import evaluate_runtime_cases


def build_parser() -> argparse.ArgumentParser:
    phase5_root = WORKSPACE_ROOT / "06_data" / "phase_05_case_builder_alert_compression"
    metadata_root = REPO_ROOT / "data" / "phase_02_scenario_dataset" / "Metadata"
    parser = argparse.ArgumentParser(description="Evaluate Phase 5 cases against offline-only answer-key artifacts.")
    parser.add_argument("--generated-cases", type=Path, default=phase5_root / "cases" / "exports" / "generated_cases.jsonl")
    parser.add_argument("--alert-case-links", type=Path, default=phase5_root / "cases" / "exports" / "alert_case_links.csv")
    parser.add_argument(
        "--ground-truth-labels",
        type=Path,
        default=metadata_root / "sprint_08_ground_truth" / "ground_truth_labels.csv",
    )
    parser.add_argument("--casebook", type=Path, default=metadata_root / "sprint_09_casebook" / "casebook.csv")
    parser.add_argument(
        "--ground-truth-crosswalk",
        type=Path,
        default=REPO_ROOT / "data" / "phase_03_alert_normalization_storage" / "evaluation_linkage" / "ground_truth_to_normalized_crosswalk.csv",
    )
    parser.add_argument("--output-dir", type=Path, default=phase5_root / "cases" / "evaluation")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    metrics = evaluate_runtime_cases(
        generated_cases_path=args.generated_cases,
        alert_case_links_path=args.alert_case_links,
        ground_truth_labels_path=args.ground_truth_labels,
        casebook_path=args.casebook,
        ground_truth_crosswalk_path=args.ground_truth_crosswalk,
        output_dir=args.output_dir,
    )
    print(f"[OK] Offline trigger preservation: {metrics['trigger_preservation_rate']}")
    print(f"[OK] Offline duplicate suppression: {metrics['duplicate_suppression_rate']}")
    print(f"[OK] Wrote offline evaluation to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
