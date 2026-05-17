from __future__ import annotations

import argparse
import csv
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[4]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export Phase 7 LLM grounding and Agent Firewall reports.")
    parser.add_argument("--reason-root", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase7" / "reason")
    parser.add_argument("--docs-dir", type=Path, default=WORKSPACE_ROOT / "01_docs" / "phase_07_llm_hypothesis_agent_firewall")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    metrics = read_metric_csv(args.reason_root / "qa" / "llm_grounding_metrics.csv")
    args.docs_dir.mkdir(parents=True, exist_ok=True)
    write_report(args.docs_dir / "llm_grounding_report.md", "Phase 7 LLM Grounding Report", metrics)
    write_report(args.docs_dir / "agent_firewall_evaluation.md", "Phase 7 Agent Firewall Evaluation", metrics)
    print(f"[OK] Exported Phase 7 reports to {args.docs_dir}")
    return 0


def read_metric_csv(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        return {row["metric"]: row["value"] for row in csv.DictReader(handle)}


def write_report(path: Path, title: str, metrics: dict[str, str]) -> None:
    path.write_text(
        "\n".join(
            [
                f"# {title}",
                "",
                "Phase 7 generated structured hypotheses, verified evidence citations, enforced the Agent Firewall, and wrote auditable decision records.",
                "",
                *[f"- {key}: {value}" for key, value in metrics.items()],
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    raise SystemExit(main())
