from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.agent_firewall.prompt_injection_tester import run_prompt_injection_tests


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Phase 7 Agent Firewall prompt-injection tests.")
    parser.add_argument("--output-dir", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase7" / "reason" / "qa")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_prompt_injection_tests()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output_dir / "prompt_injection_tests.jsonl", result["prompt_injection_results"])
    write_jsonl(args.output_dir / "unauthorized_tool_call_tests.jsonl", result["permission_results"])
    write_csv(args.output_dir / "prompt_injection_test_metrics.csv", [{"metric": key, "value": value} for key, value in result.items() if not isinstance(value, list)])
    print(f"[OK] Prompt injection rejection rate: {result['prompt_injection_rejection_rate']}")
    print(f"[OK] Unauthorized tool-call block rate: {result['unauthorized_tool_call_block_rate']}")
    return 0


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value"])
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    raise SystemExit(main())
