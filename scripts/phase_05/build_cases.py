from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.cases.case_builder import build_case_outputs
from safeagentsoc.cases.repositories import persist_case_builder_result
from safeagentsoc.storage.db import DatabaseConfig, connect, execute_sql_file


def build_parser() -> argparse.ArgumentParser:
    phase5_root = WORKSPACE_ROOT / "06_data" / "phase_05_case_builder_alert_compression"
    parser = argparse.ArgumentParser(description="Build Phase 5 runtime investigation cases from Phase 4 enriched alerts.")
    parser.add_argument(
        "--enriched-alerts",
        type=Path,
        default=WORKSPACE_ROOT / "03_data" / "context" / "exports" / "context_enriched_alerts_with_risk.jsonl",
    )
    parser.add_argument("--output-root", type=Path, default=phase5_root)
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--schema-file", type=Path, default=REPO_ROOT / "db" / "migrations" / "0003_phase5_case_tables.sql")
    parser.add_argument("--apply-schema", action="store_true")
    parser.add_argument("--persist", action="store_true")
    parser.add_argument("--no-replace", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = build_case_outputs(args.enriched_alerts, args.output_root)
    if args.persist:
        connection = connect(DatabaseConfig(args.database_url) if args.database_url else None)
        with connection:
            if args.apply_schema:
                execute_sql_file(connection, args.schema_file)
            persist_case_builder_result(
                connection,
                result,
                run_id=str(result.metrics["case_builder_run_id"]),
                replace=not args.no_replace,
            )
    print(f"[OK] Input alerts: {result.metrics['total_input_alerts']}")
    print(f"[OK] Generated cases: {result.metrics['total_generated_cases']}")
    print(f"[OK] Visible alerts: {result.metrics['visible_alert_count']}")
    print(f"[OK] Suppressed alerts: {result.metrics['suppressed_alert_count']}")
    print(f"[OK] Alert reduction ratio: {result.metrics['alert_reduction_ratio']}")
    print(f"[OK] Wrote Phase 5 outputs to {args.output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

