from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.storage.db import DatabaseConfig, connect, execute_sql_file
from safeagentsoc.timeline.repositories import persist_timeline_result
from safeagentsoc.timeline.timeline_builder import build_timeline_outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build Phase 6 case digital twins and ATT&CK timelines.")
    parser.add_argument(
        "--generated-cases",
        type=Path,
        default=WORKSPACE_ROOT / "06_data" / "phase_05_case_builder_alert_compression" / "cases" / "exports" / "generated_cases.jsonl",
    )
    parser.add_argument(
        "--enriched-alerts",
        type=Path,
        default=WORKSPACE_ROOT / "06_data" / "Phase4" / "context" / "exports" / "context_enriched_alerts_with_risk.jsonl",
    )
    parser.add_argument("--output-root", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase6" / "timelines")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--schema-file", type=Path, default=REPO_ROOT / "db" / "migrations" / "0004_phase6_timeline_tables.sql")
    parser.add_argument("--apply-schema", action="store_true")
    parser.add_argument("--persist", action="store_true")
    parser.add_argument("--no-replace", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = build_timeline_outputs(args.generated_cases, args.enriched_alerts, args.output_root)
    if args.persist:
        connection = connect(DatabaseConfig(args.database_url) if args.database_url else None)
        with connection:
            if args.apply_schema:
                execute_sql_file(connection, args.schema_file)
            persist_timeline_result(
                connection,
                result,
                run_id=str(result.quality_metrics["timeline_builder_run_id"]),
                replace=not args.no_replace,
            )
    print(f"[OK] Cases processed: {result.quality_metrics['total_cases_processed']}")
    print(f"[OK] Timelines: {result.quality_metrics['cases_with_timeline']}")
    print(f"[OK] Stories: {result.quality_metrics['cases_with_attack_story']}")
    print(f"[OK] Technique claims: {len(result.technique_claims)}")
    print(f"[OK] Unsupported claim warnings: {result.quality_metrics['unsupported_claim_count_runtime']}")
    print(f"[OK] Wrote Phase 6 outputs to {args.output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
