from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.graph.repositories import persist_graph_validation_result
from safeagentsoc.graph.validation_engine import build_graph_validation_outputs
from safeagentsoc.storage.db import DatabaseConfig, connect, execute_sql_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Phase 7 hypotheses against the Phase 8 enterprise graph.")
    parser.add_argument("--phase7-root", type=Path, default=None)
    parser.add_argument("--output-root", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase8" / "graph_validation")
    parser.add_argument("--skip-case-graph-exports", action="store_true")
    parser.add_argument("--include-context-nodes", action="store_true")
    parser.add_argument("--max-case-graph-exports", type=int, default=None)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--persist", action="store_true")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--apply-schema", action="store_true")
    parser.add_argument("--schema-file", type=Path, default=REPO_ROOT / "db" / "migrations" / "0006_phase8_graph_validation_tables.sql")
    parser.add_argument("--no-replace", action="store_true")
    parser.add_argument("--strict-success", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = build_graph_validation_outputs(
        workspace_root=WORKSPACE_ROOT,
        phase7_root=args.phase7_root,
        output_root=args.output_root,
        export_case_graphs=not args.skip_case_graph_exports,
        include_context_nodes=args.include_context_nodes,
        max_case_graph_exports=args.max_case_graph_exports,
        verbose=args.verbose,
    )
    if args.persist:
        connection = connect(DatabaseConfig(args.database_url) if args.database_url else None)
        with connection:
            if args.apply_schema:
                execute_sql_file(connection, args.schema_file)
            persist_graph_validation_result(connection, result, replace=not args.no_replace)

    metrics = result.metrics
    print(f"[OK] Phase 7 records seen: {metrics['total_phase7_records_seen']}")
    print(f"[OK] Phase 7 cases consumed: {metrics['total_validated_phase7_cases']}")
    print(f"[OK] Failed Phase 7 cases marked retry_required: {metrics['total_skipped_failed_phase7_cases']}")
    print(f"[OK] Hypotheses graph-validated: {metrics['total_hypotheses_validated']}")
    print(f"[OK] Claims graph-validated: {metrics['total_claims_validated']}")
    print(f"[OK] Average feasibility score: {metrics['average_feasibility_score']}")
    print(f"[OK] Runtime leakage count: {metrics['runtime_ground_truth_exposure_count']}")
    print(f"[OK] Wrote Phase 8 outputs to {result.paths.output_root}")
    if args.strict_success and metrics["runtime_ground_truth_exposure_count"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
