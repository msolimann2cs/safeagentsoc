from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.graph_projection import run_graph_projection


def build_parser() -> argparse.ArgumentParser:
    context_root = WORKSPACE_ROOT / "03_data" / "context"
    parser = argparse.ArgumentParser(description="Export Phase 4 graph seed nodes and edges from context-enriched alerts.")
    parser.add_argument("--enriched-alerts", type=Path, default=context_root / "exports" / "context_enriched_alerts_with_risk.jsonl")
    parser.add_argument("--output-dir", type=Path, default=context_root / "graph_seed")
    parser.add_argument("--graph-batch", default="phase4_graph_seed_v1")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--schema-file", type=Path, default=REPO_ROOT / "db" / "migrations" / "0002_phase4_context_tables.sql")
    parser.add_argument("--apply-schema", action="store_true")
    parser.add_argument("--persist", action="store_true", help="Persist graph nodes and edges into PostgreSQL runtime tables.")
    parser.add_argument("--no-replace", action="store_true", help="Upsert graph rows without truncating existing graph tables.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_graph_projection(
        enriched_alerts_path=args.enriched_alerts,
        output_dir=args.output_dir,
        graph_batch_id=args.graph_batch,
        database_url=args.database_url,
        schema_file=args.schema_file,
        apply_schema=args.apply_schema,
        persist=args.persist,
        replace=not args.no_replace,
    )
    print(f"[OK] Graph nodes: {result.metrics['total_graph_nodes']}")
    print(f"[OK] Graph edges: {result.metrics['total_graph_edges']}")
    print(f"[OK] Alert nodes: {result.metrics['alert_nodes']}")
    print(f"[OK] Evidence nodes: {result.metrics['evidence_nodes']}")
    print(f"[OK] Wrote graph seed to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
