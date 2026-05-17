from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.enrichment_engine import run_enrichment


def build_parser() -> argparse.ArgumentParser:
    context_root = WORKSPACE_ROOT / "06_data" / "Phase4" / "context"
    parser = argparse.ArgumentParser(description="Run Phase 4 context enrichment and business-risk scoring.")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--output-dir", type=Path, default=context_root / "exports")
    parser.add_argument("--qa-dir", type=Path, default=context_root / "qa")
    parser.add_argument("--schema-file", type=Path, default=REPO_ROOT / "db" / "migrations" / "0002_phase4_context_tables.sql")
    parser.add_argument("--apply-schema", action="store_true")
    parser.add_argument("--no-persist", action="store_true", help="Write files only without updating PostgreSQL context_enriched_alerts.")
    parser.add_argument("--no-replace", action="store_true", help="Upsert enriched alerts without truncating existing rows first.")
    parser.add_argument("--limit", type=int, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_enrichment(
        database_url=args.database_url,
        output_dir=args.output_dir,
        qa_dir=args.qa_dir,
        schema_file=args.schema_file,
        apply_schema=args.apply_schema,
        persist=not args.no_persist,
        replace=not args.no_replace,
        limit=args.limit,
    )
    print(f"[OK] Context-enriched alerts: {result.qa_metrics.get('total_context_enriched_alerts', 0)}")
    print(f"[OK] Asset coverage: {result.qa_metrics.get('asset_context_coverage_rate', 0):.2%}")
    print(f"[OK] Identity coverage: {result.qa_metrics.get('identity_context_coverage_rate', 0):.2%}")
    print(f"[OK] Average context confidence: {result.qa_metrics.get('context_confidence_average', 0):.4f}")
    print(f"[OK] Urgent analyst-priority alerts: {result.qa_metrics.get('urgent_analyst_priority_count', 0)}")
    print(f"[OK] Wrote exports to {args.output_dir}")
    print(f"[OK] Wrote QA outputs to {args.qa_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
