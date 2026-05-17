from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.govern.governance_engine import build_governance_outputs
from safeagentsoc.govern.repositories import persist_phase9_result
from safeagentsoc.storage.db import DatabaseConfig, connect, execute_sql_file


def build_common_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--phase8-root", type=Path, default=None)
    parser.add_argument("--phase7-root", type=Path, default=None)
    parser.add_argument("--output-root", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase9" / "governance")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--persist", action="store_true")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--apply-schema", action="store_true")
    parser.add_argument("--schema-file", type=Path, default=REPO_ROOT / "db" / "migrations" / "0007_phase9_governance_tables.sql")
    parser.add_argument("--no-replace", action="store_true")
    parser.add_argument("--strict-success", action="store_true")
    return parser


def run_phase9(args: argparse.Namespace):
    result = build_governance_outputs(
        workspace_root=WORKSPACE_ROOT,
        output_root=args.output_root,
        phase8_root=args.phase8_root,
        phase7_root=args.phase7_root,
        verbose=args.verbose,
    )
    if args.persist:
        connection = connect(DatabaseConfig(args.database_url) if args.database_url else None)
        with connection:
            if args.apply_schema:
                execute_sql_file(connection, args.schema_file)
            persist_phase9_result(connection, result, replace=not args.no_replace)
    return result


def print_summary(result: object) -> None:
    metrics = result.metrics
    print(f"[OK] Cases processed: {metrics['case_count']}")
    print(f"[OK] High or critical cases: {metrics['high_or_critical_case_count']}")
    print(f"[OK] Policy decisions: {metrics['policy_decision_count']}")
    print(f"[OK] Blocked actions: {metrics['blocked_action_count']}")
    print(f"[OK] Approval-required decisions: {metrics['approval_required_count']}")
    print(f"[OK] Safe recommendations: {metrics['safe_recommendation_count']}")
    print(f"[OK] CSIRT packs: {metrics['csirt_pack_count']}")
    print(f"[OK] CISO briefs: {metrics['ciso_brief_count']}")
    print(f"[OK] Unsafe action block rate: {metrics['unsafe_action_block_rate']}")
    print(f"[OK] Runtime leakage count: {metrics['runtime_leakage_count']}")
    print(f"[OK] Wrote Phase 9 outputs to {result.paths.output_root}")
