from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.repositories import (
    ContextImportPaths,
    import_context_package,
    write_import_manifest,
    write_import_report,
)


def default_paths() -> dict[str, Path]:
    context_root = WORKSPACE_ROOT / "06_data" / "Phase4" / "context"
    return {
        "seed_dir": context_root / "seed",
        "mapping_rules": context_root / "mappings" / "context_mapping_rules.csv",
        "manifest_output": context_root / "seed" / "context_import_manifest.yaml",
        "report_output": WORKSPACE_ROOT / "01_docs" / "phase_04_enterprise_context" / "context_import_report.md",
        "schema_file": REPO_ROOT / "db" / "migrations" / "0002_phase4_context_tables.sql",
    }


def build_parser() -> argparse.ArgumentParser:
    defaults = default_paths()
    parser = argparse.ArgumentParser(description="Import Phase 4 context files into safeagentsoc_runtime PostgreSQL tables.")
    parser.add_argument("--seed-dir", type=Path, default=defaults["seed_dir"])
    parser.add_argument("--mapping-rules", type=Path, default=defaults["mapping_rules"])
    parser.add_argument("--schema-file", type=Path, default=defaults["schema_file"])
    parser.add_argument("--batch", default="phase4_context_v1")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--replace", action="store_true", help="Clear existing context tables before import.")
    parser.add_argument("--apply-schema", action="store_true", help="Apply the context table migration before import.")
    parser.add_argument("--manifest-output", type=Path, default=defaults["manifest_output"])
    parser.add_argument("--report-output", type=Path, default=defaults["report_output"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = ContextImportPaths(
        seed_dir=args.seed_dir,
        mapping_rules=args.mapping_rules,
        schema_file=args.schema_file,
        manifest_output=args.manifest_output,
        report_output=args.report_output,
    )
    result = import_context_package(
        paths=paths,
        batch_id=args.batch,
        database_url=args.database_url,
        replace_existing=args.replace,
        apply_schema=args.apply_schema,
    )
    if args.manifest_output:
        write_import_manifest(result, args.manifest_output)
    if args.report_output:
        write_import_report(result, args.report_output)
    if result.validation_errors:
        for error in result.validation_errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print(f"[OK] Imported Phase 4 context package as batch {result.context_import_batch_id}.")
    for key, value in sorted(result.row_counts.items()):
        print(f"[OK] {key}: {value} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
