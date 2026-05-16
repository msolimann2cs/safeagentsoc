from __future__ import annotations

import argparse
from pathlib import Path
import sys

from safeagentsoc.ingestion.eval_loader import main as eval_loader_main
from safeagentsoc.ingestion.pipeline import main as ingest_alerts_main
from safeagentsoc.evaluation.linkage import main as linkage_main
from safeagentsoc.storage.snapshots import main as snapshots_main
from safeagentsoc.context.repositories import (
    ContextImportPaths,
    import_context_package,
    write_import_manifest,
    write_import_report,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="safeagentsoc", description="SafeAgentSOC Phase 3 command line tools.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest-alerts", help="Load runtime alert artifacts into PostgreSQL.")
    ingest.add_argument("--input", required=True, type=Path)
    ingest.add_argument("--lineage", required=True, type=Path)
    ingest.add_argument("--evidence", required=True, type=Path)
    ingest.add_argument("--normalized", required=True, type=Path)
    ingest.add_argument("--warnings", required=True, type=Path)
    ingest.add_argument("--errors", required=True, type=Path)
    ingest.add_argument("--batch", default="phase3_v1")
    ingest.add_argument("--database-url", default=None)
    ingest.add_argument("--replace-batch", action="store_true")
    ingest.add_argument("--summary-output", required=True, type=Path)
    ingest.add_argument("--qa-report-output", required=True, type=Path)

    load_eval = subparsers.add_parser("load-eval", help="Load evaluation-only artifacts into safeagentsoc_eval.")
    load_eval.add_argument("--labels", type=Path)
    load_eval.add_argument("--casebook", type=Path)
    load_eval.add_argument("--fatigue", type=Path)
    load_eval.add_argument("--batch", default="phase3_v1")
    load_eval.add_argument("--database-url", default=None)
    load_eval.add_argument("--replace-batch", action="store_true")

    link_eval = subparsers.add_parser("link-eval", help="Link evaluation artifacts to normalized alerts.")
    link_eval.add_argument("--ground-truth", required=True, type=Path)
    link_eval.add_argument("--casebook", required=True, type=Path)
    link_eval.add_argument("--casebook-detailed", required=True, type=Path)
    link_eval.add_argument("--fatigue", required=True, type=Path)
    link_eval.add_argument("--normalized", required=True, type=Path)
    link_eval.add_argument("--output-dir", required=True, type=Path)

    backup = subparsers.add_parser("backup-db", help="Create a PostgreSQL custom-format snapshot.")
    backup.add_argument("--database-url", default=None)
    backup.add_argument("--output-dir", required=True, type=Path)
    backup.add_argument("--name", default=None)

    restore = subparsers.add_parser("restore-db", help="Restore a PostgreSQL custom-format snapshot.")
    restore.add_argument("--database-url", default=None)
    restore.add_argument("--snapshot", required=True, type=Path)
    restore.add_argument("--no-clean", action="store_true")

    list_backups = subparsers.add_parser("list-db-backups", help="List PostgreSQL snapshot files.")
    list_backups.add_argument("--output-dir", required=True, type=Path)

    import_context = subparsers.add_parser("import-context", help="Import Phase 4 context into safeagentsoc_runtime.")
    import_context.add_argument("--seed-dir", required=True, type=Path)
    import_context.add_argument("--mapping-rules", required=True, type=Path)
    import_context.add_argument("--schema-file", type=Path, default=Path("db/migrations/0002_phase4_context_tables.sql"))
    import_context.add_argument("--batch", default="phase4_context_v1")
    import_context.add_argument("--database-url", default=None)
    import_context.add_argument("--replace", action="store_true")
    import_context.add_argument("--apply-schema", action="store_true")
    import_context.add_argument("--manifest-output", required=True, type=Path)
    import_context.add_argument("--report-output", required=True, type=Path)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    passthrough = sys.argv[2:] if argv is None else argv[1:]

    if args.command == "ingest-alerts":
        return ingest_alerts_main(passthrough)
    if args.command == "load-eval":
        return eval_loader_main(passthrough)
    if args.command == "link-eval":
        return linkage_main(passthrough)
    if args.command == "backup-db":
        return snapshots_main(["create", *passthrough])
    if args.command == "restore-db":
        return snapshots_main(["restore", *passthrough])
    if args.command == "list-db-backups":
        return snapshots_main(["list", *passthrough])
    if args.command == "import-context":
        result = import_context_package(
            paths=ContextImportPaths(
                seed_dir=args.seed_dir,
                mapping_rules=args.mapping_rules,
                schema_file=args.schema_file,
                manifest_output=args.manifest_output,
                report_output=args.report_output,
            ),
            batch_id=args.batch,
            database_url=args.database_url,
            replace_existing=args.replace,
            apply_schema=args.apply_schema,
        )
        write_import_manifest(result, args.manifest_output)
        write_import_report(result, args.report_output)
        if result.validation_errors:
            for error in result.validation_errors:
                print(f"[FAIL] {error}", file=sys.stderr)
            return 1
        print(f"[OK] Imported Phase 4 context package as batch {result.context_import_batch_id}.")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
