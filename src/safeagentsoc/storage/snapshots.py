from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import shutil
import subprocess
import sys

from safeagentsoc.storage.db import DatabaseConfig


@dataclass(frozen=True)
class SnapshotPaths:
    snapshot_file: Path
    manifest_file: Path


def utc_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def require_tool(tool_name: str) -> str:
    resolved = shutil.which(tool_name)
    if not resolved:
        raise RuntimeError(f"Required PostgreSQL tool not found on PATH: {tool_name}")
    return resolved


def snapshot_paths(output_dir: Path, name: str | None = None) -> SnapshotPaths:
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = name or f"safeagentsoc_snapshot_{utc_stamp()}"
    return SnapshotPaths(
        snapshot_file=output_dir / f"{stem}.dump",
        manifest_file=output_dir / f"{stem}.manifest.txt",
    )


def create_snapshot(database_url: str | None, output_dir: Path, name: str | None = None) -> SnapshotPaths:
    pg_dump = require_tool("pg_dump")
    paths = snapshot_paths(output_dir, name)
    dsn = database_url or DatabaseConfig.from_env().dsn

    subprocess.run(
        [
            pg_dump,
            "--format=custom",
            "--verbose",
            "--file",
            str(paths.snapshot_file),
            dsn,
        ],
        check=True,
    )
    paths.manifest_file.write_text(
        "\n".join(
            [
                "type: postgresql_custom_dump",
                f"created_at_utc: {utc_stamp()}",
                f"snapshot_file: {paths.snapshot_file}",
                "database_url_source: SAFEAGENTSOC_DATABASE_URL or --database-url",
                "restore_command: safeagentsoc restore-db --snapshot <this .dump file>",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return paths


def restore_snapshot(database_url: str | None, snapshot_file: Path, clean: bool = True) -> None:
    pg_restore = require_tool("pg_restore")
    dsn = database_url or DatabaseConfig.from_env().dsn
    command = [pg_restore, "--verbose", "--dbname", dsn]
    if clean:
        command.extend(["--clean", "--if-exists"])
    command.append(str(snapshot_file))
    subprocess.run(command, check=True)


def list_snapshots(output_dir: Path) -> list[Path]:
    if not output_dir.exists():
        return []
    return sorted(output_dir.glob("*.dump"))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create, restore, or list SafeAgentSOC PostgreSQL snapshots.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--database-url", default=None)
    create.add_argument("--output-dir", required=True, type=Path)
    create.add_argument("--name", default=None)

    restore = subparsers.add_parser("restore")
    restore.add_argument("--database-url", default=None)
    restore.add_argument("--snapshot", required=True, type=Path)
    restore.add_argument("--no-clean", action="store_true")

    list_cmd = subparsers.add_parser("list")
    list_cmd.add_argument("--output-dir", required=True, type=Path)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        if args.command == "create":
            paths = create_snapshot(args.database_url, args.output_dir, args.name)
            print(f"[OK] Snapshot: {paths.snapshot_file}")
            print(f"[OK] Manifest: {paths.manifest_file}")
            return 0
        if args.command == "restore":
            restore_snapshot(args.database_url, args.snapshot, clean=not args.no_clean)
            print(f"[OK] Restored snapshot: {args.snapshot}")
            return 0
        if args.command == "list":
            for path in list_snapshots(args.output_dir):
                print(path)
            return 0
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
