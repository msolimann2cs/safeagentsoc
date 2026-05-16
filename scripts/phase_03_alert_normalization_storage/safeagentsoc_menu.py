from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = REPO_ROOT / "scripts" / "phase_03_alert_normalization_storage" / "safeagentsoc_cli.py"
BACKUP_DIR = REPO_ROOT / ".." / ".." / "09_backups" / "phase_03_alert_normalization_storage" / "postgres"

DEFAULT_RUNTIME_INGESTION_ARGS = [
    "ingest-alerts",
    "--input",
    "data\\phase_02_scenario_dataset\\Metadata\\sprint_08_ground_truth\\raw_alerts_full.jsonl",
    "--lineage",
    "..\\..\\06_data\\phase_03_alert_normalization_storage\\lineage\\raw_alert_lineage.csv",
    "--evidence",
    "..\\..\\06_data\\phase_03_alert_normalization_storage\\lineage\\evidence_reference.csv",
    "--normalized",
    "..\\..\\06_data\\phase_03_alert_normalization_storage\\normalized\\normalized_alerts_v1.jsonl",
    "--warnings",
    "..\\..\\06_data\\phase_03_alert_normalization_storage\\normalized\\normalization_warnings.csv",
    "--errors",
    "..\\..\\06_data\\phase_03_alert_normalization_storage\\normalized\\normalization_errors.csv",
    "--batch",
    "phase3_v1",
    "--replace-batch",
    "--summary-output",
    "..\\..\\06_data\\phase_03_alert_normalization_storage\\batches\\phase3_v1\\ingestion_summary.csv",
    "--qa-report-output",
    "..\\..\\06_data\\phase_03_alert_normalization_storage\\batches\\phase3_v1\\batch_qa_report.md",
]


def prompt(default: str, label: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def run_cli(args: list[str]) -> int:
    command = [sys.executable, str(CLI_SCRIPT), *args]
    print()
    print("Running:")
    print(" ".join(f'"{part}"' if " " in part else part for part in command))
    print()
    return subprocess.call(command, cwd=REPO_ROOT)


def create_snapshot() -> int:
    default_name = "safeagentsoc_snapshot"
    name = prompt(default_name, "Snapshot name")
    output_dir = prompt(str(BACKUP_DIR), "Snapshot output folder")
    return run_cli(["backup-db", "--output-dir", output_dir, "--name", name])


def choose_snapshot_file() -> str | None:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    snapshots = sorted(BACKUP_DIR.glob("*.dump"))

    if snapshots:
        print()
        print("Available snapshots:")
        for index, snapshot in enumerate(snapshots, start=1):
            print(f"{index}. {snapshot}")
        choice = input("Choose a snapshot number, or press Enter to type a path: ").strip()
        if choice:
            try:
                selected = snapshots[int(choice) - 1]
            except (ValueError, IndexError):
                print("Invalid snapshot number.")
                return None
            return str(selected)

    snapshot_path = input("Snapshot .dump path: ").strip()
    return snapshot_path or None


def restore_snapshot() -> int:
    snapshot = choose_snapshot_file()
    if not snapshot:
        return 1
    confirm = input("Restore will replace database objects from the dump. Type RESTORE to continue: ").strip()
    if confirm != "RESTORE":
        print("Restore cancelled.")
        return 1
    return run_cli(["restore-db", "--snapshot", snapshot])


def run_runtime_ingestion() -> int:
    print()
    print("Runtime ingestion will use the Phase 3 default artifact paths and --replace-batch.")
    confirm = input("Type INGEST to continue: ").strip()
    if confirm != "INGEST":
        print("Ingestion cancelled.")
        return 1
    return run_cli(DEFAULT_RUNTIME_INGESTION_ARGS)


def print_menu() -> None:
    print()
    print("SafeAgentSOC Phase 3 Menu")
    print("1. Save database snapshot")
    print("2. Restore database snapshot")
    print("3. Run runtime ingestion")
    print("4. Exit")


def main() -> int:
    while True:
        print_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            return create_snapshot()
        if choice == "2":
            return restore_snapshot()
        if choice == "3":
            return run_runtime_ingestion()
        if choice == "4":
            print("Exiting.")
            return 0

        print("Please choose 1, 2, 3, or 4.")


if __name__ == "__main__":
    raise SystemExit(main())
