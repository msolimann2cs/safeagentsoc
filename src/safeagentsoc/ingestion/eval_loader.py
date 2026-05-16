from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys
from typing import Any

from safeagentsoc.storage.db import DatabaseConfig, connect


EVAL_SCHEMA = "safeagentsoc_eval"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def pick(row: dict[str, str], *names: str) -> str | None:
    lowered = {key.lower(): value for key, value in row.items()}
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return value
    return None


def replace_eval_batch(connection: Any, batch_id: str) -> None:
    with connection.cursor() as cursor:
        cursor.execute(f"DELETE FROM {EVAL_SCHEMA}.evaluation_scores WHERE evaluation_run_id = %s", (batch_id,))
        cursor.execute(f"DELETE FROM {EVAL_SCHEMA}.alert_case_links_gold WHERE loaded_batch_id = %s", (batch_id,))
        cursor.execute(f"DELETE FROM {EVAL_SCHEMA}.ground_truth_labels WHERE loaded_batch_id = %s", (batch_id,))
        cursor.execute(f"DELETE FROM {EVAL_SCHEMA}.alert_fatigue_baseline WHERE loaded_batch_id = %s", (batch_id,))
        cursor.execute(f"DELETE FROM {EVAL_SCHEMA}.detection_gap_register WHERE loaded_batch_id = %s", (batch_id,))
        cursor.execute(f"DELETE FROM {EVAL_SCHEMA}.scenario_run_log WHERE loaded_batch_id = %s", (batch_id,))
        cursor.execute(f"DELETE FROM {EVAL_SCHEMA}.casebook_cases WHERE loaded_batch_id = %s", (batch_id,))
    connection.commit()


def load_labels(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    values = []
    for row in rows:
        values.append(
            (
                pick(row, "alert_uid", "alert_id"),
                pick(row, "label") or "ambiguous_noise",
                pick(row, "event_role", "role") or "supporting",
                pick(row, "confidence") or "medium",
                pick(row, "scenario_id"),
                pick(row, "campaign_id"),
                pick(row, "run_id"),
                pick(row, "case_id"),
                path.name,
                batch_id,
            )
        )

    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {EVAL_SCHEMA}.ground_truth_labels (
                alert_uid,
                label,
                event_role,
                confidence,
                scenario_id,
                campaign_id,
                run_id,
                case_id,
                evaluation_source,
                loaded_batch_id
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            values,
        )
    connection.commit()
    return len(values)


def load_casebook(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    values = []
    for index, row in enumerate(rows, start=1):
        case_id = pick(row, "case_id") or f"case_{index:05d}"
        values.append(
            (
                case_id,
                pick(row, "scenario_id"),
                pick(row, "campaign_id"),
                pick(row, "run_id"),
                pick(row, "execution_mode"),
                pick(row, "expected_conclusion", "conclusion"),
                pick(row, "case_summary", "summary"),
                path.name,
                batch_id,
                "{}",
            )
        )

    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {EVAL_SCHEMA}.casebook_cases (
                case_id,
                scenario_id,
                campaign_id,
                run_id,
                execution_mode,
                expected_conclusion,
                case_summary,
                evaluation_source,
                loaded_batch_id,
                casebook_payload
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            ON CONFLICT (case_id) DO UPDATE SET
                scenario_id = EXCLUDED.scenario_id,
                campaign_id = EXCLUDED.campaign_id,
                run_id = EXCLUDED.run_id,
                execution_mode = EXCLUDED.execution_mode,
                expected_conclusion = EXCLUDED.expected_conclusion,
                case_summary = EXCLUDED.case_summary,
                evaluation_source = EXCLUDED.evaluation_source,
                loaded_batch_id = EXCLUDED.loaded_batch_id
            """,
            values,
        )
    connection.commit()
    return len(values)


def load_fatigue_baseline(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    values = []
    for row in rows:
        values.append(
            (
                pick(row, "alert_uid", "alert_id"),
                pick(row, "rule_id"),
                pick(row, "rule_description"),
                pick(row, "agent_name"),
                pick(row, "event_time_utc", "timestamp"),
                pick(row, "baseline_bucket", "bucket"),
                "{}",
                path.name,
                batch_id,
            )
        )

    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {EVAL_SCHEMA}.alert_fatigue_baseline (
                alert_uid,
                rule_id,
                rule_description,
                agent_name,
                event_time_utc,
                baseline_bucket,
                baseline_payload,
                evaluation_source,
                loaded_batch_id
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
            """,
            values,
        )
    connection.commit()
    return len(values)


def load_eval_artifacts(labels: Path | None, casebook: Path | None, fatigue: Path | None, batch_id: str, database_url: str | None, replace_batch: bool) -> dict[str, int]:
    config = DatabaseConfig(dsn=database_url) if database_url else DatabaseConfig.from_env()
    connection = connect(config)
    try:
        if replace_batch:
            replace_eval_batch(connection, batch_id)

        result = {
            "labels_loaded": load_labels(connection, labels, batch_id) if labels else 0,
            "casebook_cases_loaded": load_casebook(connection, casebook, batch_id) if casebook else 0,
            "fatigue_rows_loaded": load_fatigue_baseline(connection, fatigue, batch_id) if fatigue else 0,
        }
        return result
    finally:
        connection.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Load evaluation-only artifacts into safeagentsoc_eval.")
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--casebook", type=Path)
    parser.add_argument("--fatigue", type=Path)
    parser.add_argument("--batch", default="phase3_v1")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--replace-batch", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    for optional_path in [args.labels, args.casebook, args.fatigue]:
        if optional_path and not optional_path.exists():
            print(f"[FAIL] Missing evaluation artifact: {optional_path}", file=sys.stderr)
            return 1

    result = load_eval_artifacts(args.labels, args.casebook, args.fatigue, args.batch, args.database_url, args.replace_batch)
    for key, value in result.items():
        print(f"[OK] {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
