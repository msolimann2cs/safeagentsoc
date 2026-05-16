from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

from safeagentsoc.adapters.wazuh.jsonl_parser import parse_wazuh_jsonl
from safeagentsoc.storage.db import DatabaseConfig, connect


RUNTIME_SCHEMA = "safeagentsoc_runtime"


@dataclass(frozen=True)
class IngestionPaths:
    raw_alerts: Path
    lineage: Path
    evidence: Path
    normalized: Path
    warnings: Path
    errors: Path
    batch_manifest: Path | None = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_csv_by_key(path: Path, key: str) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as file:
        return {row[key]: row for row in csv.DictReader(file)}


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def load_normalized_alerts(path: Path) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                alerts.append(json.loads(line))
    return alerts


def jsonb(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def none_if_empty(value: Any) -> Any:
    return None if value == "" else value


def int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def float_or_none(value: Any) -> float | None:
    if value in (None, ""):
        return None
    return float(value)


def replace_runtime_batch(connection: Any, batch_id: str) -> None:
    with connection.cursor() as cursor:
        cursor.execute(f"DELETE FROM {RUNTIME_SCHEMA}.normalization_warnings WHERE alert_uid IN (SELECT alert_uid FROM {RUNTIME_SCHEMA}.raw_alerts WHERE ingestion_batch_id = %s)", (batch_id,))
        cursor.execute(f"DELETE FROM {RUNTIME_SCHEMA}.normalization_errors WHERE alert_uid IN (SELECT alert_uid FROM {RUNTIME_SCHEMA}.raw_alerts WHERE ingestion_batch_id = %s)", (batch_id,))
        cursor.execute(f"DELETE FROM {RUNTIME_SCHEMA}.normalized_alerts WHERE ingestion_batch_id = %s", (batch_id,))
        cursor.execute(f"DELETE FROM {RUNTIME_SCHEMA}.evidence_references WHERE ingestion_batch_id = %s", (batch_id,))
        cursor.execute(f"DELETE FROM {RUNTIME_SCHEMA}.raw_alerts WHERE ingestion_batch_id = %s", (batch_id,))
        cursor.execute(f"DELETE FROM {RUNTIME_SCHEMA}.normalization_batches WHERE ingestion_batch_id = %s", (batch_id,))
    connection.commit()


def insert_batch(connection: Any, batch_id: str, paths: IngestionPaths, summary: dict[str, Any]) -> None:
    manifest_payload = {
        "paths": {name: str(path) for name, path in paths.__dict__.items() if path is not None},
        "summary": summary,
    }
    source_file_sha256 = summary.get("raw_file_sha256")
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.normalization_batches (
                ingestion_batch_id,
                source_system,
                source_adapter,
                source_file_name,
                source_file_sha256,
                normalizer_version,
                uid_strategy_version,
                started_at_utc,
                completed_at_utc,
                parsed_alert_count,
                normalized_alert_count,
                warning_count,
                error_count,
                manifest
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (
                batch_id,
                summary["source_system"],
                summary["source_adapter"],
                paths.raw_alerts.name,
                source_file_sha256,
                summary["normalizer_version"],
                summary["uid_strategy_version"],
                summary["started_at_utc"],
                summary["completed_at_utc"],
                summary["parsed_alert_count"],
                summary["normalized_alert_count"],
                summary["warning_count"],
                summary["error_count"],
                jsonb(manifest_payload),
            ),
        )
    connection.commit()


def insert_raw_alerts(connection: Any, raw_by_line: dict[int, dict[str, Any]], lineage_rows: list[dict[str, str]], normalized_by_uid: dict[str, dict[str, Any]]) -> int:
    rows = []
    for lineage in lineage_rows:
        alert_uid = lineage["alert_uid"]
        normalized = normalized_by_uid[alert_uid]
        raw_alert = raw_by_line[int(lineage["raw_line_number"])]
        rows.append(
            (
                alert_uid,
                lineage["ingestion_batch_id"],
                lineage["source_system"],
                lineage["source_adapter"],
                normalized["source"].get("source_event_id"),
                lineage["raw_alert_sha256"],
                lineage["raw_file_sha256"],
                lineage["raw_file_name"],
                int(lineage["raw_line_number"]),
                normalized["timestamps"]["event_time_utc"],
                jsonb(raw_alert),
            )
        )

    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.raw_alerts (
                alert_uid,
                ingestion_batch_id,
                source_system,
                source_adapter,
                source_event_id,
                raw_alert_sha256,
                raw_file_sha256,
                raw_file_name,
                raw_line_number,
                event_time_utc,
                raw_alert
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            rows,
        )
    connection.commit()
    return len(rows)


def insert_evidence_references(connection: Any, evidence_rows: list[dict[str, str]]) -> int:
    rows = [
        (
            row["evidence_id"],
            row["alert_uid"],
            row["raw_alert_sha256"],
            row["raw_file_sha256"],
            row["raw_file_name"],
            int(row["raw_line_number"]),
            row["ingestion_batch_id"],
            row["source_system"],
            row["source_adapter"],
            row["evidence_confidence"],
        )
        for row in evidence_rows
    ]

    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.evidence_references (
                evidence_id,
                alert_uid,
                raw_alert_sha256,
                raw_file_sha256,
                raw_file_name,
                raw_line_number,
                ingestion_batch_id,
                source_system,
                source_adapter,
                evidence_confidence
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            rows,
        )
    connection.commit()
    return len(rows)


def insert_normalized_alerts(connection: Any, normalized_alerts: list[dict[str, Any]]) -> int:
    rows = []
    for alert in normalized_alerts:
        source = alert["source"]
        timestamps = alert["timestamps"]
        host = alert["host"]
        rule = alert["rule"]
        decoder = alert.get("decoder", {})
        event = alert["event"]
        severity = alert["severity"]
        mitre = alert["mitre"]
        scenario = alert["scenario_context"]
        evidence = alert["evidence"]
        normalization = alert["normalization"]
        rows.append(
            (
                alert["alert_uid"],
                evidence["evidence_id"],
                evidence["ingestion_batch_id"],
                alert["schema_version"],
                source["source_system"],
                source["source_adapter"],
                source["source_type"],
                source.get("source_event_id"),
                source.get("source_location"),
                timestamps["event_time_utc"],
                timestamps.get("normalized_at_utc"),
                host.get("hostname"),
                host.get("agent_id"),
                host.get("agent_name"),
                host.get("agent_ip"),
                host["platform"],
                rule.get("rule_id"),
                rule.get("rule_level"),
                rule.get("rule_description"),
                decoder.get("decoder_name"),
                event["kind"],
                event["category"],
                event["action"],
                event["outcome"],
                severity["normalized"],
                severity.get("normalized_score"),
                mitre.get("technique_ids", []),
                mitre.get("tactics", []),
                scenario.get("scenario_id"),
                scenario.get("campaign_id"),
                scenario.get("run_id"),
                scenario.get("execution_mode"),
                scenario.get("benchmark_link_available", False),
                normalization["status"],
                jsonb(alert),
            )
        )

    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.normalized_alerts (
                alert_uid,
                evidence_id,
                ingestion_batch_id,
                schema_version,
                source_system,
                source_adapter,
                source_type,
                source_event_id,
                source_location,
                event_time_utc,
                normalized_at_utc,
                hostname,
                agent_id,
                agent_name,
                agent_ip,
                platform,
                rule_id,
                rule_level,
                rule_description,
                decoder_name,
                event_kind,
                event_category,
                event_action,
                event_outcome,
                severity_normalized,
                severity_score,
                mitre_technique_ids,
                mitre_tactics,
                scenario_id,
                campaign_id,
                run_id,
                execution_mode,
                benchmark_link_available,
                normalization_status,
                normalized_alert
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s::jsonb
            )
            """,
            rows,
        )
    connection.commit()
    return len(rows)


def insert_warning_rows(connection: Any, warning_rows: list[dict[str, str]]) -> int:
    rows = [
        (
            row["warning_id"],
            none_if_empty(row["alert_uid"]),
            none_if_empty(row["raw_reference_id"]),
            row["warning_type"],
            none_if_empty(row["field_path"]),
            row["warning_message"],
            row["created_at_utc"],
        )
        for row in warning_rows
    ]

    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.normalization_warnings (
                warning_id,
                alert_uid,
                raw_reference_id,
                warning_type,
                field_path,
                warning_message,
                created_at_utc
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            rows,
        )
    connection.commit()
    return len(rows)


def insert_error_rows(connection: Any, error_rows: list[dict[str, str]]) -> int:
    rows = [
        (
            row["error_id"],
            none_if_empty(row["alert_uid"]),
            none_if_empty(row["raw_reference_id"]),
            row["error_type"],
            none_if_empty(row["field_path"]),
            row["error_message"],
            row["created_at_utc"],
        )
        for row in error_rows
    ]

    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.normalization_errors (
                error_id,
                alert_uid,
                raw_reference_id,
                error_type,
                field_path,
                error_message,
                created_at_utc
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            rows,
        )
    connection.commit()
    return len(rows)


def upsert_rule_reference(connection: Any, normalized_alerts: list[dict[str, Any]]) -> int:
    rule_summary: dict[tuple[str, str], dict[str, Any]] = {}
    for alert in normalized_alerts:
        source_system = alert["source"]["source_system"]
        rule_id = alert["rule"].get("rule_id")
        if not rule_id:
            continue
        key = (source_system, rule_id)
        item = rule_summary.setdefault(
            key,
            {
                "source_system": source_system,
                "rule_id": rule_id,
                "rule_level": alert["rule"].get("rule_level"),
                "rule_description": alert["rule"].get("rule_description"),
                "rule_groups": alert["rule"].get("rule_groups", []),
                "decoder_name": alert.get("decoder", {}).get("decoder_name"),
                "first_seen_at_utc": alert["timestamps"]["event_time_utc"],
                "alert_count": 0,
            },
        )
        item["alert_count"] += 1
        item["first_seen_at_utc"] = min(item["first_seen_at_utc"], alert["timestamps"]["event_time_utc"])

    rows = [
        (
            item["source_system"],
            item["rule_id"],
            item["rule_level"],
            item["rule_description"],
            item["rule_groups"],
            item["decoder_name"],
            item["first_seen_at_utc"],
            item["alert_count"],
        )
        for item in rule_summary.values()
    ]

    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.rule_reference (
                source_system,
                rule_id,
                rule_level,
                rule_description,
                rule_groups,
                decoder_name,
                first_seen_at_utc,
                alert_count
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (source_system, rule_id) DO UPDATE SET
                rule_level = EXCLUDED.rule_level,
                rule_description = EXCLUDED.rule_description,
                rule_groups = EXCLUDED.rule_groups,
                decoder_name = EXCLUDED.decoder_name,
                first_seen_at_utc = LEAST(safeagentsoc_runtime.rule_reference.first_seen_at_utc, EXCLUDED.first_seen_at_utc),
                alert_count = EXCLUDED.alert_count
            """,
            rows,
        )
    connection.commit()
    return len(rows)


def upsert_mitre_techniques(connection: Any, normalized_alerts: list[dict[str, Any]]) -> int:
    mitre_rows: dict[str, tuple[str, str | None, str | None, str | None]] = {}
    for alert in normalized_alerts:
        ids = alert["mitre"].get("technique_ids", [])
        names = alert["mitre"].get("technique_names", [])
        tactics = alert["mitre"].get("tactics", [])
        for index, technique_id in enumerate(ids):
            if technique_id not in mitre_rows:
                mitre_rows[technique_id] = (
                    technique_id,
                    names[index] if index < len(names) else None,
                    tactics[index] if index < len(tactics) else (tactics[0] if tactics else None),
                    alert["alert_uid"],
                )

    rows = list(mitre_rows.values())
    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.mitre_techniques (
                technique_id,
                technique_name,
                tactic,
                mapping_source,
                first_seen_alert_uid
            )
            VALUES (%s, %s, %s, 'wazuh_rule', %s)
            ON CONFLICT (technique_id) DO UPDATE SET
                technique_name = COALESCE(EXCLUDED.technique_name, safeagentsoc_runtime.mitre_techniques.technique_name),
                tactic = COALESCE(EXCLUDED.tactic, safeagentsoc_runtime.mitre_techniques.tactic)
            """,
            rows,
        )
    connection.commit()
    return len(rows)


def query_count(connection: Any, table_name: str, batch_id: str | None = None) -> int:
    with connection.cursor() as cursor:
        if batch_id:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name} WHERE ingestion_batch_id = %s", (batch_id,))
        else:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        return int(cursor.fetchone()[0])


def write_ingestion_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(summary.keys()))
        writer.writeheader()
        writer.writerow(summary)


def write_batch_qa_report(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Batch QA Report",
        "",
        f"Batch ID: `{summary['batch_id']}`",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key, value in summary.items():
        if key != "batch_id":
            lines.append(f"| `{key}` | {value} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def ingest_runtime(paths: IngestionPaths, batch_id: str, database_url: str | None, replace_batch: bool, summary_output: Path, qa_report_output: Path) -> dict[str, Any]:
    parsed = parse_wazuh_jsonl(paths.raw_alerts)
    raw_by_line = {alert.line_number: alert.raw for alert in parsed.alerts}
    lineage_rows = load_csv_rows(paths.lineage)
    evidence_rows = load_csv_rows(paths.evidence)
    normalized_alerts = load_normalized_alerts(paths.normalized)
    normalized_by_uid = {alert["alert_uid"]: alert for alert in normalized_alerts}
    warning_rows = load_csv_rows(paths.warnings)
    error_rows = load_csv_rows(paths.errors)
    started_at = utc_now_iso()

    config = DatabaseConfig(dsn=database_url) if database_url else DatabaseConfig.from_env()
    connection = connect(config)

    try:
        if replace_batch:
            replace_runtime_batch(connection, batch_id)

        lineage_by_line = {int(row["raw_line_number"]): row for row in lineage_rows}
        first_lineage = lineage_rows[0]
        first_normalized = normalized_alerts[0]
        summary = {
            "batch_id": batch_id,
            "source_system": first_lineage["source_system"],
            "source_adapter": first_lineage["source_adapter"],
            "normalizer_version": first_normalized["normalization"]["normalizer_version"],
            "uid_strategy_version": first_lineage["uid_strategy_version"],
            "raw_file_sha256": first_lineage["raw_file_sha256"],
            "started_at_utc": started_at,
            "completed_at_utc": utc_now_iso(),
            "parsed_alert_count": parsed.parsed_count,
            "normalized_alert_count": len(normalized_alerts),
            "warning_count": len(warning_rows),
            "error_count": len(error_rows),
        }

        insert_batch(connection, batch_id, paths, summary)
        raw_count = insert_raw_alerts(connection, raw_by_line, lineage_rows, normalized_by_uid)
        evidence_count = insert_evidence_references(connection, evidence_rows)
        normalized_count = insert_normalized_alerts(connection, normalized_alerts)
        warning_count = insert_warning_rows(connection, warning_rows)
        error_count = insert_error_rows(connection, error_rows)
        rule_count = upsert_rule_reference(connection, normalized_alerts)
        mitre_count = upsert_mitre_techniques(connection, normalized_alerts)

        result = {
            "batch_id": batch_id,
            "parsed_alerts": parsed.parsed_count,
            "invalid_json_lines": parsed.invalid_count,
            "lineage_rows": len(lineage_rows),
            "raw_alerts_inserted": raw_count,
            "evidence_references_inserted": evidence_count,
            "normalized_alerts_inserted": normalized_count,
            "normalization_warnings_inserted": warning_count,
            "normalization_errors_inserted": error_count,
            "rule_reference_upserts": rule_count,
            "mitre_technique_upserts": mitre_count,
            "db_raw_alerts_for_batch": query_count(connection, f"{RUNTIME_SCHEMA}.raw_alerts", batch_id),
            "db_normalized_alerts_for_batch": query_count(connection, f"{RUNTIME_SCHEMA}.normalized_alerts", batch_id),
            "db_evidence_references_for_batch": query_count(connection, f"{RUNTIME_SCHEMA}.evidence_references", batch_id),
        }
        write_ingestion_summary(summary_output, result)
        write_batch_qa_report(qa_report_output, result)
        return result
    finally:
        connection.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Load normalized SafeAgentSOC runtime artifacts into PostgreSQL.")
    parser.add_argument("--input", required=True, type=Path, help="Raw Wazuh JSONL input.")
    parser.add_argument("--lineage", required=True, type=Path, help="raw_alert_lineage.csv.")
    parser.add_argument("--evidence", required=True, type=Path, help="evidence_reference.csv.")
    parser.add_argument("--normalized", required=True, type=Path, help="normalized_alerts_v1.jsonl.")
    parser.add_argument("--warnings", required=True, type=Path, help="normalization_warnings.csv.")
    parser.add_argument("--errors", required=True, type=Path, help="normalization_errors.csv.")
    parser.add_argument("--batch", default="phase3_v1")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--replace-batch", action="store_true")
    parser.add_argument("--summary-output", required=True, type=Path)
    parser.add_argument("--qa-report-output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    paths = IngestionPaths(
        raw_alerts=args.input,
        lineage=args.lineage,
        evidence=args.evidence,
        normalized=args.normalized,
        warnings=args.warnings,
        errors=args.errors,
    )

    missing = [str(path) for path in paths.__dict__.values() if isinstance(path, Path) and not path.exists()]
    if missing:
        print(f"[FAIL] Missing input artifacts: {', '.join(missing)}", file=sys.stderr)
        return 1

    result = ingest_runtime(
        paths=paths,
        batch_id=args.batch,
        database_url=args.database_url,
        replace_batch=args.replace_batch,
        summary_output=args.summary_output,
        qa_report_output=args.qa_report_output,
    )
    for key, value in result.items():
        print(f"[OK] {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
