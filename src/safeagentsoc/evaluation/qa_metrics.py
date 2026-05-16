from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from safeagentsoc.adapters.wazuh.jsonl_parser import parse_wazuh_jsonl


FORBIDDEN_RUNTIME_TERMS = [
    "ground_truth",
    "true_positive",
    "false_positive",
    "expected_conclusion",
    "gold_case",
    "casebook_answer",
    "event_role",
    "casebook",
    "answer_key",
    "safeagentsoc_eval",
]

REQUIRED_NORMALIZED_TOP_LEVEL_FIELDS = [
    "alert_uid",
    "schema_version",
    "source",
    "timestamps",
    "host",
    "rule",
    "event",
    "severity",
    "mitre",
    "entities",
    "scenario_context",
    "evidence",
    "normalization",
]

REQUIRED_EVIDENCE_FIELDS = [
    "evidence_id",
    "raw_alert_sha256",
    "raw_file_sha256",
    "raw_file_name",
    "raw_line_number",
    "ingestion_batch_id",
]


@dataclass(frozen=True)
class QaPaths:
    raw_alerts: Path
    lineage: Path
    evidence: Path
    normalized: Path
    warnings: Path
    errors: Path
    runtime_schema: Path
    runtime_views: Path
    runtime_api_files: list[Path]
    metrics_output: Path
    leakage_output: Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def percent(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.00"
    return f"{(numerator / denominator) * 100:.2f}"


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def load_normalized_alerts(path: Path) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            stripped = line.strip()
            if stripped:
                alerts.append(json.loads(stripped))
    return alerts


def count_valid_timestamps(alerts: list[dict[str, Any]]) -> int:
    valid = 0
    for alert in alerts:
        value = alert.get("timestamps", {}).get("event_time_utc")
        if not isinstance(value, str) or not value:
            continue
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            continue
        valid += 1
    return valid


def count_required_field_complete(alerts: list[dict[str, Any]]) -> int:
    return sum(
        1
        for alert in alerts
        if all(field in alert and alert[field] is not None for field in REQUIRED_NORMALIZED_TOP_LEVEL_FIELDS)
    )


def count_lineage_complete(alerts: list[dict[str, Any]], lineage_rows: list[dict[str, str]], evidence_rows: list[dict[str, str]]) -> int:
    lineage_by_uid = {row.get("alert_uid"): row for row in lineage_rows}
    evidence_by_uid = {row.get("alert_uid"): row for row in evidence_rows}
    complete = 0

    for alert in alerts:
        alert_uid = alert.get("alert_uid")
        evidence = alert.get("evidence", {})
        lineage_row = lineage_by_uid.get(alert_uid)
        evidence_row = evidence_by_uid.get(alert_uid)
        if not lineage_row or not evidence_row:
            continue
        if not all(evidence.get(field) not in (None, "") for field in REQUIRED_EVIDENCE_FIELDS):
            continue
        if str(evidence.get("raw_line_number")) != str(lineage_row.get("raw_line_number")):
            continue
        if evidence.get("evidence_id") != evidence_row.get("evidence_id"):
            continue
        complete += 1

    return complete


def count_mitre_mapped(alerts: list[dict[str, Any]]) -> int:
    return sum(
        1
        for alert in alerts
        if alert.get("mitre", {}).get("technique_ids") or alert.get("mitre", {}).get("tactics")
    )


def count_forbidden_terms_in_text(text: str, forbidden_terms: list[str] = FORBIDDEN_RUNTIME_TERMS) -> dict[str, int]:
    lowered = text.lower()
    return {term: lowered.count(term) for term in forbidden_terms if lowered.count(term) > 0}


def scan_text_file(path: Path, forbidden_terms: list[str] = FORBIDDEN_RUNTIME_TERMS) -> dict[str, int]:
    return count_forbidden_terms_in_text(path.read_text(encoding="utf-8", errors="ignore"), forbidden_terms)


def scan_jsonl_runtime_objects(path: Path, forbidden_terms: list[str] = FORBIDDEN_RUNTIME_TERMS) -> dict[str, int]:
    counts = {term: 0 for term in forbidden_terms}
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            lowered = line.lower()
            for term in forbidden_terms:
                counts[term] += lowered.count(term)
    return {term: count for term, count in counts.items() if count > 0}


def metric_row(metric: str, value: str, numerator: int | str, denominator: int | str, target: str, status: str, notes: str) -> dict[str, str]:
    return {
        "metric": metric,
        "value": value,
        "numerator": str(numerator),
        "denominator": str(denominator),
        "target": target,
        "status": status,
        "notes": notes,
    }


def build_normalization_metrics(paths: QaPaths) -> list[dict[str, str]]:
    parse_result = parse_wazuh_jsonl(paths.raw_alerts)
    normalized_alerts = load_normalized_alerts(paths.normalized)
    lineage_rows = load_csv_rows(paths.lineage)
    evidence_rows = load_csv_rows(paths.evidence)
    warning_rows = load_csv_rows(paths.warnings)
    error_rows = load_csv_rows(paths.errors)

    raw_denominator = parse_result.parsed_count + parse_result.invalid_count
    required_complete = count_required_field_complete(normalized_alerts)
    timestamp_valid = count_valid_timestamps(normalized_alerts)
    lineage_complete = count_lineage_complete(normalized_alerts, lineage_rows, evidence_rows)
    mitre_mapped = count_mitre_mapped(normalized_alerts)
    leakage_counts = scan_jsonl_runtime_objects(paths.normalized)
    exposure_count = sum(leakage_counts.values())

    rows = [
        metric_row(
            "parse_success_rate",
            percent(parse_result.parsed_count, raw_denominator),
            parse_result.parsed_count,
            raw_denominator,
            ">=99.00",
            "pass" if raw_denominator and parse_result.parsed_count / raw_denominator >= 0.99 else "fail",
            f"{parse_result.invalid_count} invalid JSON lines; {parse_result.blank_lines} blank lines.",
        ),
        metric_row(
            "normalization_success_rate",
            percent(len(normalized_alerts), parse_result.parsed_count),
            len(normalized_alerts),
            parse_result.parsed_count,
            ">=95.00",
            "pass" if parse_result.parsed_count and len(normalized_alerts) / parse_result.parsed_count >= 0.95 else "fail",
            "Measured as normalized records generated per parsed raw alert.",
        ),
        metric_row(
            "required_field_completeness",
            percent(required_complete, len(normalized_alerts)),
            required_complete,
            len(normalized_alerts),
            ">=95.00",
            "pass" if normalized_alerts and required_complete / len(normalized_alerts) >= 0.95 else "fail",
            "Required top-level canonical runtime fields are present.",
        ),
        metric_row(
            "timestamp_normalization_rate",
            percent(timestamp_valid, len(normalized_alerts)),
            timestamp_valid,
            len(normalized_alerts),
            "100.00 for valid timestamps",
            "pass" if timestamp_valid == len(normalized_alerts) else "fail",
            "All generated normalized alerts must have parseable event_time_utc.",
        ),
        metric_row(
            "raw_lineage_coverage",
            percent(lineage_complete, len(normalized_alerts)),
            lineage_complete,
            len(normalized_alerts),
            "100.00",
            "pass" if lineage_complete == len(normalized_alerts) else "fail",
            "Evidence and lineage rows match normalized alert evidence references.",
        ),
        metric_row(
            "mitre_preservation_rate",
            percent(mitre_mapped, len(normalized_alerts)),
            mitre_mapped,
            len(normalized_alerts),
            "measured",
            "measured",
            "Percent of normalized alerts with Wazuh MITRE IDs or tactics preserved.",
        ),
        metric_row(
            "runtime_ground_truth_exposure_count",
            str(exposure_count),
            exposure_count,
            "runtime normalized artifact",
            "0",
            "pass" if exposure_count == 0 else "fail",
            "Forbidden answer-key terms scanned in normalized runtime output.",
        ),
        metric_row(
            "label_linkage_rate",
            "not_available",
            "not_loaded",
            "800 expected labels",
            "100.00 after eval load",
            "not_available",
            "Evaluation loading is intentionally separate from runtime ingestion.",
        ),
        metric_row(
            "casebook_linkage_rate",
            "not_available",
            "not_loaded",
            "50 expected cases",
            "100.00 after eval load",
            "not_available",
            "Evaluation loading is intentionally separate from runtime ingestion.",
        ),
        metric_row(
            "normalization_warning_count",
            str(len(warning_rows)),
            len(warning_rows),
            len(normalized_alerts),
            "measured",
            "measured",
            "Warnings are expected for missing MITRE metadata, missing agent IP, or unmapped categories.",
        ),
        metric_row(
            "normalization_error_count",
            str(len(error_rows)),
            len(error_rows),
            len(normalized_alerts),
            "0 preferred",
            "pass" if len(error_rows) == 0 else "review",
            "Errors are recorded instead of hidden.",
        ),
    ]
    return rows


def leakage_row(check_name: str, path: Path | str, counts: dict[str, int], details: str) -> dict[str, str]:
    exposure_count = sum(counts.values())
    return {
        "check_name": check_name,
        "artifact": str(path),
        "status": "pass" if exposure_count == 0 else "fail",
        "exposure_count": str(exposure_count),
        "matched_terms": ";".join(f"{term}:{count}" for term, count in sorted(counts.items())),
        "details": details,
        "checked_at_utc": utc_now_iso(),
    }


def build_leakage_audit(paths: QaPaths) -> list[dict[str, str]]:
    rows = [
        leakage_row(
            "normalized_runtime_jsonl_forbidden_terms",
            paths.normalized,
            scan_jsonl_runtime_objects(paths.normalized),
            "Runtime normalized alerts must not contain ground-truth or answer-key fields.",
        ),
        leakage_row(
            "runtime_schema_forbidden_terms",
            paths.runtime_schema,
            scan_text_file(paths.runtime_schema),
            "Runtime SQL schema must not define evaluation-only columns or tables.",
        ),
        leakage_row(
            "runtime_views_forbidden_terms",
            paths.runtime_views,
            scan_text_file(paths.runtime_views),
            "Runtime views must not reference eval schema or answer-key terms.",
        ),
    ]

    for api_file in paths.runtime_api_files:
        rows.append(
            leakage_row(
                f"runtime_api_{api_file.stem}_forbidden_terms",
                api_file,
                scan_text_file(api_file),
                "Runtime API route file must not expose evaluation-only data.",
            )
        )

    return rows


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_qa(paths: QaPaths) -> dict[str, Any]:
    metrics = build_normalization_metrics(paths)
    leakage = build_leakage_audit(paths)
    write_csv(paths.metrics_output, metrics)
    write_csv(paths.leakage_output, leakage)
    return {
        "metrics_output": str(paths.metrics_output),
        "leakage_output": str(paths.leakage_output),
        "metric_count": len(metrics),
        "leakage_check_count": len(leakage),
        "failed_metric_count": sum(1 for row in metrics if row["status"] == "fail"),
        "failed_leakage_check_count": sum(1 for row in leakage if row["status"] == "fail"),
    }
