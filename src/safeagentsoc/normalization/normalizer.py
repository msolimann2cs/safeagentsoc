from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

from safeagentsoc.adapters.wazuh.jsonl_parser import ParsedWazuhAlert, get_nested, parse_wazuh_jsonl
from safeagentsoc.normalization.event_taxonomy import infer_event_action, infer_event_category, infer_event_outcome
from safeagentsoc.normalization.mappings import (
    as_int,
    as_list,
    as_string,
    extract_file,
    extract_network,
    extract_process,
    extract_user,
    infer_platform,
)
from safeagentsoc.normalization.severity import normalize_severity
from safeagentsoc.evidence.uid import sha256_text


NORMALIZER_VERSION = "normalizer_v1.0.0"

WARNING_FIELDS = [
    "warning_id",
    "alert_uid",
    "raw_reference_id",
    "warning_type",
    "field_path",
    "warning_message",
    "created_at_utc",
]

ERROR_FIELDS = [
    "error_id",
    "alert_uid",
    "raw_reference_id",
    "error_type",
    "field_path",
    "error_message",
    "created_at_utc",
]


@dataclass(frozen=True)
class NormalizationWarning:
    warning_id: str
    alert_uid: str | None
    raw_reference_id: str | None
    warning_type: str
    field_path: str | None
    warning_message: str
    created_at_utc: str


@dataclass(frozen=True)
class NormalizationError:
    error_id: str
    alert_uid: str | None
    raw_reference_id: str | None
    error_type: str
    field_path: str | None
    error_message: str
    created_at_utc: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_timestamp_utc(value: Any) -> tuple[str | None, str | None]:
    raw = as_string(value)
    if raw is None:
        return None, "missing timestamp"

    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        return None, str(exc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(), None


def load_lineage_by_line(path: Path) -> dict[int, dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as file:
        return {
            int(row["raw_line_number"]): row
            for row in csv.DictReader(file)
        }


def stable_id(prefix: str, parts: list[str | None]) -> str:
    return prefix + "_" + sha256_text("|".join(part or "" for part in parts))[:32]


def make_warning(alert_uid: str | None, evidence_id: str | None, warning_type: str, field_path: str | None, message: str, created_at_utc: str) -> NormalizationWarning:
    return NormalizationWarning(
        warning_id=stable_id("warning", [alert_uid, evidence_id, warning_type, field_path, message]),
        alert_uid=alert_uid,
        raw_reference_id=evidence_id,
        warning_type=warning_type,
        field_path=field_path,
        warning_message=message,
        created_at_utc=created_at_utc,
    )


def make_error(alert_uid: str | None, evidence_id: str | None, error_type: str, field_path: str | None, message: str, created_at_utc: str) -> NormalizationError:
    return NormalizationError(
        error_id=stable_id("error", [alert_uid, evidence_id, error_type, field_path, message]),
        alert_uid=alert_uid,
        raw_reference_id=evidence_id,
        error_type=error_type,
        field_path=field_path,
        error_message=message,
        created_at_utc=created_at_utc,
    )


def normalize_alert(alert: ParsedWazuhAlert, lineage: dict[str, str] | None, normalized_at_utc: str) -> tuple[dict[str, Any] | None, list[NormalizationWarning], list[NormalizationError]]:
    alert_uid = lineage.get("alert_uid") if lineage else None
    evidence_id = lineage.get("evidence_id") if lineage else None
    warnings: list[NormalizationWarning] = []
    errors: list[NormalizationError] = []

    if lineage is None:
        errors.append(make_error(None, None, "missing_lineage", "raw_line_number", f"No lineage row for raw line {alert.line_number}.", normalized_at_utc))
        return None, warnings, errors

    event_time_utc, timestamp_error = parse_timestamp_utc(get_nested(alert.raw, "timestamp"))
    if event_time_utc is None:
        errors.append(make_error(alert_uid, evidence_id, "timestamp_parse_failed", "timestamp", timestamp_error or "Timestamp could not be parsed.", normalized_at_utc))
        event_time_utc = normalized_at_utc

    rule_level = as_int(get_nested(alert.raw, "rule.level"))
    rule_id = as_string(get_nested(alert.raw, "rule.id"))
    rule_description = as_string(get_nested(alert.raw, "rule.description"))
    rule_groups = as_list(get_nested(alert.raw, "rule.groups"))
    decoder_name = as_string(get_nested(alert.raw, "decoder.name"))
    decoder_parent = as_string(get_nested(alert.raw, "decoder.parent"))
    severity_label, severity_score = normalize_severity(rule_level)
    platform = infer_platform(alert.raw)
    mitre_ids = as_list(get_nested(alert.raw, "rule.mitre.id"))
    mitre_names = as_list(get_nested(alert.raw, "rule.mitre.technique"))
    mitre_tactics = as_list(get_nested(alert.raw, "rule.mitre.tactic"))
    event_category = infer_event_category(rule_description, decoder_name, rule_groups)
    event_action = infer_event_action(rule_description, decoder_name, rule_id)
    event_outcome = infer_event_outcome(rule_description, rule_level)

    if decoder_name is None:
        warnings.append(make_warning(alert_uid, evidence_id, "missing_field", "decoder.name", "Wazuh alert has no decoder name.", normalized_at_utc))
    if as_string(get_nested(alert.raw, "agent.ip")) is None:
        warnings.append(make_warning(alert_uid, evidence_id, "missing_field", "agent.ip", "Wazuh alert has no agent IP.", normalized_at_utc))
    if not mitre_ids and not mitre_tactics:
        warnings.append(make_warning(alert_uid, evidence_id, "missing_mitre", "rule.mitre", "Wazuh rule has no MITRE mapping.", normalized_at_utc))
    if event_category == "unknown":
        warnings.append(make_warning(alert_uid, evidence_id, "unmapped_category", "rule.description", "Event category could not be confidently mapped.", normalized_at_utc))
    if platform == "unknown":
        warnings.append(make_warning(alert_uid, evidence_id, "partial_metadata", "host.platform", "Host platform could not be inferred.", normalized_at_utc))

    status = "failed" if errors else "partial" if warnings else "success"

    normalized_alert = {
        "alert_uid": alert_uid,
        "schema_version": "1.0.0",
        "source": {
            "source_system": lineage["source_system"],
            "source_adapter": lineage["source_adapter"],
            "source_type": "siem",
            "source_event_id": as_string(get_nested(alert.raw, "id")),
            "source_location": as_string(get_nested(alert.raw, "location")),
            "source_rule_engine": "wazuh_ruleset",
        },
        "timestamps": {
            "event_time_utc": event_time_utc,
            "source_time_raw": as_string(get_nested(alert.raw, "timestamp")),
            "ingested_at_utc": lineage["ingested_at_utc"],
            "normalized_at_utc": normalized_at_utc,
        },
        "host": {
            "hostname": as_string(get_nested(alert.raw, "agent.name")),
            "agent_id": as_string(get_nested(alert.raw, "agent.id")),
            "agent_name": as_string(get_nested(alert.raw, "agent.name")),
            "agent_ip": as_string(get_nested(alert.raw, "agent.ip")),
            "platform": platform,
            "asset_role": "endpoint" if platform in {"windows", "linux", "macos"} else "unknown",
        },
        "rule": {
            "rule_id": rule_id,
            "rule_level": rule_level,
            "rule_description": rule_description,
            "rule_groups": rule_groups,
            "rule_firedtimes": as_int(get_nested(alert.raw, "rule.firedtimes")),
        },
        "decoder": {
            "decoder_name": decoder_name,
            "decoder_parent": decoder_parent,
        },
        "event": {
            "kind": "alert",
            "category": event_category,
            "action": event_action,
            "outcome": event_outcome,
            "description": rule_description,
        },
        "severity": {
            "original_level": rule_level,
            "original_label": None,
            "normalized": severity_label,
            "normalized_score": severity_score,
        },
        "mitre": {
            "technique_ids": mitre_ids,
            "technique_names": mitre_names,
            "tactics": mitre_tactics,
            "mapping_source": "wazuh_rule" if mitre_ids or mitre_tactics else "none",
        },
        "entities": {
            "user": extract_user(alert.raw),
            "process": extract_process(alert.raw),
            "network": extract_network(alert.raw),
            "file": extract_file(alert.raw),
        },
        "scenario_context": {
            "scenario_id": None,
            "campaign_id": None,
            "run_id": None,
            "execution_mode": None,
            "metadata_quality": "not_recovered",
            "benchmark_link_available": False,
        },
        "evidence": {
            "evidence_id": lineage["evidence_id"],
            "raw_alert_sha256": lineage["raw_alert_sha256"],
            "raw_file_sha256": lineage["raw_file_sha256"],
            "raw_file_name": lineage["raw_file_name"],
            "raw_line_number": int(lineage["raw_line_number"]),
            "ingestion_batch_id": lineage["ingestion_batch_id"],
            "evidence_confidence": "high",
        },
        "normalization": {
            "status": status,
            "normalizer_version": NORMALIZER_VERSION,
            "warnings": [warning.warning_type for warning in warnings],
            "errors": [error.error_type for error in errors],
        },
    }

    return normalized_alert, warnings, errors


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def normalize_dataset(input_path: Path, lineage_path: Path, normalized_output: Path, warnings_output: Path, errors_output: Path) -> dict[str, Any]:
    parse_result = parse_wazuh_jsonl(input_path)
    lineage_by_line = load_lineage_by_line(lineage_path)
    normalized_at_utc = utc_now_iso()
    normalized_count = 0
    status_counts = {"success": 0, "partial": 0, "failed": 0}
    warning_rows: list[dict[str, Any]] = []
    error_rows: list[dict[str, Any]] = []
    category_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}

    normalized_output.parent.mkdir(parents=True, exist_ok=True)
    with normalized_output.open("w", encoding="utf-8") as output_file:
        for alert in parse_result.alerts:
            normalized_alert, warnings, errors = normalize_alert(alert, lineage_by_line.get(alert.line_number), normalized_at_utc)

            warning_rows.extend(asdict(warning) for warning in warnings)
            error_rows.extend(asdict(error) for error in errors)

            if normalized_alert is None:
                continue

            normalized_count += 1
            status = normalized_alert["normalization"]["status"]
            category = normalized_alert["event"]["category"]
            severity = normalized_alert["severity"]["normalized"]
            status_counts[status] += 1
            category_counts[category] = category_counts.get(category, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            output_file.write(json.dumps(normalized_alert, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")

    write_csv(warnings_output, WARNING_FIELDS, warning_rows)
    write_csv(errors_output, ERROR_FIELDS, error_rows)

    return {
        "input_file": str(input_path),
        "lineage_file": str(lineage_path),
        "parsed_alerts": parse_result.parsed_count,
        "invalid_json_lines": parse_result.invalid_count,
        "normalized_records": normalized_count,
        "warning_count": len(warning_rows),
        "error_count": len(error_rows),
        "status_counts": status_counts,
        "category_counts": category_counts,
        "severity_counts": severity_counts,
        "normalized_at_utc": normalized_at_utc,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize Wazuh JSONL alerts into SafeAgentSOC canonical alerts.")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--lineage", required=True, type=Path)
    parser.add_argument("--normalized-output", required=True, type=Path)
    parser.add_argument("--warnings-output", required=True, type=Path)
    parser.add_argument("--errors-output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    for path_name in ["input", "lineage"]:
        path = getattr(args, path_name)
        if not path.exists():
            print(f"[FAIL] Missing {path_name}: {path}", file=sys.stderr)
            return 1

    summary = normalize_dataset(
        input_path=args.input,
        lineage_path=args.lineage,
        normalized_output=args.normalized_output,
        warnings_output=args.warnings_output,
        errors_output=args.errors_output,
    )

    print(f"[OK] Parsed alerts: {summary['parsed_alerts']}")
    print(f"[OK] Normalized records: {summary['normalized_records']}")
    print(f"[OK] Warning rows: {summary['warning_count']}")
    print(f"[OK] Error rows: {summary['error_count']}")
    print(f"[OK] Normalized output: {args.normalized_output}")
    print(f"[OK] Warnings output: {args.warnings_output}")
    print(f"[OK] Errors output: {args.errors_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
