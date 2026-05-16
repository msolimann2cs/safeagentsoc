from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

from safeagentsoc.adapters.wazuh.jsonl_parser import (
    ParsedWazuhAlert,
    flatten_json,
    get_nested,
    parse_wazuh_jsonl,
)


DEFAULT_REQUIRED_FIELDS = [
    "timestamp",
    "agent.id",
    "agent.name",
    "agent.ip",
    "rule.id",
    "rule.level",
    "rule.description",
    "rule.groups",
    "decoder.name",
    "location",
]


def scalar_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def normalize_counter_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "|".join(str(item) for item in value)
    return str(value)


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None

    candidate = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class WazuhFieldProfiler:
    def __init__(self, required_fields: list[str] | None = None) -> None:
        self.required_fields = required_fields or DEFAULT_REQUIRED_FIELDS

    def profile(self, alerts: list[ParsedWazuhAlert]) -> dict[str, Any]:
        total = len(alerts)
        field_presence: Counter[str] = Counter()
        field_types: dict[str, Counter[str]] = defaultdict(Counter)
        missing_required: Counter[str] = Counter()
        agents: Counter[str] = Counter()
        rules: Counter[tuple[str, str, str]] = Counter()
        decoders: Counter[str] = Counter()
        mitre_ids: Counter[str] = Counter()
        mitre_tactics: Counter[str] = Counter()
        timestamps: list[datetime] = []
        invalid_timestamps = 0

        for alert in alerts:
            flattened = flatten_json(alert.raw)

            for field, value in flattened.items():
                field_presence[field] += 1
                field_types[field][scalar_type(value)] += 1

            for field in self.required_fields:
                value = get_nested(alert.raw, field)
                if value is None or value == "":
                    missing_required[field] += 1

            agent_name = normalize_counter_value(get_nested(alert.raw, "agent.name")) or "unknown"
            agent_id = normalize_counter_value(get_nested(alert.raw, "agent.id")) or "unknown"
            agent_ip = normalize_counter_value(get_nested(alert.raw, "agent.ip")) or "unknown"
            agents[f"{agent_name}|{agent_id}|{agent_ip}"] += 1

            rule_id = normalize_counter_value(get_nested(alert.raw, "rule.id")) or "unknown"
            rule_level = normalize_counter_value(get_nested(alert.raw, "rule.level")) or "unknown"
            rule_description = normalize_counter_value(get_nested(alert.raw, "rule.description")) or "unknown"
            rules[(rule_id, rule_level, rule_description)] += 1

            decoder = normalize_counter_value(get_nested(alert.raw, "decoder.name")) or "unknown"
            decoders[decoder] += 1

            technique_ids = get_nested(alert.raw, "rule.mitre.id")
            tactics = get_nested(alert.raw, "rule.mitre.tactic")
            for technique_id in technique_ids if isinstance(technique_ids, list) else [technique_ids]:
                if technique_id:
                    mitre_ids[str(technique_id)] += 1
            for tactic in tactics if isinstance(tactics, list) else [tactics]:
                if tactic:
                    mitre_tactics[str(tactic)] += 1

            timestamp = parse_timestamp(get_nested(alert.raw, "timestamp"))
            if timestamp is None:
                invalid_timestamps += 1
            else:
                timestamps.append(timestamp)

        return {
            "total_alerts": total,
            "field_presence": field_presence,
            "field_types": field_types,
            "missing_required": missing_required,
            "agents": agents,
            "rules": rules,
            "decoders": decoders,
            "mitre_ids": mitre_ids,
            "mitre_tactics": mitre_tactics,
            "timestamps": timestamps,
            "invalid_timestamps": invalid_timestamps,
        }


def percent(count: int, total: int) -> str:
    if total == 0:
        return "0.00"
    return f"{(count / total) * 100:.2f}"


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_profiles(input_path: Path, output_dir: Path) -> dict[str, Any]:
    parse_result = parse_wazuh_jsonl(input_path)
    profiler = WazuhFieldProfiler()
    profile = profiler.profile(parse_result.alerts)
    total = profile["total_alerts"]
    output_dir.mkdir(parents=True, exist_ok=True)

    field_frequency_rows = [
        {
            "field": field,
            "present_count": count,
            "present_percent": percent(count, total),
            "missing_count": total - count,
            "missing_percent": percent(total - count, total),
        }
        for field, count in profile["field_presence"].most_common()
    ]
    write_csv(
        output_dir / "field_frequency_report.csv",
        ["field", "present_count", "present_percent", "missing_count", "missing_percent"],
        field_frequency_rows,
    )

    missing_rows = [
        {
            "field": field,
            "missing_count": count,
            "missing_percent": percent(count, total),
        }
        for field, count in profile["missing_required"].most_common()
    ]
    write_csv(output_dir / "missing_field_report.csv", ["field", "missing_count", "missing_percent"], missing_rows)

    type_rows: list[dict[str, Any]] = []
    for field, type_counts in sorted(profile["field_types"].items()):
        for type_name, count in type_counts.most_common():
            type_rows.append({"field": field, "type": type_name, "count": count, "percent": percent(count, total)})
    write_csv(output_dir / "field_type_profile.csv", ["field", "type", "count", "percent"], type_rows)

    agent_rows = []
    for value, count in profile["agents"].most_common():
        agent_name, agent_id, agent_ip = value.split("|", maxsplit=2)
        agent_rows.append(
            {
                "agent_name": agent_name,
                "agent_id": agent_id,
                "agent_ip": agent_ip,
                "alert_count": count,
                "alert_percent": percent(count, total),
            }
        )
    write_csv(output_dir / "agent_distribution.csv", ["agent_name", "agent_id", "agent_ip", "alert_count", "alert_percent"], agent_rows)

    rule_rows = [
        {
            "rule_id": rule_id,
            "rule_level": rule_level,
            "rule_description": rule_description,
            "alert_count": count,
            "alert_percent": percent(count, total),
        }
        for (rule_id, rule_level, rule_description), count in profile["rules"].most_common()
    ]
    write_csv(output_dir / "rule_distribution.csv", ["rule_id", "rule_level", "rule_description", "alert_count", "alert_percent"], rule_rows)
    write_csv(output_dir / "top_noisy_rules.csv", ["rule_id", "rule_level", "rule_description", "alert_count", "alert_percent"], rule_rows[:25])

    decoder_rows = [
        {"decoder_name": decoder, "alert_count": count, "alert_percent": percent(count, total)}
        for decoder, count in profile["decoders"].most_common()
    ]
    write_csv(output_dir / "decoder_distribution.csv", ["decoder_name", "alert_count", "alert_percent"], decoder_rows)

    mitre_rows = []
    for technique_id, count in profile["mitre_ids"].most_common():
        mitre_rows.append(
            {
                "mitre_field": "rule.mitre.id",
                "value": technique_id,
                "alert_count": count,
                "alert_percent": percent(count, total),
            }
        )
    for tactic, count in profile["mitre_tactics"].most_common():
        mitre_rows.append(
            {
                "mitre_field": "rule.mitre.tactic",
                "value": tactic,
                "alert_count": count,
                "alert_percent": percent(count, total),
            }
        )
    write_csv(output_dir / "mitre_field_profile.csv", ["mitre_field", "value", "alert_count", "alert_percent"], mitre_rows)

    timestamps = profile["timestamps"]
    timestamp_rows = [
        {
            "input_file": str(input_path),
            "total_alerts": total,
            "valid_timestamp_count": len(timestamps),
            "invalid_timestamp_count": profile["invalid_timestamps"],
            "earliest_event_time_utc": min(timestamps).isoformat() if timestamps else "",
            "latest_event_time_utc": max(timestamps).isoformat() if timestamps else "",
        }
    ]
    write_csv(
        output_dir / "timestamp_profile.csv",
        [
            "input_file",
            "total_alerts",
            "valid_timestamp_count",
            "invalid_timestamp_count",
            "earliest_event_time_utc",
            "latest_event_time_utc",
        ],
        timestamp_rows,
    )

    invalid_rows = [
        {
            "line_number": invalid.line_number,
            "error": invalid.error,
            "raw_line_excerpt": invalid.raw_line,
        }
        for invalid in parse_result.invalid_lines
    ]
    write_csv(output_dir / "invalid_json_lines.csv", ["line_number", "error", "raw_line_excerpt"], invalid_rows)

    parse_summary_rows = [
        {
            "input_file": str(input_path),
            "total_lines": parse_result.total_lines,
            "parsed_alerts": parse_result.parsed_count,
            "invalid_json_lines": parse_result.invalid_count,
            "blank_lines": parse_result.blank_lines,
        }
    ]
    write_csv(
        output_dir / "parser_summary.csv",
        ["input_file", "total_lines", "parsed_alerts", "invalid_json_lines", "blank_lines"],
        parse_summary_rows,
    )

    return {
        "parse_result": parse_result,
        "profile": profile,
        "output_dir": output_dir,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Profile raw Wazuh JSONL alert exports.")
    parser.add_argument("--input", required=True, type=Path, help="Path to raw Wazuh JSONL file.")
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory for generated CSV profile reports.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not args.input.exists():
        print(f"[FAIL] Input file not found: {args.input}", file=sys.stderr)
        return 1

    result = write_profiles(args.input, args.output_dir)
    parse_result = result["parse_result"]
    profile = result["profile"]

    print(f"[OK] Parsed alerts: {parse_result.parsed_count}")
    print(f"[OK] Invalid JSON lines: {parse_result.invalid_count}")
    print(f"[OK] Unique fields: {len(profile['field_presence'])}")
    print(f"[OK] Profile reports written to: {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
