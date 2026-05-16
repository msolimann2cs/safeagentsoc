from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import json
import sys
from typing import Any


MISSING = "__missing__"


@dataclass(frozen=True)
class ExtractionPaths:
    normalized_alerts: Path
    output_dir: Path
    report_output: Path | None = None


def load_normalized_alerts(path: Path) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            stripped = line.strip()
            if stripped:
                alerts.append(json.loads(stripped))
    return alerts


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def clean(value: Any) -> str:
    if value is None or value == "":
        return MISSING
    if isinstance(value, list):
        return ";".join(str(item) for item in value if item not in (None, ""))
    return str(value)


def actual(value: Any) -> str:
    cleaned = clean(value)
    return "" if cleaned == MISSING else cleaned


def update_seen(row: dict[str, Any], event_time: str) -> None:
    if not row.get("first_seen") or event_time < row["first_seen"]:
        row["first_seen"] = event_time
    if not row.get("last_seen") or event_time > row["last_seen"]:
        row["last_seen"] = event_time


def add_sample(row: dict[str, Any], field: str, value: str, limit: int = 8) -> None:
    if not value or value == MISSING:
        return
    values = set(str(row.get(field, "")).split(";")) if row.get(field) else set()
    values.discard("")
    if len(values) < limit:
        values.add(value)
    row[field] = ";".join(sorted(values))


def count_by_key(store: dict[tuple[str, ...], dict[str, Any]], key: tuple[str, ...], event_time: str) -> dict[str, Any]:
    row = store.setdefault(key, {"alert_count": 0, "first_seen": event_time, "last_seen": event_time})
    row["alert_count"] += 1
    update_seen(row, event_time)
    return row


def extract_observed_entities(alerts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    hosts: dict[tuple[str, str], dict[str, Any]] = {}
    users: dict[tuple[str, str], dict[str, Any]] = {}
    ips: dict[tuple[str, str], dict[str, Any]] = {}
    processes: dict[tuple[str, str], dict[str, Any]] = {}
    rules: dict[tuple[str, str], dict[str, Any]] = {}
    summary_counts = defaultdict(int)

    for alert in alerts:
        event_time = clean(alert.get("timestamps", {}).get("event_time_utc"))
        host = alert.get("host", {})
        entities = alert.get("entities", {})
        user = entities.get("user", {}) or {}
        process = entities.get("process", {}) or {}
        network = entities.get("network", {}) or {}
        rule = alert.get("rule", {})
        mitre = alert.get("mitre", {})
        event = alert.get("event", {})
        severity = alert.get("severity", {})

        observed_host = clean(host.get("hostname") or host.get("agent_name"))
        agent_name = clean(host.get("agent_name"))
        agent_ip = clean(host.get("agent_ip"))
        platform = clean(host.get("platform"))
        host_row = count_by_key(hosts, (observed_host, agent_name), event_time)
        host_row.update(
            {
                "observed_host": observed_host,
                "agent_name": agent_name,
            }
        )
        add_sample(host_row, "agent_ip", actual(agent_ip))
        add_sample(host_row, "platform", actual(platform))

        if agent_ip == MISSING:
            summary_counts["missing_agent_ip_alerts"] += 1
        else:
            ip_row = count_by_key(ips, ("agent_ip", agent_ip), event_time)
            ip_row.update({"ip_role": "agent_ip", "ip_address": agent_ip})
            add_sample(ip_row, "sample_agent_names", actual(agent_name))

        username = clean(user.get("username"))
        if username == MISSING:
            summary_counts["missing_user_alerts"] += 1
        else:
            user_key = (username, clean(user.get("domain")))
            user_row = count_by_key(users, user_key, event_time)
            user_row.update(
                {
                    "observed_username": username,
                    "domain": "" if user_key[1] == MISSING else user_key[1],
                    "privilege_hint": actual(user.get("privilege_hint")),
                }
            )
            add_sample(user_row, "sample_agent_names", actual(agent_name))

        for role, value in [("src_ip", network.get("src_ip")), ("dst_ip", network.get("dst_ip"))]:
            ip_address = clean(value)
            if ip_address == MISSING:
                summary_counts[f"missing_{role}_alerts"] += 1
                continue
            ip_row = count_by_key(ips, (role, ip_address), event_time)
            ip_row.update({"ip_role": role, "ip_address": ip_address})
            add_sample(ip_row, "sample_agent_names", actual(agent_name))

        process_name = clean(process.get("name"))
        command_line = clean(process.get("command_line"))
        if process_name == MISSING and command_line == MISSING:
            summary_counts["missing_process_alerts"] += 1
        else:
            proc_row = count_by_key(processes, (process_name, command_line), event_time)
            proc_row.update(
                {
                    "process_name": "" if process_name == MISSING else process_name,
                    "command_line": "" if command_line == MISSING else command_line,
                    "process_path": actual(process.get("path")),
                }
            )
            add_sample(proc_row, "sample_agent_names", actual(agent_name))

        rule_id = clean(rule.get("rule_id"))
        rule_description = clean(rule.get("rule_description"))
        if rule_id == MISSING:
            summary_counts["missing_rule_id_alerts"] += 1
        else:
            rule_row = count_by_key(rules, (rule_id, rule_description), event_time)
            rule_row.update(
                {
                    "rule_id": rule_id,
                    "rule_description": "" if rule_description == MISSING else rule_description,
                    "rule_level": actual(rule.get("rule_level")),
                    "event_category": actual(event.get("category")),
                    "event_action": actual(event.get("action")),
                    "severity_normalized": actual(severity.get("normalized")),
                    "mitre_technique_ids": clean(mitre.get("technique_ids", [])),
                    "mitre_tactics": clean(mitre.get("tactics", [])),
                }
            )
            add_sample(rule_row, "sample_agent_names", actual(agent_name))

    summary_rows = [
        {"metric": "total_normalized_alerts", "value": len(alerts), "notes": "Runtime normalized alerts processed."},
        {"metric": "observed_host_rows", "value": len(hosts), "notes": "Distinct observed host and agent-name combinations; IPs and platforms are aggregated."},
        {"metric": "observed_user_rows", "value": len(users), "notes": "Distinct observed user/domain combinations."},
        {"metric": "observed_ip_rows", "value": len(ips), "notes": "Distinct observed IPs by role."},
        {"metric": "observed_process_rows", "value": len(processes), "notes": "Distinct process name and command line combinations."},
        {"metric": "observed_rule_rows", "value": len(rules), "notes": "Distinct Wazuh rule ID and description combinations."},
    ]
    for metric in sorted(summary_counts):
        summary_rows.append({"metric": metric, "value": summary_counts[metric], "notes": "Missing-value count across normalized alerts."})

    return {
        "hosts": sorted(hosts.values(), key=lambda row: (-int(row["alert_count"]), row["observed_host"], row.get("agent_ip", ""))),
        "users": sorted(users.values(), key=lambda row: (-int(row["alert_count"]), row["observed_username"])),
        "ips": sorted(ips.values(), key=lambda row: (row["ip_role"], -int(row["alert_count"]), row["ip_address"])),
        "processes": sorted(processes.values(), key=lambda row: (-int(row["alert_count"]), row["process_name"], row["command_line"])),
        "rules": sorted(rules.values(), key=lambda row: (-int(row["alert_count"]), row["rule_id"])),
        "summary": summary_rows,
    }


def write_observed_outputs(paths: ExtractionPaths, extracted: dict[str, list[dict[str, Any]]]) -> dict[str, Path]:
    outputs = {
        "observed_hosts": paths.output_dir / "observed_hosts.csv",
        "observed_users": paths.output_dir / "observed_users.csv",
        "observed_ips": paths.output_dir / "observed_ips.csv",
        "observed_processes": paths.output_dir / "observed_processes.csv",
        "observed_rules": paths.output_dir / "observed_rules.csv",
        "observed_entities_summary": paths.output_dir / "observed_entities_summary.csv",
    }
    write_csv(outputs["observed_hosts"], ["observed_host", "agent_name", "agent_ip", "platform", "alert_count", "first_seen", "last_seen"], extracted["hosts"])
    write_csv(outputs["observed_users"], ["observed_username", "domain", "privilege_hint", "sample_agent_names", "alert_count", "first_seen", "last_seen"], extracted["users"])
    write_csv(outputs["observed_ips"], ["ip_role", "ip_address", "sample_agent_names", "alert_count", "first_seen", "last_seen"], extracted["ips"])
    write_csv(outputs["observed_processes"], ["process_name", "command_line", "process_path", "sample_agent_names", "alert_count", "first_seen", "last_seen"], extracted["processes"])
    write_csv(outputs["observed_rules"], ["rule_id", "rule_level", "rule_description", "event_category", "event_action", "severity_normalized", "mitre_technique_ids", "mitre_tactics", "sample_agent_names", "alert_count", "first_seen", "last_seen"], extracted["rules"])
    write_csv(outputs["observed_entities_summary"], ["metric", "value", "notes"], extracted["summary"])
    return outputs


def write_report(path: Path, extracted: dict[str, list[dict[str, Any]]], outputs: dict[str, Path]) -> None:
    summary = {row["metric"]: row["value"] for row in extracted["summary"]}
    lines = [
        "# Observed Entity Extraction Report",
        "",
        "## Scope",
        "",
        "Sprint 1 extracted observed entities from Phase 3 runtime normalized alerts only. No evaluation labels, casebook answers, or linkage files were used.",
        "",
        "## Counts",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key in [
        "total_normalized_alerts",
        "observed_host_rows",
        "observed_user_rows",
        "observed_ip_rows",
        "observed_process_rows",
        "observed_rule_rows",
        "missing_user_alerts",
        "missing_agent_ip_alerts",
    ]:
        if key in summary:
            lines.append(f"| `{key}` | {summary[key]} |")
    lines.extend(
        [
            "",
            "## Top Hosts",
            "",
            "| Observed Host | Agent IP | Platform | Alerts |",
            "|---|---|---|---:|",
        ]
    )
    for row in extracted["hosts"][:5]:
        lines.append(f"| `{row['observed_host']}` | `{row.get('agent_ip', '')}` | `{row['platform']}` | {row['alert_count']} |")
    lines.extend(["", "## Outputs", ""])
    for name, output in outputs.items():
        lines.append(f"- `{name}`: `{output}`")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_extraction(paths: ExtractionPaths) -> dict[str, Any]:
    alerts = load_normalized_alerts(paths.normalized_alerts)
    extracted = extract_observed_entities(alerts)
    outputs = write_observed_outputs(paths, extracted)
    if paths.report_output:
        write_report(paths.report_output, extracted, outputs)
    return {
        "total_normalized_alerts": len(alerts),
        "observed_host_rows": len(extracted["hosts"]),
        "observed_user_rows": len(extracted["users"]),
        "observed_ip_rows": len(extracted["ips"]),
        "observed_process_rows": len(extracted["processes"]),
        "observed_rule_rows": len(extracted["rules"]),
        "output_dir": str(paths.output_dir),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract observed runtime entities from Phase 3 normalized alerts.")
    parser.add_argument("--normalized-alerts", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--report-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if not args.normalized_alerts.exists():
        print(f"[FAIL] Missing normalized alerts: {args.normalized_alerts}", file=sys.stderr)
        return 1
    result = run_extraction(
        ExtractionPaths(
            normalized_alerts=args.normalized_alerts,
            output_dir=args.output_dir,
            report_output=args.report_output,
        )
    )
    for key, value in result.items():
        print(f"[OK] {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
