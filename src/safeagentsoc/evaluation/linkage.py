from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any


@dataclass(frozen=True)
class LinkagePaths:
    ground_truth: Path
    casebook: Path
    casebook_detailed: Path
    fatigue_baseline: Path
    normalized_alerts: Path
    output_dir: Path


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def parse_timestamp_to_utc(value: str | None) -> str:
    if not value:
        return ""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def label_key(row: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        row.get("agent_name", ""),
        row.get("timestamp", ""),
        row.get("rule_id", ""),
        row.get("rule_description", ""),
    )


def normalized_key(alert: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        alert.get("host", {}).get("agent_name") or "",
        alert.get("timestamps", {}).get("source_time_raw") or "",
        str(alert.get("rule", {}).get("rule_id") or ""),
        alert.get("rule", {}).get("rule_description") or "",
    )


def normalized_public_fields(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase3_alert_uid": alert["alert_uid"],
        "evidence_id": alert["evidence"]["evidence_id"],
        "raw_file_name": alert["evidence"]["raw_file_name"],
        "raw_line_number": alert["evidence"]["raw_line_number"],
        "raw_alert_sha256": alert["evidence"]["raw_alert_sha256"],
        "source_event_id": alert["source"].get("source_event_id"),
        "source_location": alert["source"].get("source_location"),
        "event_time_utc": alert["timestamps"].get("event_time_utc"),
        "source_time_raw": alert["timestamps"].get("source_time_raw"),
        "normalized_agent_name": alert["host"].get("agent_name"),
        "normalized_rule_id": alert["rule"].get("rule_id"),
        "normalized_rule_description": alert["rule"].get("rule_description"),
        "event_category": alert["event"].get("category"),
        "event_action": alert["event"].get("action"),
        "event_outcome": alert["event"].get("outcome"),
        "normalized_severity": alert["severity"].get("normalized"),
        "mitre_technique_ids": ";".join(alert["mitre"].get("technique_ids", [])),
        "normalization_status": alert["normalization"].get("status"),
    }


def build_normalized_index(normalized_alerts: list[dict[str, Any]]) -> dict[tuple[str, str, str, str], list[dict[str, Any]]]:
    index: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for alert in normalized_alerts:
        index.setdefault(normalized_key(alert), []).append(alert)
    for candidates in index.values():
        candidates.sort(key=lambda item: int(item["evidence"]["raw_line_number"]))
    return index


def case_id_by_run(casebook_rows: list[dict[str, str]]) -> dict[str, str]:
    return {
        row["run_id"]: row["case_id"]
        for row in casebook_rows
        if row.get("run_id") and row.get("case_id")
    }


def case_by_id(casebook_rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    return {
        row["case_id"]: row
        for row in casebook_rows
        if row.get("case_id")
    }


def build_label_crosswalk(
    labels: list[dict[str, str]],
    normalized_index: dict[tuple[str, str, str, str], list[dict[str, Any]]],
    run_to_case: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    summary_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []

    for label in labels:
        candidates = normalized_index.get(label_key(label), [])
        phase3_ids = [candidate["alert_uid"] for candidate in candidates]
        evidence_ids = [candidate["evidence"]["evidence_id"] for candidate in candidates]
        raw_lines = [str(candidate["evidence"]["raw_line_number"]) for candidate in candidates]
        case_id = label.get("case_id") or run_to_case.get(label.get("run_id", ""), "")

        summary_rows.append(
            {
                "label_id": label.get("label_id", ""),
                "phase2_alert_uid": label.get("alert_uid", ""),
                "case_id": case_id,
                "run_id": label.get("run_id", ""),
                "campaign_id": label.get("campaign_id", ""),
                "scenario_id": label.get("scenario_id", ""),
                "agent_name": label.get("agent_name", ""),
                "label_timestamp": label.get("timestamp", ""),
                "label_timestamp_utc": parse_timestamp_to_utc(label.get("timestamp", "")),
                "rule_id": label.get("rule_id", ""),
                "rule_description": label.get("rule_description", ""),
                "label": label.get("label", ""),
                "event_role": label.get("event_role", ""),
                "execution_mode": label.get("execution_mode", ""),
                "tool": label.get("tool", ""),
                "mitre_technique_id": label.get("mitre_technique_id", ""),
                "confidence": label.get("confidence", ""),
                "match_status": "matched" if candidates else "unmatched",
                "match_method": "agent_source_timestamp_rule_description" if candidates else "none",
                "candidate_count": len(candidates),
                "primary_phase3_alert_uid": phase3_ids[0] if phase3_ids else "",
                "primary_evidence_id": evidence_ids[0] if evidence_ids else "",
                "candidate_phase3_alert_uids": ";".join(phase3_ids),
                "candidate_evidence_ids": ";".join(evidence_ids),
                "candidate_raw_line_numbers": ";".join(raw_lines),
            }
        )

        if candidates:
            for rank, candidate in enumerate(candidates, start=1):
                candidate_rows.append(
                    {
                        **{
                            "label_id": label.get("label_id", ""),
                            "phase2_alert_uid": label.get("alert_uid", ""),
                            "case_id": case_id,
                            "run_id": label.get("run_id", ""),
                            "campaign_id": label.get("campaign_id", ""),
                            "scenario_id": label.get("scenario_id", ""),
                            "label": label.get("label", ""),
                            "event_role": label.get("event_role", ""),
                            "execution_mode": label.get("execution_mode", ""),
                            "tool": label.get("tool", ""),
                            "match_rank": rank,
                            "candidate_count": len(candidates),
                            "is_primary_candidate": rank == 1,
                        },
                        **normalized_public_fields(candidate),
                    }
                )
        else:
            candidate_rows.append(
                {
                    "label_id": label.get("label_id", ""),
                    "phase2_alert_uid": label.get("alert_uid", ""),
                    "case_id": case_id,
                    "run_id": label.get("run_id", ""),
                    "campaign_id": label.get("campaign_id", ""),
                    "scenario_id": label.get("scenario_id", ""),
                    "label": label.get("label", ""),
                    "event_role": label.get("event_role", ""),
                    "execution_mode": label.get("execution_mode", ""),
                    "tool": label.get("tool", ""),
                    "match_rank": "",
                    "candidate_count": 0,
                    "is_primary_candidate": False,
                }
            )

    return summary_rows, candidate_rows


def split_semicolon(value: str | None) -> set[str]:
    if not value:
        return set()
    return {part.strip() for part in value.split(";") if part.strip()}


def normalized_alerts_for_case_window(case: dict[str, str], normalized_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    agent_name = case.get("agent_name", "")
    start_ts = parse_timestamp_to_utc(case.get("start_ts", ""))
    end_ts = parse_timestamp_to_utc(case.get("end_ts", ""))
    rule_ids = split_semicolon(case.get("rule_ids", ""))

    matches: list[dict[str, Any]] = []
    for alert in normalized_alerts:
        alert_agent = alert.get("host", {}).get("agent_name") or ""
        alert_time = alert.get("timestamps", {}).get("event_time_utc") or ""
        alert_rule_id = str(alert.get("rule", {}).get("rule_id") or "")
        if agent_name and alert_agent != agent_name:
            continue
        if start_ts and alert_time < start_ts:
            continue
        if end_ts and alert_time > end_ts:
            continue
        if rule_ids and alert_rule_id not in rule_ids:
            continue
        matches.append(alert)

    matches.sort(key=lambda item: int(item["evidence"]["raw_line_number"]))
    return matches


def window_case_row(case_id: str, case: dict[str, str], alert: dict[str, Any], rank: int, candidate_count: int) -> dict[str, Any]:
    return {
        "label_id": "",
        "phase2_alert_uid": "",
        "case_id": case_id,
        "run_id": case.get("run_id", ""),
        "campaign_id": case.get("campaign_id", ""),
        "scenario_id": case.get("scenario_id", ""),
        "label": "",
        "event_role": "case_window_context",
        "execution_mode": case.get("execution_mode", ""),
        "tool": case.get("tool", ""),
        "match_rank": rank,
        "candidate_count": candidate_count,
        "is_primary_candidate": False,
        "link_source": "case_window_match",
        **normalized_public_fields(alert),
    }


def build_case_linkage(casebook_rows: list[dict[str, str]], candidate_rows: list[dict[str, Any]], normalized_alerts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases = case_by_id(casebook_rows)
    labels_by_case: dict[str, list[dict[str, Any]]] = {}
    for row in candidate_rows:
        if row.get("phase3_alert_uid"):
            row.setdefault("link_source", "ground_truth_label_match")
            labels_by_case.setdefault(str(row.get("case_id", "")), []).append(row)

    case_alert_rows: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []
    for case_id, case in cases.items():
        linked = list(labels_by_case.get(case_id, []))
        seen_alert_uids = {row["phase3_alert_uid"] for row in linked if row.get("phase3_alert_uid")}
        window_matches = [
            alert
            for alert in normalized_alerts_for_case_window(case, normalized_alerts)
            if alert["alert_uid"] not in seen_alert_uids
        ]
        for rank, alert in enumerate(window_matches, start=1):
            linked.append(window_case_row(case_id, case, alert, rank, len(window_matches)))

        primary_linked = [row for row in linked if str(row.get("is_primary_candidate")).lower() == "true"]
        window_linked = [row for row in linked if row.get("link_source") == "case_window_match"]
        unique_alerts = sorted({row["phase3_alert_uid"] for row in linked if row.get("phase3_alert_uid")})
        primary_unique_alerts = sorted({row["phase3_alert_uid"] for row in primary_linked if row.get("phase3_alert_uid")})

        summary_rows.append(
            {
                "case_id": case_id,
                "run_id": case.get("run_id", ""),
                "campaign_id": case.get("campaign_id", ""),
                "scenario_id": case.get("scenario_id", ""),
                "case_type": case.get("case_type", ""),
                "agent_name": case.get("agent_name", ""),
                "start_ts": case.get("start_ts", ""),
                "end_ts": case.get("end_ts", ""),
                "execution_mode": case.get("execution_mode", ""),
                "tool": case.get("tool", ""),
                "expected_raw_alert_count": case.get("raw_alert_count", ""),
                "expected_trigger_alert_count": case.get("trigger_alert_count", ""),
                "expected_supporting_alert_count": case.get("supporting_alert_count", ""),
                "expected_duplicate_alert_count": case.get("duplicate_alert_count", ""),
                "expected_noise_alert_count": case.get("noise_alert_count", ""),
                "candidate_link_rows": len(linked),
                "primary_link_rows": len(primary_linked),
                "case_window_link_rows": len(window_linked),
                "unique_phase3_alert_count_all_candidates": len(unique_alerts),
                "unique_phase3_alert_count_primary": len(primary_unique_alerts),
                "match_status": "matched" if linked else "unmatched",
                "primary_phase3_alert_uids": ";".join(primary_unique_alerts),
                "all_candidate_phase3_alert_uids": ";".join(unique_alerts),
                "case_summary": case.get("case_summary", ""),
                "analyst_expected_conclusion": case.get("analyst_expected_conclusion", ""),
            }
        )

        for row in linked:
            case_alert_rows.append(
                {
                    "case_id": case_id,
                    "case_run_id": case.get("run_id", ""),
                    "case_campaign_id": case.get("campaign_id", ""),
                    "case_execution_mode": case.get("execution_mode", ""),
                    "case_tool": case.get("tool", ""),
                    "case_summary": case.get("case_summary", ""),
                    "analyst_expected_conclusion": case.get("analyst_expected_conclusion", ""),
                    **row,
                }
            )

    return case_alert_rows, summary_rows


def build_investigation_index(case_alert_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = [
        "case_id",
        "case_run_id",
        "case_campaign_id",
        "case_execution_mode",
        "case_tool",
        "label_id",
        "phase2_alert_uid",
        "phase3_alert_uid",
        "evidence_id",
        "raw_line_number",
        "label",
        "event_role",
        "event_time_utc",
        "source_time_raw",
        "normalized_agent_name",
        "normalized_rule_id",
        "normalized_rule_description",
        "event_category",
        "event_action",
        "event_outcome",
        "normalized_severity",
        "mitre_technique_ids",
        "normalization_status",
        "link_source",
        "match_rank",
        "candidate_count",
        "is_primary_candidate",
        "case_summary",
        "analyst_expected_conclusion",
    ]
    return [{field: row.get(field, "") for field in fields} for row in case_alert_rows]


def build_fatigue_case_index(fatigue_rows: list[dict[str, str]], case_summary_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    case_by_run_id = {row["run_id"]: row for row in case_summary_rows if row.get("run_id")}
    linked_rows: list[dict[str, Any]] = []
    for row in fatigue_rows:
        case = case_by_run_id.get(row.get("run_id", ""), {})
        linked_rows.append(
            {
                **row,
                "case_id": case.get("case_id", ""),
                "case_match_status": "matched" if case else "unmatched",
                "case_execution_mode": case.get("execution_mode", ""),
                "case_tool": case.get("tool", ""),
                "case_primary_phase3_alert_uids": case.get("primary_phase3_alert_uids", ""),
            }
        )
    return linked_rows


def output_fields(rows: list[dict[str, Any]]) -> list[str]:
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    return fields


def build_linkage(paths: LinkagePaths) -> dict[str, Any]:
    labels = read_csv(paths.ground_truth)
    casebook_rows = read_csv(paths.casebook)
    fatigue_rows = read_csv(paths.fatigue_baseline)
    casebook_detailed_rows = read_jsonl(paths.casebook_detailed)
    normalized_alerts = read_jsonl(paths.normalized_alerts)

    normalized_index = build_normalized_index(normalized_alerts)
    run_to_case = case_id_by_run(casebook_rows)
    crosswalk_rows, candidate_rows = build_label_crosswalk(labels, normalized_index, run_to_case)
    case_alert_rows, case_summary_rows = build_case_linkage(casebook_rows, candidate_rows, normalized_alerts)
    investigation_rows = build_investigation_index(case_alert_rows)
    fatigue_link_rows = build_fatigue_case_index(fatigue_rows, case_summary_rows)

    outputs = {
        "ground_truth_to_normalized_crosswalk": paths.output_dir / "ground_truth_to_normalized_crosswalk.csv",
        "label_normalized_alert_candidates": paths.output_dir / "label_normalized_alert_candidates.csv",
        "casebook_to_normalized_alerts": paths.output_dir / "casebook_to_normalized_alerts.csv",
        "case_linkage_summary": paths.output_dir / "case_linkage_summary.csv",
        "investigation_flow_index": paths.output_dir / "investigation_flow_index.csv",
        "fatigue_case_linkage": paths.output_dir / "fatigue_case_linkage.csv",
        "linkage_manifest": paths.output_dir / "linkage_manifest.json",
    }

    write_csv(outputs["ground_truth_to_normalized_crosswalk"], output_fields(crosswalk_rows), crosswalk_rows)
    write_csv(outputs["label_normalized_alert_candidates"], output_fields(candidate_rows), candidate_rows)
    write_csv(outputs["casebook_to_normalized_alerts"], output_fields(case_alert_rows), case_alert_rows)
    write_csv(outputs["case_linkage_summary"], output_fields(case_summary_rows), case_summary_rows)
    write_csv(outputs["investigation_flow_index"], output_fields(investigation_rows), investigation_rows)
    write_csv(outputs["fatigue_case_linkage"], output_fields(fatigue_link_rows), fatigue_link_rows)

    matched_labels = sum(1 for row in crosswalk_rows if row["match_status"] == "matched")
    ambiguous_labels = sum(1 for row in crosswalk_rows if int(row["candidate_count"]) > 1)
    matched_cases = sum(1 for row in case_summary_rows if row["match_status"] == "matched")
    manifest = {
        "inputs": {
            "ground_truth": str(paths.ground_truth),
            "casebook": str(paths.casebook),
            "casebook_detailed": str(paths.casebook_detailed),
            "fatigue_baseline": str(paths.fatigue_baseline),
            "normalized_alerts": str(paths.normalized_alerts),
        },
        "outputs": {name: str(path) for name, path in outputs.items() if name != "linkage_manifest"},
        "counts": {
            "ground_truth_labels": len(labels),
            "matched_ground_truth_labels": matched_labels,
            "unmatched_ground_truth_labels": len(labels) - matched_labels,
            "ambiguous_ground_truth_labels": ambiguous_labels,
            "casebook_cases": len(casebook_rows),
            "casebook_detailed_cases": len(casebook_detailed_rows),
            "matched_casebook_cases": matched_cases,
            "unmatched_casebook_cases": len(casebook_rows) - matched_cases,
            "candidate_link_rows": len(candidate_rows),
            "case_alert_link_rows": len(case_alert_rows),
            "investigation_flow_rows": len(investigation_rows),
            "fatigue_rows": len(fatigue_rows),
            "fatigue_case_link_rows": len(fatigue_link_rows),
        },
        "matching_strategy": {
            "label_to_normalized": "agent_name + source_time_raw/timestamp + rule_id + rule_description",
            "case_to_labels": "run_id mapped from casebook.csv to ground_truth_labels.csv",
            "case_to_normalized": "case-to-label links expanded through label-to-normalized candidates, plus case-window context matches by agent/time/rule IDs",
            "duplicate_behavior": "All normalized candidates are preserved; the first raw-line-number candidate is marked primary for convenience.",
        },
        "runtime_boundary": "These files are evaluation/investigation artifacts. They must not be queried by runtime AI endpoints.",
    }
    write_json(outputs["linkage_manifest"], manifest)
    return manifest


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Link Phase 2 evaluation artifacts to Phase 3 normalized runtime alerts.")
    parser.add_argument("--ground-truth", required=True, type=Path)
    parser.add_argument("--casebook", required=True, type=Path)
    parser.add_argument("--casebook-detailed", required=True, type=Path)
    parser.add_argument("--fatigue", required=True, type=Path)
    parser.add_argument("--normalized", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    paths = LinkagePaths(
        ground_truth=args.ground_truth,
        casebook=args.casebook,
        casebook_detailed=args.casebook_detailed,
        fatigue_baseline=args.fatigue,
        normalized_alerts=args.normalized,
        output_dir=args.output_dir,
    )
    missing = [
        str(path)
        for path in [
            paths.ground_truth,
            paths.casebook,
            paths.casebook_detailed,
            paths.fatigue_baseline,
            paths.normalized_alerts,
        ]
        if not path.exists()
    ]
    if missing:
        print(f"[FAIL] Missing linkage inputs: {', '.join(missing)}", file=sys.stderr)
        return 1

    manifest = build_linkage(paths)
    for key, value in manifest["counts"].items():
        print(f"[OK] {key}: {value}")
    print(f"[OK] output_dir: {paths.output_dir}")
    return 0 if manifest["counts"]["unmatched_ground_truth_labels"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
