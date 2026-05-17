from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
from statistics import mean, median
from typing import Any

from safeagentsoc.cases.behavior_family_mapper import map_behavior_family
from safeagentsoc.cases.case_scoring import score_case
from safeagentsoc.cases.case_seed import generate_case_seeds
from safeagentsoc.cases.duplicate_detector import detect_duplicate_groups
from safeagentsoc.cases.grouping_engine import build_candidate_links
from safeagentsoc.cases.role_classifier import classify_case_alert_roles
from safeagentsoc.cases.suppression_safety import apply_suppression_safety


FORBIDDEN_RUNTIME_FIELDS = {
    "ground_truth",
    "expected_conclusion",
    "casebook_answer",
    "true_positive",
    "false_positive",
    "event_role",
    "scenario_label",
    "gold_label",
    "answer_key",
}


@dataclass(frozen=True)
class CaseBuilderResult:
    cases: list[dict[str, Any]]
    alert_case_links: list[dict[str, Any]]
    case_alert_roles: list[dict[str, Any]]
    evidence_summary: list[dict[str, Any]]
    duplicate_groups: list[dict[str, Any]]
    case_seeds: list[dict[str, Any]]
    metrics: dict[str, Any]
    behavior_grouping_rows: list[dict[str, Any]]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        keys: list[str] = []
        for row in rows:
            for key in row:
                if key not in keys:
                    keys.append(key)
        fieldnames = keys
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})


def csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return value


def distribution(rows: list[dict[str, Any]], field: str, count_field: str = "count") -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{field: key, count_field: value} for key, value in sorted(counts.items())]


def flatten_link(row: dict[str, Any]) -> dict[str, Any]:
    alert = row["alert"]
    analyst_priority = alert.get("analyst_priority") or {}
    business_risk = alert.get("business_risk") or {}
    asset = alert.get("asset_context") or {}
    identity = alert.get("identity_context") or {}
    summary = alert.get("original_alert_summary") or {}
    return {
        "case_id": row["case_id"],
        "alert_uid": alert.get("alert_uid"),
        "evidence_id": alert.get("evidence_id"),
        "runtime_alert_role": row["runtime_alert_role"],
        "role_confidence": row["role_confidence"],
        "role_reason": row["role_reason"],
        "role_features": row["role_features"],
        "case_affinity_score": row["case_affinity_score"],
        "case_affinity_reasons": row["case_affinity_reasons"],
        "visibility_level": row["visibility_level"],
        "suppression_safe": row["suppression_safe"],
        "suppression_reason": row["suppression_reason"],
        "must_remain_visible_reason": row["must_remain_visible_reason"],
        "preserved_unique_evidence_types": row["preserved_unique_evidence_types"],
        "representative_alert_uid": row.get("representative_alert_uid"),
        "duplicate_group_id": row.get("duplicate_group_id"),
        "behavior_family": row.get("behavior_family"),
        "analyst_priority_score": analyst_priority.get("analyst_priority_score"),
        "analyst_priority_label": analyst_priority.get("analyst_priority_label"),
        "business_risk_score": business_risk.get("business_risk_score"),
        "business_risk_label": business_risk.get("business_risk_label"),
        "asset_id": asset.get("asset_id"),
        "identity_id": identity.get("identity_id"),
        "rule_id": summary.get("rule_id"),
        "event_time_utc": alert.get("event_time_utc"),
    }


def evidence_summary_for_case(case: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    visible = [flatten_link(row) for row in rows if row["visibility_level"].startswith("visible")]
    collapsed = [flatten_link(row) for row in rows if row["visibility_level"].startswith("collapsed")]
    return {
        "case_id": case["case_id"],
        "evidence_ids": case["evidence_ids"],
        "visible_alert_uids": [row["alert_uid"] for row in visible],
        "collapsed_alert_uids": [row["alert_uid"] for row in collapsed],
        "visible_evidence_count": len(visible),
        "collapsed_evidence_count": len(collapsed),
        "unique_mitre_technique_ids": case["mitre_technique_ids"],
        "unique_rule_ids": case["rule_ids"],
    }


def build_cases(alerts: list[dict[str, Any]]) -> CaseBuilderResult:
    started = datetime.now(UTC)
    alerts = sorted(alerts, key=lambda alert: (str(alert.get("event_time_utc") or ""), str(alert.get("alert_uid") or "")))
    behavior_families = {str(alert["alert_uid"]): map_behavior_family(alert) for alert in alerts}
    seeds = generate_case_seeds(alerts)
    duplicate_groups, duplicate_group_by_alert = detect_duplicate_groups(alerts, behavior_families)
    candidates_by_case = build_candidate_links(alerts, seeds, behavior_families, duplicate_group_by_alert)

    all_role_rows: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    evidence_summary: list[dict[str, Any]] = []
    behavior_rows: list[dict[str, Any]] = []

    for case_id, candidates in candidates_by_case.items():
        role_rows = classify_case_alert_roles(candidates, behavior_families, duplicate_group_by_alert)
        for row in role_rows:
            row["behavior_family"] = behavior_families.get(str(row["alert"]["alert_uid"]), "unknown_low_signal")
        safe_rows = apply_suppression_safety(role_rows)
        case = score_case(case_id, safe_rows)
        seed_uid = next((row["alert"]["alert_uid"] for row in safe_rows if row["case_affinity_reasons"] == ["case seed alert"]), None)
        case["case_seed_alert_uid"] = seed_uid
        case["case_alerts"] = [flatten_link(row) for row in sorted(safe_rows, key=lambda item: str(item["alert"].get("event_time_utc") or ""))]
        cases.append(case)
        all_role_rows.extend(safe_rows)
        evidence_summary.append(evidence_summary_for_case(case, safe_rows))
        for row in safe_rows:
            behavior_rows.append(
                {
                    "case_id": case_id,
                    "alert_uid": row["alert"]["alert_uid"],
                    "behavior_family": row["behavior_family"],
                    "mitre_technique_ids": (row["alert"].get("original_alert_summary") or {}).get("mitre_technique_ids") or [],
                    "case_affinity_score": row["case_affinity_score"],
                    "runtime_alert_role": row["runtime_alert_role"],
                }
            )

    cases.sort(
        key=lambda case: (
            -float(case["case_priority_score"]),
            -float(case["max_analyst_priority_score"]),
            case["case_start_time_utc"],
            case["case_id"],
        )
    )
    case_id_map = {case["case_id"]: f"case_rt_{index + 1:06d}" for index, case in enumerate(cases)}
    for case in cases:
        old_case_id = case["case_id"]
        case["case_id"] = case_id_map[old_case_id]
        for alert_link in case["case_alerts"]:
            alert_link["case_id"] = case["case_id"]
    for row in all_role_rows:
        row["case_id"] = case_id_map[row["case_id"]]
    for row in evidence_summary:
        row["case_id"] = case_id_map[row["case_id"]]
    for row in behavior_rows:
        row["case_id"] = case_id_map[row["case_id"]]

    flat_links = [flatten_link(row) for row in all_role_rows]
    runtime_seconds = round((datetime.now(UTC) - started).total_seconds(), 4)
    visible_count = sum(1 for row in flat_links if str(row["visibility_level"]).startswith("visible"))
    suppressed_count = len(flat_links) - visible_count
    alert_counts = [int(case["alert_count_total"]) for case in cases]
    metrics = {
        "case_builder_run_id": f"case_builder_run_{started.strftime('%Y%m%dT%H%M%SZ')}",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "total_input_alerts": len(alerts),
        "total_generated_cases": len(cases),
        "case_count_reduction": round(1 - (len(cases) / len(alerts)), 4) if alerts else 0,
        "alert_reduction_ratio": round(1 - (visible_count / len(alerts)), 4) if alerts else 0,
        "visible_alert_count": visible_count,
        "suppressed_alert_count": suppressed_count,
        "duplicate_alert_count": sum(1 for row in flat_links if row["runtime_alert_role"] == "duplicate"),
        "noise_alert_count": sum(1 for row in flat_links if row["runtime_alert_role"] == "noise"),
        "context_alert_count": sum(1 for row in flat_links if row["runtime_alert_role"] == "context"),
        "trigger_alert_count": sum(1 for row in flat_links if row["runtime_alert_role"] == "trigger"),
        "supporting_alert_count": sum(1 for row in flat_links if row["runtime_alert_role"] == "supporting"),
        "average_alerts_per_case": round(mean(alert_counts), 4) if alert_counts else 0,
        "median_alerts_per_case": median(alert_counts) if alert_counts else 0,
        "max_alerts_per_case": max(alert_counts) if alert_counts else 0,
        "case_builder_runtime_seconds": runtime_seconds,
        "runtime_safety": "runtime_only_no_evaluation_artifacts",
        "seed_count": len(seeds),
        "duplicate_group_count": len(duplicate_groups),
    }

    return CaseBuilderResult(
        cases=cases,
        alert_case_links=flat_links,
        case_alert_roles=flat_links,
        evidence_summary=evidence_summary,
        duplicate_groups=[asdict(group) for group in duplicate_groups],
        case_seeds=[asdict(seed) for seed in seeds],
        metrics=metrics,
        behavior_grouping_rows=behavior_rows,
    )


def build_case_outputs(enriched_alerts_path: Path, output_root: Path) -> CaseBuilderResult:
    alerts = read_jsonl(enriched_alerts_path)
    result = build_cases(alerts)
    cases_dir = output_root / "cases"
    qa_dir = cases_dir / "qa"
    review_dir = output_root / "review_packs"
    exports_dir = cases_dir / "exports"

    write_jsonl(exports_dir / "generated_cases.jsonl", result.cases)
    write_csv(exports_dir / "generated_case_queue.csv", result.cases)
    write_csv(exports_dir / "alert_case_links.csv", result.alert_case_links)
    write_csv(exports_dir / "case_alert_roles.csv", result.case_alert_roles)
    write_csv(exports_dir / "case_evidence_summary.csv", result.evidence_summary)
    write_csv(exports_dir / "generated_case_seeds.csv", result.case_seeds)
    write_csv(exports_dir / "duplicate_groups.csv", result.duplicate_groups)
    write_csv(exports_dir / "behavior_grouping_report.csv", result.behavior_grouping_rows)

    metrics_rows = [{"metric": key, "value": value} for key, value in result.metrics.items()]
    write_csv(qa_dir / "case_builder_metrics.csv", metrics_rows, ["metric", "value"])
    write_csv(qa_dir / "case_priority_distribution.csv", distribution(result.cases, "case_priority_label", "case_count"))
    write_csv(qa_dir / "case_role_distribution.csv", distribution(result.case_alert_roles, "runtime_alert_role", "alert_count"))
    write_csv(qa_dir / "case_visibility_distribution.csv", distribution(result.case_alert_roles, "visibility_level", "alert_count"))
    write_csv(qa_dir / "cases_by_behavior_family.csv", distribution(result.behavior_grouping_rows, "behavior_family", "alert_count"))
    write_csv(qa_dir / "cases_by_business_unit.csv", distribution(result.cases, "business_unit", "case_count"))
    write_csv(qa_dir / "suppressed_alerts.csv", [row for row in result.alert_case_links if str(row["visibility_level"]).startswith("collapsed")])
    write_csv(qa_dir / "visible_alerts.csv", [row for row in result.alert_case_links if str(row["visibility_level"]).startswith("visible")])

    review_rows = []
    for case in result.cases[:50]:
        review_rows.append(
            {
                "case_id": case["case_id"],
                "case_title": case["case_title"],
                "case_priority_label": case["case_priority_label"],
                "case_priority_score": case["case_priority_score"],
                "business_unit": case["business_unit"],
                "business_service": case["business_service"],
                "trigger_alert_count": case["trigger_alert_count"],
                "supporting_alert_count": case["supporting_alert_count"],
                "duplicate_alert_count": case["duplicate_alert_count"],
                "noise_alert_count": case["noise_alert_count"],
                "visible_alert_count": case["visible_alert_count"],
                "suppressed_alert_count": case["suppressed_alert_count"],
                "case_summary": case["case_summary"],
                "top_visible_alerts": [
                    link["alert_uid"]
                    for link in case["case_alerts"]
                    if str(link["visibility_level"]).startswith("visible")
                ][:10],
            }
        )
    write_csv(review_dir / "case_review_pack.csv", review_rows)
    return result
