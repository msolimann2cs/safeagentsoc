from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.analyst_priority import calculate_analyst_priority


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def load_enriched(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                existing = row.get("analyst_priority") or {}
                needs_recompute = (
                    "analyst_priority" not in row
                    or "urgent_priority_gate_passed" not in existing
                    or "high_priority_gate_passed" in existing
                )
                if needs_recompute:
                    priority = calculate_analyst_priority(
                        original_alert_summary=row["original_alert_summary"],
                        asset_context=row["asset_context"],
                        identity_context=row["identity_context"],
                        identity_applicability=row.get("identity_applicability", {}),
                        policy_context=row["policy_context"],
                        business_risk=row["business_risk"],
                        context_metadata=row["context_metadata"],
                    )
                    row["analyst_priority"] = {
                        "analyst_priority_score": priority.analyst_priority_score,
                        "analyst_priority_label": priority.analyst_priority_label,
                        "urgent_priority_gate_passed": priority.urgent_priority_gate_passed,
                        "gate_reasons": priority.gate_reasons,
                        "priority_factors": priority.priority_factors,
                        "suppressors": priority.suppressors,
                    }
                rows.append(row)
    return rows


def rule_description(rows: list[dict[str, str]], rule_id: str) -> str:
    for row in rows:
        if row.get("rule_id") == rule_id:
            return row.get("rule_description", "")
    return ""


def build_trigger_profile(ground_truth_rows: list[dict[str, str]], casebook_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    roles_by_rule: dict[str, Counter[str]] = {}
    for row in ground_truth_rows:
        rule_id = row.get("rule_id") or "unknown"
        roles_by_rule.setdefault(rule_id, Counter())[row.get("event_role") or "unknown"] += 1
    case_counts = Counter()
    for row in casebook_rows:
        for rule_id in (row.get("rule_ids") or "").split(";"):
            if rule_id:
                case_counts[rule_id] += 1
    output: list[dict[str, Any]] = []
    for rule_id, counter in sorted(
        roles_by_rule.items(),
        key=lambda item: (-(item[1].get("trigger", 0)), -sum(item[1].values()), item[0]),
    ):
        total = sum(counter.values())
        output.append(
            {
                "rule_id": rule_id,
                "rule_description": rule_description(ground_truth_rows, rule_id),
                "trigger_count": counter.get("trigger", 0),
                "supporting_count": counter.get("supporting", 0),
                "duplicate_count": counter.get("duplicate", 0),
                "unrelated_count": counter.get("unrelated", 0),
                "noise_count": counter.get("noise", 0),
                "labeled_total": total,
                "trigger_rate_within_labels": round(counter.get("trigger", 0) / total, 4) if total else 0.0,
                "casebook_case_count": case_counts.get(rule_id, 0),
            }
        )
    return output


def build_priority_distribution(enriched_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    label_counts = Counter(row["analyst_priority"].get("analyst_priority_label", "unknown") for row in enriched_rows)
    return [{"analyst_priority_label": label, "alert_count": count} for label, count in sorted(label_counts.items())]


def build_urgent_mapping_distribution(enriched_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    urgent = [
        row
        for row in enriched_rows
        if row["analyst_priority"].get("analyst_priority_label") in {"high", "critical"}
    ]
    counts = Counter(
        (
            row["context_metadata"].get("mapping_rule_type", "unknown"),
            row["context_metadata"].get("mapping_rule_id", "unknown"),
        )
        for row in urgent
    )
    return [
        {
            "mapping_rule_type": mapping_type,
            "mapping_rule_id": mapping_id,
            "urgent_alert_count": count,
            "urgent_alert_rate": round(count / len(urgent), 4) if urgent else 0.0,
        }
        for (mapping_type, mapping_id), count in counts.most_common()
    ]


def build_suppressor_distribution(enriched_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter()
    for row in enriched_rows:
        for suppressor in row.get("analyst_priority", {}).get("suppressors") or []:
            counts[str(suppressor)] += 1
    return [{"suppressor": key, "count": value} for key, value in counts.most_common()]


def write_report(
    path: Path,
    ground_truth_rows: list[dict[str, str]],
    casebook_rows: list[dict[str, str]],
    enriched_rows: list[dict[str, Any]],
) -> None:
    gt_roles = Counter(row.get("event_role") for row in ground_truth_rows)
    priority_counts = Counter(row["analyst_priority"].get("analyst_priority_label", "unknown") for row in enriched_rows)
    case_totals = {
        key: sum(int(row.get(key) or 0) for row in casebook_rows)
        for key in [
            "trigger_alert_count",
            "meaningful_alert_count",
            "suppression_candidate_count",
            "duplicate_alert_count",
            "noise_alert_count",
        ]
    }
    urgent_count = priority_counts.get("high", 0) + priority_counts.get("critical", 0)
    lines = [
        "# Analyst Priority Offline Calibration Report",
        "",
        "This report uses evaluation artifacts after runtime enrichment has completed. It must not be imported into runtime context tables or queried by runtime API logic.",
        "",
        "## Evaluation Baseline",
        "",
        f"- Ground-truth labels: {len(ground_truth_rows)}",
        f"- Trigger labels: {gt_roles.get('trigger', 0)}",
        f"- Supporting labels: {gt_roles.get('supporting', 0)}",
        f"- Duplicate labels: {gt_roles.get('duplicate', 0)}",
        f"- Unrelated labels: {gt_roles.get('unrelated', 0)}",
        f"- Noise labels: {gt_roles.get('noise', 0)}",
        f"- Casebook trigger-alert total: {case_totals['trigger_alert_count']}",
        f"- Casebook meaningful-alert total: {case_totals['meaningful_alert_count']}",
        f"- Casebook suppression-candidate total: {case_totals['suppression_candidate_count']}",
        "",
        "## Analyst Priority Output",
        "",
        f"- Low: {priority_counts.get('low', 0)}",
        f"- Medium: {priority_counts.get('medium', 0)}",
        f"- High: {priority_counts.get('high', 0)}",
        f"- Critical: {priority_counts.get('critical', 0)}",
        f"- High + critical: {urgent_count}",
        "",
        "## Calibration Judgment",
        "",
        "The target urgent analyst queue is approximately 100-130 alerts, based on the casebook trigger-alert total of 107.",
        f"The current urgent analyst queue contains {urgent_count} alerts.",
        "",
        "Runtime enrichment did not query these evaluation files. This report is an offline calibration artifact only.",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    metadata_root = REPO_ROOT / "data" / "phase_02_scenario_dataset" / "Metadata"
    context_root = WORKSPACE_ROOT / "03_data" / "context"
    parser = argparse.ArgumentParser(description="Offline calibration for Phase 4 analyst priority.")
    parser.add_argument("--ground-truth", type=Path, default=metadata_root / "sprint_08_ground_truth" / "ground_truth_labels.csv")
    parser.add_argument("--casebook", type=Path, default=metadata_root / "sprint_09_casebook" / "casebook.csv")
    parser.add_argument("--enriched-alerts", type=Path, default=context_root / "exports" / "context_enriched_alerts_with_risk.jsonl")
    parser.add_argument("--qa-dir", type=Path, default=context_root / "qa")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ground_truth_rows = read_csv(args.ground_truth)
    casebook_rows = read_csv(args.casebook)
    enriched_rows = load_enriched(args.enriched_alerts)

    write_csv(args.qa_dir / "analyst_priority_distribution.csv", build_priority_distribution(enriched_rows))
    write_csv(args.qa_dir / "analyst_priority_urgent_mapping_distribution.csv", build_urgent_mapping_distribution(enriched_rows))
    write_csv(args.qa_dir / "analyst_priority_suppressor_distribution.csv", build_suppressor_distribution(enriched_rows))
    write_csv(args.qa_dir / "analyst_priority_trigger_rule_profile.csv", build_trigger_profile(ground_truth_rows, casebook_rows))
    write_report(args.qa_dir / "analyst_priority_offline_calibration_report.md", ground_truth_rows, casebook_rows, enriched_rows)

    urgent_count = sum(
        1
        for row in enriched_rows
        if row["analyst_priority"].get("analyst_priority_label") in {"high", "critical"}
    )
    print(f"[OK] Offline calibration complete. Urgent analyst-priority alerts: {urgent_count}")
    print(f"[OK] Wrote calibration outputs to {args.qa_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
