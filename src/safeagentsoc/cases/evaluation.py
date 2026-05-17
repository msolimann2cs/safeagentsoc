from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def evaluate_runtime_cases(
    *,
    generated_cases_path: Path,
    alert_case_links_path: Path,
    ground_truth_labels_path: Path,
    casebook_path: Path,
    ground_truth_crosswalk_path: Path | None = None,
    output_dir: Path,
) -> dict[str, Any]:
    """Offline-only evaluation. Do not call this from runtime services."""
    links = read_csv(alert_case_links_path)
    labels = read_csv(ground_truth_crosswalk_path) if ground_truth_crosswalk_path and ground_truth_crosswalk_path.exists() else read_csv(ground_truth_labels_path)
    casebook = read_csv(casebook_path)
    link_by_alert = {row["alert_uid"]: row for row in links}
    trigger_labels = [row for row in labels if row.get("event_role") == "trigger" and row.get("primary_phase3_alert_uid")]
    duplicate_labels = [row for row in labels if row.get("event_role") == "duplicate" and row.get("primary_phase3_alert_uid")]
    visible_representative_keys = {
        (
            link.get("case_id"),
            link.get("duplicate_group_id") or "",
            link.get("rule_id") or "",
        )
        for link in links
        if str(link.get("visibility_level") or "").startswith("visible")
    }
    visible_roles = {"trigger", "supporting"}
    trigger_preserved = [
        row
        for row in trigger_labels
        if (link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("runtime_alert_role") in visible_roles
        or str((link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("visibility_level", "")).startswith("visible")
    ]
    duplicate_suppressed = [
        row
        for row in duplicate_labels
        if str((link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("visibility_level", "")).startswith("collapsed")
    ]
    duplicate_collapsed_or_represented = [
        row
        for row in duplicate_labels
        if str((link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("visibility_level", "")).startswith("collapsed")
        or (
            (link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("case_id"),
            (link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("duplicate_group_id") or "",
            (link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("rule_id") or "",
        )
        in visible_representative_keys
    ]
    meaningful = [row for row in labels if row.get("event_role") in {"trigger", "supporting"} and row.get("primary_phase3_alert_uid")]
    false_suppressed = [
        row
        for row in meaningful
        if str((link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("visibility_level", "")).startswith("collapsed")
        and (
            (link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("case_id"),
            (link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("duplicate_group_id") or "",
            (link_by_alert.get(row.get("primary_phase3_alert_uid") or "") or {}).get("rule_id") or "",
        )
        not in visible_representative_keys
    ]
    visible_alert_count = sum(1 for row in links if str(row.get("visibility_level") or "").startswith("visible"))
    metrics = {
        "total_generated_links": len(links),
        "gold_trigger_count": len(trigger_labels),
        "gold_duplicate_count": len(duplicate_labels),
        "gold_casebook_case_count": len(casebook),
        "trigger_preservation_rate": round(len(trigger_preserved) / len(trigger_labels), 4) if trigger_labels else 0,
        "duplicate_suppression_rate": round(len(duplicate_suppressed) / len(duplicate_labels), 4) if duplicate_labels else 0,
        "duplicate_collapsed_or_represented_rate": round(len(duplicate_collapsed_or_represented) / len(duplicate_labels), 4)
        if duplicate_labels
        else 0,
        "alert_reduction_ratio": round(1 - (visible_alert_count / len(links)), 4) if links else 0,
        "false_suppression_rate": round(len(false_suppressed) / len(meaningful), 4) if meaningful else 0,
        "evaluation_scope": "offline_only",
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "case_builder_eval_metrics.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value"])
        writer.writeheader()
        for key, value in metrics.items():
            writer.writerow({"metric": key, "value": value})
    with (output_dir / "case_builder_evaluation.md").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Phase 5 Offline Case Builder Evaluation\n\n")
        handle.write("Status: generated from offline evaluation artifacts only.\n\n")
        for key, value in metrics.items():
            handle.write(f"- `{key}`: {value}\n")
    return metrics
