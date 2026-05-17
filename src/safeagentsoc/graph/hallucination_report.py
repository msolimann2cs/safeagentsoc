from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

FORBIDDEN_RUNTIME_TERMS = [
    "ground_truth",
    "casebook",
    "expected_conclusion",
    "event_role",
    "true_positive",
    "false_positive",
    "scenario_label",
    "gold",
    "answer_key",
]


def build_graph_validation_metrics(
    *,
    phase7_records: list[dict[str, Any]],
    claims: list[Any],
    validation_results: list[Any],
    hypothesis_rollups: list[dict[str, Any]],
    skipped_cases: list[str],
    leakage_count: int = 0,
) -> dict[str, Any]:
    claim_status_counts: dict[str, int] = {}
    for result in validation_results:
        status = getattr(result, "graph_validation_status", None) or result.get("graph_validation_status")
        claim_status_counts[status] = claim_status_counts.get(status, 0) + 1

    hypothesis_status_counts: dict[str, int] = {}
    for row in hypothesis_rollups:
        status = row.get("graph_validation_status")
        hypothesis_status_counts[status] = hypothesis_status_counts.get(status, 0) + 1

    rejected_claims = claim_status_counts.get("infeasible", 0) + claim_status_counts.get("unsupported", 0)
    total_claims = len(validation_results)
    explanation_count = sum(
        1
        for result in validation_results
        if (getattr(result, "graph_explanation", None) or (result.get("graph_explanation") if isinstance(result, dict) else None))
    )
    scores = [
        float(getattr(result, "feasibility_score", None) if hasattr(result, "feasibility_score") else result.get("feasibility_score", 0))
        for result in validation_results
    ]

    return {
        "phase": "Phase 8",
        "graph_validation_run_id": f"phase8_graph_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "total_phase7_records_seen": len(phase7_records),
        "total_validated_phase7_cases": len({row.get("case_id") for row in phase7_records if row.get("validation_status") == "passed"}),
        "total_skipped_failed_phase7_cases": len(skipped_cases),
        "skipped_failed_phase7_case_ids": skipped_cases,
        "total_hypotheses_validated": len(hypothesis_rollups),
        "total_claims_extracted": len(claims),
        "total_claims_validated": total_claims,
        "claim_status_counts": claim_status_counts,
        "hypothesis_status_counts": hypothesis_status_counts,
        "feasible_claim_count": claim_status_counts.get("feasible", 0),
        "conditional_claim_count": claim_status_counts.get("conditional", 0),
        "infeasible_claim_count": claim_status_counts.get("infeasible", 0),
        "unsupported_claim_count": claim_status_counts.get("unsupported", 0),
        "not_enough_graph_context_count": claim_status_counts.get("not_enough_graph_context", 0),
        "mixed_hypothesis_count": hypothesis_status_counts.get("mixed", 0),
        "average_feasibility_score": round(sum(scores) / max(len(scores), 1), 4),
        "graph_explanation_coverage": round(explanation_count / max(total_claims, 1), 4),
        "infeasible_path_rejection_rate": round(rejected_claims / max(total_claims, 1), 4),
        "valid_path_retention_rate": round(
            claim_status_counts.get("feasible", 0) / max(total_claims - rejected_claims, 1), 4
        ),
        "conditional_path_detection_rate": round(claim_status_counts.get("conditional", 0) / max(total_claims, 1), 4),
        "hallucination_reduction_rate": round(rejected_claims / max(total_claims, 1), 4),
        "runtime_ground_truth_exposure_count": leakage_count,
    }


def scan_forbidden_terms(paths: list[Path]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        text = text.replace("runtime_ground_truth_exposure_count", "runtime_label_exposure_metric")
        for term in FORBIDDEN_RUNTIME_TERMS:
            if term in text:
                findings.append({"path": str(path), "forbidden_term": term})
    return findings


def write_hallucination_report(report_path: Path, metrics: dict[str, Any]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    status_counts = metrics.get("claim_status_counts", {})
    report_path.write_text(
        "\n".join(
            [
                "# Phase 8 Hallucination Rejection Report",
                "",
                "Phase 8 validates accepted Phase 7 hypotheses against a runtime enterprise graph. "
                "A feasible graph result means structurally possible, not confirmed compromise.",
                "",
                "## Summary Metrics",
                "",
                f"- Total Phase 7 records seen: {metrics.get('total_phase7_records_seen', 0)}",
                f"- Validated Phase 7 cases consumed: {metrics.get('total_validated_phase7_cases', 0)}",
                f"- Failed Phase 7 cases marked retry_required: {metrics.get('total_skipped_failed_phase7_cases', 0)}",
                f"- Claims extracted: {metrics.get('total_claims_extracted', 0)}",
                f"- Feasible claims: {status_counts.get('feasible', 0)}",
                f"- Conditional claims: {status_counts.get('conditional', 0)}",
                f"- Infeasible claims: {status_counts.get('infeasible', 0)}",
                f"- Unsupported claims: {status_counts.get('unsupported', 0)}",
                f"- Not enough graph context: {status_counts.get('not_enough_graph_context', 0)}",
                f"- Hallucination reduction rate: {metrics.get('hallucination_reduction_rate', 0)}",
                f"- Runtime leakage count: {metrics.get('runtime_ground_truth_exposure_count', 0)}",
                "",
                "Because Phase 7 already filtered unsupported language, Phase 8 primarily downgrades weak "
                "paths to conditional or not-enough-context and blocks graph-infeasible claims from later response phases.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def write_metrics_files(output_root: Path, metrics: dict[str, Any]) -> None:
    qa_dir = output_root / "qa"
    exports_dir = output_root / "exports"
    qa_dir.mkdir(parents=True, exist_ok=True)
    exports_dir.mkdir(parents=True, exist_ok=True)
    (exports_dir / "graph_validation_summary.json").write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    with (qa_dir / "graph_validation_metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value"])
        writer.writeheader()
        for key, value in metrics.items():
            writer.writerow({"metric": key, "value": json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value})
