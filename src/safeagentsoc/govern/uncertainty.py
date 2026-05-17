from __future__ import annotations

from typing import Any

from safeagentsoc.govern.schemas import UncertaintyAssessment


GRAPH_UNCERTAINTY = {
    "feasible": 0.12,
    "conditional": 0.28,
    "not_enough_graph_context": 0.45,
    "infeasible": 0.65,
    "unsupported": 0.75,
    "mixed": 0.42,
}


def assess_uncertainty(case_id: str, hypothesis_rows: list[dict[str, Any]], missing_evidence: list[str]) -> UncertaintyAssessment:
    statuses = [row.get("graph_validation_status") for row in hypothesis_rows]
    status = rollup_graph_status(statuses)
    base = GRAPH_UNCERTAINTY.get(status, 0.5)
    confidence_values = [float(row.get("hypothesis_confidence") or 0.5) for row in hypothesis_rows]
    avg_hypothesis_confidence = sum(confidence_values) / max(len(confidence_values), 1)
    missing_penalty = min(0.2, len(set(missing_evidence)) * 0.025)
    uncertainty = max(0.05, min(0.95, base + missing_penalty + (0.5 - avg_hypothesis_confidence) * 0.2))
    confidence = round(1 - uncertainty, 4)
    drivers = []
    if status != "feasible":
        drivers.append(f"graph validation is {status}")
    for item in sorted(set(missing_evidence))[:6]:
        drivers.append(item)
    if avg_hypothesis_confidence < 0.7:
        drivers.append("hypothesis confidence below high threshold")
    label = uncertainty_label(uncertainty)
    not_sufficient_for = ["public disclosure", "confirmed breach conclusion"]
    if status != "feasible" or confidence < 0.85:
        not_sufficient_for.append("account disablement")
        not_sufficient_for.append("critical server isolation")
    if any("exfiltration" in item for item in missing_evidence):
        not_sufficient_for.append("customer data impact conclusion")
    sufficiency = "sufficient_for_monitoring_and_Tier2_review"
    if confidence >= 0.78 and status == "feasible":
        sufficiency = "sufficient_for_approval_gated_containment_review"
    elif status in {"infeasible", "unsupported"}:
        sufficiency = "sufficient_for_monitoring_only"
    return UncertaintyAssessment(
        case_id=case_id,
        uncertainty_score=round(uncertainty, 4),
        uncertainty_label=label,
        confidence_score=confidence,
        evidence_sufficiency=sufficiency,
        uncertainty_drivers=drivers,
        not_sufficient_for=not_sufficient_for,
        graph_validation_status=status,
    )


def rollup_graph_status(statuses: list[str | None]) -> str:
    present = {status for status in statuses if status}
    if not present:
        return "insufficient_context"
    if "infeasible" in present:
        return "infeasible"
    if "unsupported" in present:
        return "unsupported"
    if "not_enough_graph_context" in present:
        return "not_enough_graph_context"
    if "conditional" in present:
        return "conditional"
    if present == {"feasible"}:
        return "feasible"
    return "mixed"


def uncertainty_label(value: float) -> str:
    if value >= 0.55:
        return "high"
    if value >= 0.25:
        return "medium"
    return "low"
