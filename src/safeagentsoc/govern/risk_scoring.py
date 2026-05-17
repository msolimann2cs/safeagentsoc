from __future__ import annotations

from typing import Any

from safeagentsoc.govern.business_impact import ASSET_CRITICALITY
from safeagentsoc.govern.io_utils import clamp, dedupe, score_label
from safeagentsoc.govern.schemas import BusinessImpactAssessment, IncidentRiskScore, UncertaintyAssessment


TECHNIQUE_SEVERITY = {
    "T1546.011": 82.0,
    "T1574.001": 78.0,
    "T1059.001": 72.0,
    "T1059.003": 70.0,
    "T1070.004": 74.0,
    "T1087": 55.0,
    "T1021": 82.0,
    "T1021.004": 84.0,
    "T1110.001": 80.0,
    "T1486": 92.0,
    "T1490": 88.0,
    "T1531": 86.0,
}
GRAPH_STATUS_SCORE = {
    "feasible": 92.0,
    "conditional": 72.0,
    "not_enough_graph_context": 50.0,
    "mixed": 58.0,
    "infeasible": 20.0,
    "unsupported": 15.0,
    "insufficient_context": 35.0,
}


def score_incident_risk(
    case: dict[str, Any],
    hypothesis_rows: list[dict[str, Any]],
    business_impact: BusinessImpactAssessment,
    uncertainty: UncertaintyAssessment,
    asset: dict[str, Any] | None,
    identity: dict[str, Any] | None,
) -> IncidentRiskScore:
    asset = asset or {}
    identity = identity or {}
    max_priority = float(case.get("max_analyst_priority_score") or case.get("case_priority_score") or 0)
    graph_score = max((float(row.get("feasibility_score") or 0) * 100 for row in hypothesis_rows), default=GRAPH_STATUS_SCORE.get(uncertainty.graph_validation_status, 35.0))
    if uncertainty.graph_validation_status in GRAPH_STATUS_SCORE:
        graph_score = min(graph_score, GRAPH_STATUS_SCORE[uncertainty.graph_validation_status])
    techniques = dedupe([tech for row in hypothesis_rows for tech in row.get("mitre_techniques", [])])
    technique_score = max((TECHNIQUE_SEVERITY.get(tech, TECHNIQUE_SEVERITY.get(tech.split(".")[0], 50.0)) for tech in techniques), default=45.0)
    asset_score = ASSET_CRITICALITY.get(str(asset.get("asset_criticality") or "").lower(), 50.0)
    identity_score = float(identity.get("identity_risk_score") or (88 if str(identity.get("privileged_account")).lower() == "true" else 45))
    evidence_count = len(set(case.get("evidence_ids") or [e for row in hypothesis_rows for e in row.get("evidence_ids", [])]))
    evidence_strength = min(95.0, 35.0 + evidence_count * 2.0)
    policy_sensitivity_score = policy_sensitivity(case, asset, identity)
    raw = (
        0.20 * max_priority
        + 0.20 * business_impact.business_impact_score
        + 0.15 * graph_score
        + 0.15 * technique_score
        + 0.10 * asset_score
        + 0.10 * identity_score
        + 0.05 * evidence_strength
        + 0.05 * policy_sensitivity_score
    )
    if uncertainty.graph_validation_status == "conditional":
        raw -= 5.0
    elif uncertainty.graph_validation_status == "not_enough_graph_context":
        raw -= 10.0
    elif uncertainty.graph_validation_status in {"infeasible", "unsupported"}:
        raw = min(raw, 58.0)
    score = round(clamp(raw), 2)
    drivers = build_risk_drivers(case, asset, identity, techniques, business_impact)
    evidence_ids = dedupe([e for row in hypothesis_rows for e in row.get("evidence_ids", [])]) or (case.get("evidence_ids") or [])
    alert_uids = dedupe([a for row in hypothesis_rows for a in row.get("alert_uids", [])])
    return IncidentRiskScore(
        case_id=case["case_id"],
        risk_score=score,
        risk_label=score_label(score),
        confidence_score=uncertainty.confidence_score,
        uncertainty_label=uncertainty.uncertainty_label,
        business_impact_score=business_impact.business_impact_score,
        technical_severity_score=round(technique_score, 2),
        graph_feasibility_status=uncertainty.graph_validation_status,
        policy_sensitivity=policy_sensitivity_label(policy_sensitivity_score),
        risk_drivers=drivers,
        uncertainty_drivers=uncertainty.uncertainty_drivers,
        evidence_ids=evidence_ids[:25],
        alert_uids=alert_uids[:25],
    )


def policy_sensitivity(case: dict[str, Any], asset: dict[str, Any], identity: dict[str, Any]) -> float:
    score = 35.0
    if str(identity.get("privileged_account")).lower() == "true":
        score += 25
    if str(asset.get("crown_jewel")).lower() == "true":
        score += 20
    if asset.get("regulatory_scope"):
        score += 10
    if "finance" in str(asset.get("business_unit") or case.get("business_unit") or "").lower():
        score += 10
    return clamp(score)


def policy_sensitivity_label(score: float) -> str:
    if score >= 75:
        return "approval_required"
    if score >= 55:
        return "policy_sensitive"
    return "standard"


def build_risk_drivers(
    case: dict[str, Any],
    asset: dict[str, Any],
    identity: dict[str, Any],
    techniques: list[str],
    business_impact: BusinessImpactAssessment,
) -> list[str]:
    drivers = []
    if business_impact.business_impact_label in {"high", "critical"}:
        drivers.append(f"{business_impact.business_impact_label} business impact")
    if asset.get("asset_criticality"):
        drivers.append(f"{asset.get('asset_criticality')} asset criticality")
    if str(identity.get("privileged_account")).lower() == "true":
        drivers.append("privileged identity")
    if any(tech in {"T1546.011", "T1574.001"} for tech in techniques):
        drivers.append("persistence or execution-flow technique")
    if case.get("case_priority_label"):
        drivers.append(str(case.get("case_priority_label")))
    return drivers or ["evidence-linked security case"]
