from __future__ import annotations

from typing import Any

from safeagentsoc.govern.schemas import BusinessImpactAssessment, CisoDecisionBrief, IncidentRiskScore, PolicyDecision, SafeRecommendation, UncertaintyAssessment


def build_ciso_brief(
    case: dict[str, Any],
    risk: IncidentRiskScore,
    uncertainty: UncertaintyAssessment,
    business: BusinessImpactAssessment,
    recommendations: list[SafeRecommendation],
    policies: list[PolicyDecision],
) -> CisoDecisionBrief:
    blocked = [policy.action_id for policy in policies if policy.policy_decision == "blocked"]
    approval = [policy.action_id for policy in policies if policy.policy_decision == "approval_required"]
    recommended = recommendations[0].recommended_action_id if recommendations else "continue_monitoring"
    situation = f"{case.get('case_title') or case['case_id']} is a {risk.risk_label} risk case affecting {business.business_service or 'an unresolved service'}."
    confirmed = ["case-local evidence exists", f"graph validation status is {risk.graph_feasibility_status}"]
    not_confirmed = ["confirmed compromise", "confirmed lateral movement", "confirmed exfiltration", "confirmed customer impact"]
    board = (
        f"SafeAgentSOC assessed {case['case_id']} as {risk.risk_label} risk with {uncertainty.uncertainty_label} uncertainty. "
        f"The case affects {business.business_service or 'a business service'} and has graph status {risk.graph_feasibility_status}. "
        "The system preserved evidence links, blocked unsafe actions where policy required, and recommended validation before disruptive containment."
    )
    return CisoDecisionBrief(
        case_id=case["case_id"],
        risk_label=risk.risk_label,
        risk_score=risk.risk_score,
        confidence_score=risk.confidence_score,
        uncertainty_label=uncertainty.uncertainty_label,
        situation=situation,
        business_impact=business.business_impact_summary,
        evidence_basis=risk.evidence_ids[:10],
        confirmed=confirmed,
        not_confirmed=not_confirmed,
        recommended_decision=recommended,
        blocked_actions=blocked,
        approval_required=approval,
        residual_risk="Residual risk remains until missing evidence and graph context are validated.",
        next_update_trigger="Update after Tier 2 validation, endpoint scan result, identity review, or new evidence.",
        board_narrative=board,
    )
