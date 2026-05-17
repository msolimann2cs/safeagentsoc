from __future__ import annotations

from safeagentsoc.govern.schemas import IncidentRiskScore, PolicyDecision, ResponseAction, SafeRecommendation


RISK_REDUCTION = {
    "request_edr_scan": "high",
    "force_mfa_reauth": "medium",
    "disable_active_sessions": "medium",
    "isolate_endpoint": "high",
    "escalate_to_tier2": "medium",
    "review_logs": "low",
    "inspect_endpoint_telemetry": "medium",
    "check_related_alerts": "medium",
    "continue_monitoring": "low",
    "create_analyst_task": "low",
    "open_it_ticket": "medium",
}


def rank_recommendations(
    case_id: str,
    actions: dict[str, ResponseAction],
    policies: list[PolicyDecision],
    risk: IncidentRiskScore,
) -> list[SafeRecommendation]:
    allowed = [policy for policy in policies if policy.policy_decision in {"allowed", "approval_required", "monitor_only"}]
    allowed.sort(key=lambda p: _rank_key(actions.get(p.action_id), p))
    blocked = [policy.action_id for policy in policies if policy.policy_decision == "blocked"]
    recommendations: list[SafeRecommendation] = []
    for index, policy in enumerate(allowed[:6], start=1):
        action = actions[policy.action_id]
        recommendations.append(
            SafeRecommendation(
                recommendation_id=f"{case_id}|{action.action_id}|recommendation",
                case_id=case_id,
                recommended_action_id=action.action_id,
                recommendation_rank=index,
                policy_decision=policy.policy_decision,
                risk_reduction_potential=RISK_REDUCTION.get(action.action_id, "low"),
                business_disruption=action.business_disruption,
                reversibility=action.reversibility,
                confidence_required=action.minimum_confidence,
                current_confidence=risk.confidence_score,
                evidence_ids=policy.evidence_ids,
                why_recommended=_why_recommended(action, risk, policy),
                why_not_stronger_action=_why_not_stronger(blocked, policies),
                approver_required=policy.approver_required,
                safer_alternatives=policy.safer_alternatives,
            )
        )
    return recommendations


def _rank_key(action: ResponseAction | None, policy: PolicyDecision) -> tuple[int, int, int]:
    if action is None:
        return (99, 99, 99)
    decision_rank = {"allowed": 0, "approval_required": 1, "monitor_only": 2}.get(policy.policy_decision, 3)
    disruption_rank = {"low": 0, "medium": 1, "high": 2}.get(action.business_disruption, 3)
    tier_rank = action.tier
    return (decision_rank, disruption_rank, tier_rank)


def _why_recommended(action: ResponseAction, risk: IncidentRiskScore, policy: PolicyDecision) -> str:
    return (
        f"{action.description} is appropriate for a {risk.risk_label} risk case with "
        f"{risk.graph_feasibility_status} graph validation and policy decision {policy.policy_decision}."
    )


def _why_not_stronger(blocked: list[str], policies: list[PolicyDecision]) -> str:
    if not blocked:
        return "No stronger catalog action was blocked for this case."
    reasons = [policy.reason for policy in policies if policy.action_id in blocked]
    return "Stronger action is constrained because " + (reasons[0] if reasons else ", ".join(blocked))
