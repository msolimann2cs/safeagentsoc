from __future__ import annotations

from typing import Any

from safeagentsoc.govern.schemas import IncidentRiskScore, PolicyDecision, ResponseAction, UncertaintyAssessment


HIGH_IMPACT_ACTIONS = {
    "disable_user_account",
    "isolate_critical_server",
    "block_ip_domain",
    "revoke_tokens",
    "quarantine_file",
}
PUBLIC_ACTIONS = {"public_customer_communication", "prepare_holding_statement"}


def decide_policy(
    *,
    case_id: str,
    action: ResponseAction | None,
    action_id: str,
    risk: IncidentRiskScore,
    uncertainty: UncertaintyAssessment,
    business_impact_label: str,
    evidence_ids: list[str],
    privileged_identity: bool,
    finance_or_payroll: bool,
) -> PolicyDecision:
    if action is None:
        return PolicyDecision(
            decision_id=f"{case_id}|{action_id}|policy",
            case_id=case_id,
            action_id=action_id,
            policy_decision="blocked",
            policy_ids=["POL-ACTION-000"],
            reason="Action is outside the finite Phase 9 action catalog.",
            approver_required=None,
            evidence_ids=evidence_ids,
            graph_validation_status=risk.graph_feasibility_status,
            confidence_score=risk.confidence_score,
            safer_alternatives=["create_analyst_task", "review_logs"],
        )
    policy_ids: list[str] = []
    reasons: list[str] = []
    decision = "allowed"
    approver = action.required_approver if action.requires_approval else None

    if risk.graph_feasibility_status not in action.allowed_graph_statuses:
        decision = "blocked" if action.tier >= 3 else "monitor_only"
        policy_ids.append("POL-ACTION-001")
        reasons.append(f"{action.action_id} is not allowed for graph status {risk.graph_feasibility_status}.")
    if risk.confidence_score < action.minimum_confidence:
        decision = "blocked" if action.tier >= 3 else "insufficient_evidence"
        policy_ids.append("POL-ACTION-004")
        reasons.append(f"Current confidence {risk.confidence_score:.2f} is below required {action.minimum_confidence:.2f}.")
    if action.action_id in HIGH_IMPACT_ACTIONS and risk.graph_feasibility_status != "feasible":
        decision = "blocked"
        policy_ids.append("POL-ACTION-001")
        reasons.append("High-impact action cannot be driven by non-feasible graph evidence.")
    if action.action_id == "disable_user_account" and privileged_identity:
        if decision != "blocked":
            decision = "approval_required"
        approver = "CISO_or_delegate_and_identity_owner"
        policy_ids.append("POL-ACTION-002")
        reasons.append("Privileged identity containment requires explicit approval.")
    if finance_or_payroll and action.action_id in {"disable_user_account", "revoke_tokens"}:
        decision = "blocked"
        policy_ids.append("POL-ACTION-005")
        reasons.append("Payroll or finance-sensitive identity disruption is blocked without stronger evidence and business-owner approval.")
    if action.action_id in PUBLIC_ACTIONS:
        approver = "Legal_PR_and_CISO"
        policy_ids.append("POL-ACTION-003")
        reasons.append("External or public communication requires Legal, PR, and CISO approval.")
        if decision != "blocked":
            decision = "approval_required"
    if action.requires_approval and decision == "allowed":
        decision = "approval_required"
        policy_ids.append("POL-ACTION-006")
        reasons.append("Action metadata requires human approval.")
    if action.tier >= 3 and business_impact_label in {"high", "critical"} and decision != "blocked":
        decision = "approval_required"
        approver = approver or "CISO_or_delegate"
        policy_ids.append("POL-ACTION-007")
        reasons.append("High business impact requires approval for disruptive containment.")

    return PolicyDecision(
        decision_id=f"{case_id}|{action.action_id}|policy",
        case_id=case_id,
        action_id=action.action_id,
        policy_decision=decision,
        policy_ids=sorted(set(policy_ids)) or ["POL-ACTION-ALLOW"],
        reason=" ".join(reasons) or "Action is allowed by catalog, evidence, graph, and confidence constraints.",
        approver_required=approver if decision == "approval_required" else None,
        evidence_ids=evidence_ids[:10],
        graph_validation_status=risk.graph_feasibility_status,
        confidence_score=risk.confidence_score,
        safer_alternatives=action.safer_alternatives,
    )
