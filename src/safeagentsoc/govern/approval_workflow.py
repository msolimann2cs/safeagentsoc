from __future__ import annotations

from safeagentsoc.govern.schemas import ApprovalDecision, PolicyDecision


DEFAULT_APPROVERS = {
    "force_mfa_reauth": ["SOC Lead"],
    "disable_active_sessions": ["SOC Lead"],
    "isolate_endpoint": ["SOC Lead", "CSIRT Lead"],
    "disable_user_account": ["CISO or delegate", "Identity owner"],
    "isolate_critical_server": ["CISO or delegate", "IT Operations owner"],
    "public_customer_communication": ["Legal", "PR / Communications", "CISO"],
    "prepare_holding_statement": ["Legal", "PR / Communications", "CISO"],
    "notify_executive_team": ["CISO or delegate"],
}


def build_approval_decision(policy: PolicyDecision) -> ApprovalDecision:
    approvers = []
    if policy.policy_decision == "approval_required":
        approvers = DEFAULT_APPROVERS.get(policy.action_id) or [policy.approver_required or "SOC Lead"]
    status = "not_required" if policy.policy_decision != "approval_required" else "pending_human_approval"
    return ApprovalDecision(
        approval_id=f"{policy.case_id}|{policy.action_id}|approval",
        case_id=policy.case_id,
        action_id=policy.action_id,
        approval_status=status,
        required_approvers=approvers,
        approval_reason=policy.reason,
    )
