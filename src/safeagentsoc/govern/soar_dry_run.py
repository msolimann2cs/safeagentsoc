from __future__ import annotations

from safeagentsoc.govern.schemas import PolicyDecision, ResponseAction, SoarDryRun


ROLLBACK = {
    "force_mfa_reauth": "remove temporary sign-in challenge after validation window if needed",
    "disable_active_sessions": "allow normal re-authentication after identity review",
    "isolate_endpoint": "remove isolation from EDR console after approval and validation",
    "request_edr_scan": "cancel queued scan if change window is rejected",
    "open_it_ticket": "close or reassign ticket with audit note",
    "create_analyst_task": "close analyst task with disposition",
}


def build_soar_dry_run(action: ResponseAction, policy: PolicyDecision, business_impact_label: str) -> SoarDryRun:
    return SoarDryRun(
        dry_run_id=f"{policy.case_id}|{action.action_id}|dry_run",
        case_id=policy.case_id,
        action_id=action.action_id,
        dry_run_status="not_executed",
        would_call=action.would_call,
        required_approval=policy.approver_required,
        policy_decision=policy.policy_decision,
        business_impact=business_impact_label,
        rollback_plan=ROLLBACK.get(action.action_id, "document reversal steps before execution"),
        audit_note="No external API was called. This is a Phase 9 SOAR dry-run simulation.",
    )
