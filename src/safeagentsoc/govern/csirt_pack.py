from __future__ import annotations

from typing import Any

from safeagentsoc.govern.schemas import BusinessImpactAssessment, CsirtPack, IncidentRiskScore, PolicyDecision, SafeRecommendation, UncertaintyAssessment


def build_csirt_pack(
    case: dict[str, Any],
    risk: IncidentRiskScore,
    uncertainty: UncertaintyAssessment,
    business: BusinessImpactAssessment,
    recommendations: list[SafeRecommendation],
    policies: list[PolicyDecision],
) -> CsirtPack:
    blocked = [policy.action_id for policy in policies if policy.policy_decision == "blocked"]
    approval = [f"{policy.action_id}: {policy.approver_required}" for policy in policies if policy.policy_decision == "approval_required"]
    options = [rec.recommended_action_id for rec in recommendations[:5]]
    status = "triage_escalation_candidate" if risk.risk_label in {"high", "critical"} else "monitoring_candidate"
    return CsirtPack(
        case_id=case["case_id"],
        csirt_status=status,
        incident_commander_needed=risk.risk_label == "critical",
        scope=f"{business.affected_asset or 'unresolved asset'} supporting {business.business_service or 'unresolved service'}",
        affected_assets=[item for item in [case.get("primary_asset_id"), business.affected_asset] if item],
        affected_identities=[case.get("primary_identity_id")] if case.get("primary_identity_id") else [],
        evidence_ids=risk.evidence_ids[:15],
        graph_validation_status=risk.graph_feasibility_status,
        risk_label=risk.risk_label,
        uncertainty_label=uncertainty.uncertainty_label,
        containment_options=options,
        blocked_actions=blocked,
        approval_requirements=approval,
        communications_status="internal_draft_only",
        open_questions=[
            "Was the observed activity approved administrative work?",
            "Is there related identity activity outside the current evidence set?",
            "Is there evidence of lateral movement, C2, exfiltration, or impact?",
        ],
        next_30_60_120_minute_actions={
            "30_minutes": ["review cited evidence", "assign owner", "validate user and host context"],
            "60_minutes": ["check related alerts", "review endpoint telemetry", "confirm business owner constraints"],
            "120_minutes": ["decide whether CSIRT escalation is required", "prepare approved stakeholder update if needed"],
        },
    )
