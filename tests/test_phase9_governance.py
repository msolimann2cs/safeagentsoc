from __future__ import annotations

from safeagentsoc.govern.action_catalog import validate_action_id
from safeagentsoc.govern.policy_engine import decide_policy
from safeagentsoc.govern.schemas import IncidentRiskScore, ResponseAction, StakeholderMessage, UncertaintyAssessment
from safeagentsoc.govern.soar_dry_run import build_soar_dry_run
from safeagentsoc.govern.stakeholder_communication import lint_messages


def _risk(graph_status: str = "conditional", confidence: float = 0.72) -> IncidentRiskScore:
    return IncidentRiskScore(
        case_id="case_rt_test",
        risk_score=80.0,
        risk_label="high",
        confidence_score=confidence,
        uncertainty_label="medium",
        business_impact_score=82.0,
        technical_severity_score=75.0,
        graph_feasibility_status=graph_status,
        policy_sensitivity="policy_sensitive",
        risk_drivers=["critical asset"],
        uncertainty_drivers=["conditional graph validation"],
        evidence_ids=["evidence_1"],
        alert_uids=["alert_1"],
    )


def _uncertainty(graph_status: str = "conditional") -> UncertaintyAssessment:
    return UncertaintyAssessment(
        case_id="case_rt_test",
        uncertainty_score=0.35,
        uncertainty_label="medium",
        confidence_score=0.65,
        evidence_sufficiency="sufficient_for_monitoring_and_Tier2_review",
        uncertainty_drivers=["conditional graph validation"],
        not_sufficient_for=["account disablement"],
        graph_validation_status=graph_status,
    )


def _action(action_id: str = "disable_user_account") -> ResponseAction:
    return ResponseAction(
        action_id=action_id,
        description="Disable the involved user account.",
        tier=3,
        risk_level="high",
        reversibility="medium",
        business_disruption="high",
        requires_approval=True,
        required_approver="CISO_or_delegate",
        allowed_graph_statuses=["feasible"],
        minimum_confidence=0.85,
        safer_alternatives=["force_mfa_reauth"],
        stakeholder_notifications=["CISO"],
        evidence_requirements=["identity_id", "evidence_id"],
        simulated_connector="identity_provider",
        would_call="IdP.disable_user",
    )


def test_policy_blocks_high_impact_action_on_conditional_graph_status() -> None:
    decision = decide_policy(
        case_id="case_rt_test",
        action=_action(),
        action_id="disable_user_account",
        risk=_risk("conditional", 0.8),
        uncertainty=_uncertainty("conditional"),
        business_impact_label="high",
        evidence_ids=["evidence_1"],
        privileged_identity=True,
        finance_or_payroll=False,
    )
    assert decision.policy_decision == "blocked"
    assert "POL-ACTION-001" in decision.policy_ids


def test_unknown_action_is_not_valid_catalog_action() -> None:
    assert not validate_action_id("format_the_server", {})


def test_soar_dry_run_never_executes_real_action() -> None:
    decision = decide_policy(
        case_id="case_rt_test",
        action=_action("disable_user_account"),
        action_id="disable_user_account",
        risk=_risk("conditional", 0.8),
        uncertainty=_uncertainty("conditional"),
        business_impact_label="high",
        evidence_ids=["evidence_1"],
        privileged_identity=True,
        finance_or_payroll=False,
    )
    dry_run = build_soar_dry_run(_action("disable_user_account"), decision, "high")
    assert dry_run.dry_run_status == "not_executed"
    assert dry_run.would_call == "IdP.disable_user"


def test_communication_linter_catches_public_overclaim() -> None:
    message = StakeholderMessage(
        message_id="case_rt_test|public|message",
        case_id="case_rt_test",
        audience="public_customer",
        classification="external_draft",
        approval_required=True,
        allowed_claims=[],
        forbidden_claims=["confirmed breach"],
        evidence_basis=["evidence_1"],
        uncertainty="medium",
        message="Confirmed breach with customer data impacted.",
    )
    findings = lint_messages([message])
    assert findings
