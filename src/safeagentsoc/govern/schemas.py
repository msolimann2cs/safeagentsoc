from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class IncidentRiskScore:
    case_id: str
    risk_score: float
    risk_label: str
    confidence_score: float
    uncertainty_label: str
    business_impact_score: float
    technical_severity_score: float
    graph_feasibility_status: str
    policy_sensitivity: str
    risk_drivers: list[str]
    uncertainty_drivers: list[str]
    evidence_ids: list[str]
    alert_uids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class UncertaintyAssessment:
    case_id: str
    uncertainty_score: float
    uncertainty_label: str
    confidence_score: float
    evidence_sufficiency: str
    uncertainty_drivers: list[str]
    not_sufficient_for: list[str]
    graph_validation_status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BusinessImpactAssessment:
    case_id: str
    affected_asset: str | None
    business_service: str | None
    business_unit: str | None
    business_impact_score: float
    business_impact_label: str
    blast_radius: dict[str, Any]
    business_impact_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ResponseAction:
    action_id: str
    description: str
    tier: int
    risk_level: str
    reversibility: str
    business_disruption: str
    requires_approval: bool
    required_approver: str | None
    allowed_graph_statuses: list[str]
    minimum_confidence: float
    forbidden_when: list[str] = field(default_factory=list)
    safer_alternatives: list[str] = field(default_factory=list)
    stakeholder_notifications: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    simulated_connector: str = "siem_case_note"
    would_call: str = "SIEM.add_case_note"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PolicyDecision:
    decision_id: str
    case_id: str
    action_id: str
    policy_decision: str
    policy_ids: list[str]
    reason: str
    approver_required: str | None
    evidence_ids: list[str]
    graph_validation_status: str
    confidence_score: float
    safer_alternatives: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovalDecision:
    approval_id: str
    case_id: str
    action_id: str
    approval_status: str
    required_approvers: list[str]
    approval_reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SafeRecommendation:
    recommendation_id: str
    case_id: str
    recommended_action_id: str
    recommendation_rank: int
    policy_decision: str
    risk_reduction_potential: str
    business_disruption: str
    reversibility: str
    confidence_required: float
    current_confidence: float
    evidence_ids: list[str]
    why_recommended: str
    why_not_stronger_action: str
    approver_required: str | None
    safer_alternatives: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SoarDryRun:
    dry_run_id: str
    case_id: str
    action_id: str
    dry_run_status: str
    would_call: str
    required_approval: str | None
    policy_decision: str
    business_impact: str
    rollback_plan: str
    audit_note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CsirtPack:
    case_id: str
    csirt_status: str
    incident_commander_needed: bool
    scope: str
    affected_assets: list[str]
    affected_identities: list[str]
    evidence_ids: list[str]
    graph_validation_status: str
    risk_label: str
    uncertainty_label: str
    containment_options: list[str]
    blocked_actions: list[str]
    approval_requirements: list[str]
    communications_status: str
    open_questions: list[str]
    next_30_60_120_minute_actions: dict[str, list[str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StakeholderMessage:
    message_id: str
    case_id: str
    audience: str
    classification: str
    approval_required: bool
    allowed_claims: list[str]
    forbidden_claims: list[str]
    evidence_basis: list[str]
    uncertainty: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CisoDecisionBrief:
    case_id: str
    risk_label: str
    risk_score: float
    confidence_score: float
    uncertainty_label: str
    situation: str
    business_impact: str
    evidence_basis: list[str]
    confirmed: list[str]
    not_confirmed: list[str]
    recommended_decision: str
    blocked_actions: list[str]
    approval_required: list[str]
    residual_risk: str
    next_update_trigger: str
    board_narrative: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FrameworkMapping:
    mapping_id: str
    case_id: str
    framework: str
    function_or_domain: str
    mapped_outputs: list[str]
    evidence: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Phase9LedgerEntry:
    decision_id: str
    case_id: str
    object_type: str
    object_id: str
    decision: str
    reason: str
    evidence_ids: list[str]
    input_hash: str
    output_hash: str
    created_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
