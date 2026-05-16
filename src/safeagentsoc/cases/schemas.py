from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


RuntimeAlertRole = Literal["trigger", "supporting", "duplicate", "noise", "context", "unrelated"]
VisibilityLevel = Literal["visible_primary", "visible_supporting", "collapsed_duplicate", "collapsed_noise", "excluded"]
CasePriorityLabel = Literal["P1 critical", "P2 high", "P3 medium", "P4 low"]


@dataclass(frozen=True)
class CaseSeed:
    case_seed_id: str
    seed_alert_uid: str
    seed_evidence_id: str
    seed_reason: str
    seed_priority_score: float
    seed_business_risk_score: float
    seed_asset_id: str | None
    seed_identity_id: str | None
    seed_rule_id: str | None
    seed_behavior_family: str
    seed_mitre_techniques: list[str]
    seed_time: str


@dataclass
class DuplicateGroup:
    duplicate_group_id: str
    duplicate_type: str
    duplicate_fingerprint: str
    representative_alert_uid: str
    duplicate_alert_uids: list[str]
    duplicate_count: int


@dataclass
class CaseAlertLink:
    case_id: str
    alert_uid: str
    evidence_id: str
    runtime_alert_role: RuntimeAlertRole
    role_confidence: float
    role_reason: str
    role_features: list[str] = field(default_factory=list)
    case_affinity_score: float = 0.0
    case_affinity_reasons: list[str] = field(default_factory=list)
    visibility_level: VisibilityLevel = "visible_supporting"
    suppression_safe: bool = False
    suppression_reason: str | None = None
    must_remain_visible_reason: str | None = None
    preserved_unique_evidence_types: list[str] = field(default_factory=list)
    representative_alert_uid: str | None = None
    duplicate_group_id: str | None = None


@dataclass
class GeneratedCase:
    case_id: str
    case_schema_version: str
    case_status: str
    case_created_at_utc: str
    case_start_time_utc: str
    case_end_time_utc: str
    case_duration_minutes: float
    primary_asset_id: str | None
    primary_identity_id: str | None
    business_unit: str | None
    business_service: str | None
    case_priority_score: float
    case_priority_label: CasePriorityLabel
    case_business_impact_score: float
    case_confidence: float
    alert_count_total: int
    visible_alert_count: int
    suppressed_alert_count: int
    trigger_alert_count: int
    supporting_alert_count: int
    duplicate_alert_count: int
    noise_alert_count: int
    context_alert_count: int
    mitre_technique_ids: list[str]
    mitre_tactics: list[str]
    rule_ids: list[str]
    evidence_ids: list[str]
    case_title: str
    case_summary: str
    case_rationale: list[str]
    max_analyst_priority_score: float
    max_business_risk_score: float
    case_seed_alert_uid: str | None = None
    primary_behavior_family: str | None = None
    case_alerts: list[dict[str, Any]] = field(default_factory=list)

