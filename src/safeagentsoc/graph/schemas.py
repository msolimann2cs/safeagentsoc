from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


GRAPH_STATUSES = {
    "feasible",
    "conditional",
    "infeasible",
    "unsupported",
    "not_enough_graph_context",
    "mixed",
    "retry_required",
}


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: str
    source_id: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GraphEdge:
    edge_id: str
    source: str
    target: str
    relationship: str
    weight: float = 1.0
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HypothesisGraphClaim:
    claim_id: str
    case_id: str
    hypothesis_id: str
    claim_type: str
    claim_text: str
    techniques: list[str]
    evidence_ids: list[str]
    alert_uids: list[str]
    claim_source: str
    critical: bool = True
    decision_ledger_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ClaimEntityResolution:
    claim_id: str
    case_id: str
    hypothesis_id: str
    resolved_entities: dict[str, list[str]]
    entity_resolution_score: float
    unresolved_entities: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ClaimPathValidation:
    claim_id: str
    case_id: str
    hypothesis_id: str
    path_existence_score: float
    evidence_alignment_score: float
    privilege_or_access_score: float
    network_reachability_score: float
    path_exists: bool
    supporting_paths: list[list[str]]
    missing_requirements: list[str]
    contradictions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GraphValidationResult:
    case_id: str
    hypothesis_id: str
    claim_id: str
    claim_type: str
    graph_validation_status: str
    feasibility_score: float
    graph_explanation: str
    supporting_graph_facts: list[str]
    missing_graph_requirements: list[str]
    validated_claims: list[str]
    conditional_claims: list[str]
    rejected_claims: list[str]
    evidence_ids: list[str]
    alert_uids: list[str]
    mitre_techniques: list[str]
    decision_ledger_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MissingGraphEvidence:
    case_id: str
    hypothesis_id: str
    claim_id: str
    missing_type: str
    reason: str
    effect: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
