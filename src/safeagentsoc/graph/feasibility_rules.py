from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FeasibilityRule:
    claim_type: str
    required: tuple[str, ...]
    optional: tuple[str, ...]
    feasible_threshold: float = 0.85
    conditional_threshold: float = 0.55


DEFAULT_RULES: dict[str, FeasibilityRule] = {
    "execution_claim": FeasibilityRule(
        "execution_claim",
        ("evidence_exists", "asset_or_host_exists", "technique_present"),
        ("process_or_file_evidence",),
        0.78,
        0.50,
    ),
    "persistence_claim": FeasibilityRule(
        "persistence_claim",
        ("evidence_exists", "asset_or_host_exists", "technique_present"),
        ("process_or_file_evidence", "privileged_identity"),
        0.78,
        0.52,
    ),
    "privilege_claim": FeasibilityRule(
        "privilege_claim",
        ("evidence_exists", "identity_exists", "asset_or_host_exists"),
        ("privilege_edge", "technique_present"),
        0.82,
        0.55,
    ),
    "credential_access_claim": FeasibilityRule(
        "credential_access_claim",
        ("evidence_exists", "identity_exists", "technique_present"),
        ("auth_context", "privileged_identity"),
        0.82,
        0.55,
    ),
    "lateral_movement_claim": FeasibilityRule(
        "lateral_movement_claim",
        ("evidence_exists", "source_asset_exists", "target_asset_exists", "remote_service_or_lateral_movement_technique"),
        ("network_zone_reachability", "identity_access_edge", "cross_host_evidence"),
        0.80,
        0.55,
    ),
    "network_reachability_claim": FeasibilityRule(
        "network_reachability_claim",
        ("evidence_exists", "network_zone_exists"),
        ("external_destination", "zone_reachability"),
        0.78,
        0.52,
    ),
    "exfiltration_claim": FeasibilityRule(
        "exfiltration_claim",
        ("evidence_exists", "external_destination", "exfiltration_technique_or_rule"),
        ("outbound_transfer_evidence", "sensitive_asset"),
        0.85,
        0.60,
    ),
    "impact_claim": FeasibilityRule(
        "impact_claim",
        ("evidence_exists", "asset_or_host_exists", "impact_technique"),
        ("critical_asset", "destructive_signal"),
        0.85,
        0.58,
    ),
    "defense_evasion_claim": FeasibilityRule(
        "defense_evasion_claim",
        ("evidence_exists", "asset_or_host_exists", "technique_present"),
        ("process_or_file_evidence",),
        0.78,
        0.50,
    ),
    "identity_claim": FeasibilityRule(
        "identity_claim",
        ("evidence_exists", "identity_exists"),
        ("identity_access_edge", "privileged_identity"),
        0.75,
        0.48,
    ),
    "host_claim": FeasibilityRule(
        "host_claim",
        ("evidence_exists", "host_exists"),
        ("asset_exists", "network_zone_exists"),
        0.75,
        0.48,
    ),
    "asset_claim": FeasibilityRule(
        "asset_claim",
        ("evidence_exists", "asset_exists"),
        ("business_context", "network_zone_exists"),
        0.75,
        0.48,
    ),
    "business_context_claim": FeasibilityRule(
        "business_context_claim",
        ("asset_exists", "business_service_exists"),
        ("business_unit_exists", "policy_exists"),
        0.72,
        0.48,
    ),
    "technique_claim": FeasibilityRule(
        "technique_claim",
        ("evidence_exists", "technique_present"),
        ("asset_or_host_exists",),
        0.72,
        0.48,
    ),
    "telemetry_backlog_claim": FeasibilityRule(
        "telemetry_backlog_claim",
        ("evidence_exists",),
        ("case_volume_context", "monitoring_asset"),
        0.70,
        0.45,
    ),
}


def load_feasibility_rules(path: Path | None = None) -> dict[str, FeasibilityRule]:
    """Return deterministic built-in rules.

    The YAML file is shipped as human-readable configuration for reports and review.
    The runtime intentionally avoids a PyYAML dependency in this repository.
    """
    return dict(DEFAULT_RULES)


def rule_for(claim_type: str, rules: dict[str, FeasibilityRule] | None = None) -> FeasibilityRule:
    active_rules = rules or DEFAULT_RULES
    return active_rules.get(claim_type) or active_rules["technique_claim"]


def rules_as_dict(rules: dict[str, FeasibilityRule] | None = None) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "required": list(rule.required),
            "optional": list(rule.optional),
            "feasible_threshold": rule.feasible_threshold,
            "conditional_threshold": rule.conditional_threshold,
        }
        for name, rule in (rules or DEFAULT_RULES).items()
    }
