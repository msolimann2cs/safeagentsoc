from __future__ import annotations

from dataclasses import dataclass
from typing import Any


UNKNOWN_ASSET_ID = "__UNKNOWN__"


@dataclass(frozen=True)
class ContextConfidenceResult:
    context_confidence: float
    missing_context_fields: list[str]
    confidence_factors: dict[str, float]
    recommended_follow_up: list[str]


def has_value(value: Any) -> bool:
    return value not in (None, "", [], {})


def known_context(context: dict[str, Any] | None, key: str) -> bool:
    if not context:
        return False
    if context.get("status") == "unknown":
        return False
    return has_value(context.get(key))


def missing_fields(
    asset_context: dict[str, Any] | None,
    identity_context: dict[str, Any] | None,
    network_context: dict[str, Any] | None,
    policy_context: dict[str, Any] | None,
    identity_applicability_status: str = "unknown",
) -> list[str]:
    missing: list[str] = []
    if not known_context(asset_context, "asset_id"):
        missing.extend(
            [
                "asset_context.asset_id",
                "asset_context.logical_asset_name",
                "asset_context.business_unit",
                "asset_context.business_service",
                "asset_context.asset_criticality",
            ]
        )
    if identity_applicability_status in {"missing", "unknown"} and not known_context(identity_context, "identity_id"):
        missing.extend(
            [
                "identity_context.identity_id",
                "identity_context.logical_username",
                "identity_context.privileged_account",
                "identity_context.identity_risk_score",
            ]
        )
    if not known_context(network_context, "network_zone_id"):
        missing.extend(["network_context.network_zone_id", "network_context.network_zone"])
    if not policy_context or not policy_context.get("relevant_policy_ids"):
        missing.append("policy_context.relevant_policy_ids")
    return sorted(set(missing))


def recommended_follow_up(missing: list[str]) -> list[str]:
    recommendations: list[str] = []
    if any(field.startswith("asset_context") for field in missing):
        recommendations.append("review asset inventory coverage for this observed host")
    if any(field.startswith("identity_context") for field in missing):
        recommendations.append("review identity context for the observed user")
    if any(field.startswith("network_context") for field in missing):
        recommendations.append("review network zone mapping for this asset or IP")
    if any(field.startswith("policy_context") for field in missing):
        recommendations.append("review policy relevance mapping for this alert pattern")
    return recommendations


def calculate_context_confidence(
    *,
    mapping_confidence: float,
    asset_context: dict[str, Any] | None,
    identity_context: dict[str, Any] | None,
    network_context: dict[str, Any] | None,
    policy_context: dict[str, Any] | None,
    evidence_id: str | None,
    identity_applicability_status: str = "unknown",
) -> ContextConfidenceResult:
    missing = missing_fields(asset_context, identity_context, network_context, policy_context, identity_applicability_status)
    asset_score = 1.0 if known_context(asset_context, "asset_id") else 0.0
    if identity_applicability_status == "not_applicable":
        identity_score = 1.0
    else:
        identity_score = 1.0 if known_context(identity_context, "identity_id") else 0.0
    network_score = 1.0 if known_context(network_context, "network_zone_id") else 0.0
    business_service_score = 1.0 if known_context(asset_context, "business_service") else 0.0
    policy_score = 1.0 if policy_context and policy_context.get("relevant_policy_ids") else 0.0
    evidence_score = 1.0 if evidence_id else 0.0

    score = (
        0.25 * asset_score
        + 0.20 * identity_score
        + 0.15 * network_score
        + 0.15 * max(0.0, min(mapping_confidence, 1.0))
        + 0.10 * business_service_score
        + 0.10 * policy_score
        + 0.05 * evidence_score
    )
    factors = {
        "asset_match_confidence": asset_score,
        "identity_match_confidence": identity_score,
        "network_match_confidence": network_score,
        "mapping_rule_confidence": round(max(0.0, min(mapping_confidence, 1.0)), 4),
        "business_service_completeness": business_service_score,
        "policy_context_completeness": policy_score,
        "evidence_integrity": evidence_score,
    }
    return ContextConfidenceResult(
        context_confidence=round(score, 4),
        missing_context_fields=missing,
        confidence_factors=factors,
        recommended_follow_up=recommended_follow_up(missing),
    )


def unknown_asset_context() -> dict[str, Any]:
    return {
        "status": "unknown",
        "asset_id": None,
        "logical_asset_name": None,
        "asset_owner": None,
        "business_unit": None,
        "business_service": None,
        "asset_criticality": "unknown",
        "environment": None,
        "asset_role": None,
        "exposure_level": "unknown",
        "internet_facing": None,
        "crown_jewel": None,
        "data_classification": "unknown",
    }


def unknown_identity_context() -> dict[str, Any]:
    return {
        "status": "unknown",
        "identity_id": None,
        "logical_username": None,
        "user_department": None,
        "user_role": None,
        "privileged_account": None,
        "service_account": None,
        "identity_risk_score": None,
        "mfa_status": None,
        "manager_or_owner": None,
    }


def unknown_network_context() -> dict[str, Any]:
    return {
        "status": "unknown",
        "network_zone_id": None,
        "network_zone": None,
        "subnet": None,
        "site": None,
        "cloud_region": None,
        "vpc_or_vlan": None,
        "trusted_boundary_crossing": None,
        "known_admin_network": None,
        "known_scanner_network": None,
    }
