from __future__ import annotations

from typing import Any

from safeagentsoc.govern.io_utils import clamp, score_label
from safeagentsoc.govern.schemas import BusinessImpactAssessment


ASSET_CRITICALITY = {"critical": 95.0, "high": 80.0, "medium": 60.0, "low": 35.0}
DATA_CLASSIFICATION = {"restricted": 95.0, "confidential": 80.0, "internal": 55.0, "public": 25.0}
SERVICE_TIER = {"tier_0": 95.0, "tier_1": 80.0, "tier_2": 60.0, "tier_3": 40.0}


def assess_business_impact(case: dict[str, Any], asset: dict[str, Any] | None, identity: dict[str, Any] | None) -> BusinessImpactAssessment:
    asset = asset or {}
    identity = identity or {}
    case_score = float(case.get("case_business_impact_score") or case.get("max_business_risk_score") or 0)
    criticality = ASSET_CRITICALITY.get(str(asset.get("asset_criticality") or "").lower(), 50.0)
    data_score = DATA_CLASSIFICATION.get(str(asset.get("data_classification") or "").lower(), 45.0)
    tier_score = SERVICE_TIER.get(str(asset.get("service_tier") or "").lower(), 50.0)
    identity_score = float(identity.get("identity_risk_score") or (85 if str(identity.get("privileged_account")).lower() == "true" else 45))
    crown_jewel_bonus = 7.0 if str(asset.get("crown_jewel")).lower() == "true" else 0.0
    internet_bonus = 5.0 if str(asset.get("internet_facing")).lower() == "true" else 0.0
    score = clamp(0.35 * case_score + 0.25 * criticality + 0.15 * data_score + 0.15 * tier_score + 0.10 * identity_score + crown_jewel_bonus + internet_bonus)
    label = score_label(score)
    asset_name = asset.get("logical_asset_name") or case.get("primary_asset_id")
    service = asset.get("business_service") or case.get("business_service")
    unit = asset.get("business_unit") or case.get("business_unit")
    privileged = str(identity.get("privileged_account")).lower() == "true"
    blast_radius = {
        "direct_assets": 1 if asset_name else 0,
        "related_services": [service] if service else [],
        "business_unit": unit,
        "sensitive_data": asset.get("data_classification") or "unknown",
        "privileged_identity": privileged,
        "customer_facing": bool(str(asset.get("internet_facing")).lower() == "true"),
        "operational_dependency": "high" if score >= 75 else "medium" if score >= 50 else "low",
    }
    summary = (
        f"The case affects {asset_name or 'an unresolved asset'} supporting {service or 'an unresolved service'}. "
        f"A disruptive response could affect {unit or 'the owning business unit'} operations."
    )
    return BusinessImpactAssessment(
        case_id=case["case_id"],
        affected_asset=asset_name,
        business_service=service,
        business_unit=unit,
        business_impact_score=round(score, 2),
        business_impact_label=label,
        blast_radius=blast_radius,
        business_impact_summary=summary,
    )
