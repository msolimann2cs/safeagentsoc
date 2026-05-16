from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SEVERITY_SCORES = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
    "unknown": 35,
}

CRITICALITY_SCORES = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
    "unknown": 40,
}

CLASSIFICATION_SCORES = {
    "public": 10,
    "internal": 35,
    "confidential": 75,
    "restricted": 95,
    "unknown": 45,
}

EXPOSURE_SCORES = {
    "internal": 30,
    "limited": 50,
    "external": 80,
    "internet": 95,
    "unknown": 45,
}

SERVICE_IMPORTANCE_SCORES = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
    "unknown": 45,
}


@dataclass(frozen=True)
class BusinessRiskResult:
    business_risk_score: float
    business_risk_label: str
    risk_factors: list[str]
    risk_explanation: str
    risk_confidence: float
    score_components: dict[str, float]


def label_for_score(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def safe_lower(value: Any, default: str = "unknown") -> str:
    if value in (None, ""):
        return default
    return str(value).strip().lower()


def risk_factors_for(
    original_alert_summary: dict[str, Any],
    asset_context: dict[str, Any],
    identity_context: dict[str, Any],
    policy_context: dict[str, Any],
) -> list[str]:
    factors: list[str] = []
    severity = safe_lower(original_alert_summary.get("severity_normalized"))
    if severity in {"high", "critical"}:
        factors.append(f"{severity.title()} technical severity")

    asset_criticality = safe_lower(asset_context.get("asset_criticality"))
    if asset_criticality in {"high", "critical"}:
        factors.append(f"{asset_criticality.title()} criticality asset")

    if asset_context.get("crown_jewel") is True:
        factors.append("Crown-jewel business asset")

    data_classification = safe_lower(asset_context.get("data_classification"))
    if data_classification in {"confidential", "restricted"}:
        factors.append(f"{data_classification.title()} data classification")

    if identity_context.get("privileged_account") is True:
        factors.append("Privileged identity context")
    if identity_context.get("service_account") is True:
        factors.append("Service account context")

    rule_description = safe_lower(original_alert_summary.get("rule_description"), "")
    if "powershell" in rule_description:
        factors.append("PowerShell or command shell activity")
    if "sudo" in rule_description:
        factors.append("Linux sudo or privilege activity")
    if "wazuh" in safe_lower(asset_context.get("logical_asset_name"), "") or safe_lower(asset_context.get("asset_role")) in {
        "siem_server",
        "detection_data_store",
        "security_console",
        "config_monitoring_node",
    }:
        factors.append("Security monitoring infrastructure")

    policy_ids = policy_context.get("relevant_policy_ids") or []
    if policy_ids:
        factors.append(f"Relevant governance policies: {', '.join(policy_ids)}")
    return factors or ["Business risk derived from technical severity and available context"]


def risk_dampening(
    original_alert_summary: dict[str, Any],
    asset_context: dict[str, Any],
    identity_context: dict[str, Any],
    *,
    mapping_rule_type: str | None = None,
    mapping_confidence: float | None = None,
) -> tuple[float, str | None, float | None]:
    """Return a score reduction, explanatory factor, and optional score cap."""
    description = safe_lower(original_alert_summary.get("rule_description"), "")
    category = safe_lower(original_alert_summary.get("event_category"), "")
    asset_role = safe_lower(asset_context.get("asset_role"), "")
    has_identity = bool(identity_context.get("identity_id"))
    process = original_alert_summary.get("process") or {}
    network = original_alert_summary.get("network") or {}
    mitre_technique_ids = original_alert_summary.get("mitre_technique_ids") or []
    has_process_evidence = any(process.get(key) for key in ("name", "command_line", "pid", "parent_name"))
    has_network_evidence = any(network.get(key) for key in ("source_ip", "destination_ip", "destination_port"))
    has_strong_runtime_evidence = bool(
        has_identity
        or has_process_evidence
        or has_network_evidence
        or mitre_technique_ids
        or category in {"authentication", "privilege_activity", "process_execution", "network_activity"}
    )

    if mapping_rule_type in {"agent_fallback", "generic_unknown_fallback"} and not has_strong_runtime_evidence:
        confidence = float(mapping_confidence) if mapping_confidence is not None else 0.0
        if category in {"unknown", "background", "monitoring_internal", ""}:
            return 10.0, "Fallback mapping risk cap applied because no strong MITRE, user, process, or network evidence was present", 74.9
        if confidence < 0.75:
            return 7.0, "Fallback mapping dampening applied because context came from host-level default mapping", 79.0

    if ("dpkg" in description or "package" in description) and not has_identity:
        return 18.0, "Package-management noise dampening applied because no suspicious identity/process context was present", 68.0

    if "security configuration assessment" in description or "sca" in description:
        if asset_context.get("crown_jewel") is True or asset_role in {"siem_server", "detection_data_store", "config_monitoring_node"}:
            return 8.0, "SCA/compliance dampening applied but capped higher for critical security infrastructure", 78.0
        return 20.0, "SCA/compliance-only dampening applied", 62.0

    if "syscheck" in description or "integrity" in description:
        if asset_role in {"siem_server", "detection_data_store", "security_console", "config_monitoring_node"}:
            return 0.0, "Integrity activity on security infrastructure was not dampened", None
        return 10.0, "Generic integrity/syscheck dampening applied", 70.0

    if category == "monitoring_internal" and asset_role not in {"siem_server", "detection_data_store", "security_console", "config_monitoring_node"}:
        return 10.0, "Internal monitoring noise dampening applied", 65.0

    return 0.0, None, None


def calculate_business_risk(
    *,
    original_alert_summary: dict[str, Any],
    asset_context: dict[str, Any],
    identity_context: dict[str, Any],
    policy_context: dict[str, Any],
    context_confidence: float,
    mapping_rule_type: str | None = None,
    mapping_confidence: float | None = None,
) -> BusinessRiskResult:
    severity_score = SEVERITY_SCORES.get(safe_lower(original_alert_summary.get("severity_normalized")), 35)
    asset_score = CRITICALITY_SCORES.get(safe_lower(asset_context.get("asset_criticality")), 40)
    identity_score = identity_context.get("identity_risk_score")
    if identity_score is None:
        identity_score = 50
    data_score = CLASSIFICATION_SCORES.get(safe_lower(asset_context.get("data_classification")), 45)
    exposure_score = EXPOSURE_SCORES.get(safe_lower(asset_context.get("exposure_level")), 45)
    service_score = SERVICE_IMPORTANCE_SCORES.get(safe_lower(asset_context.get("service_criticality")), asset_score)
    confidence_adjustment = max(0.0, min(context_confidence, 1.0)) * 100

    score = (
        0.25 * severity_score
        + 0.20 * asset_score
        + 0.15 * float(identity_score)
        + 0.15 * data_score
        + 0.10 * exposure_score
        + 0.10 * service_score
        + 0.05 * confidence_adjustment
    )
    if asset_context.get("crown_jewel") is True:
        score += 4
    if identity_context.get("privileged_account") is True:
        score += 3
    if safe_lower(asset_context.get("asset_role")) in {"siem_server", "detection_data_store"}:
        score += 4
    dampening, dampening_factor, score_cap = risk_dampening(
        original_alert_summary,
        asset_context,
        identity_context,
        mapping_rule_type=mapping_rule_type,
        mapping_confidence=mapping_confidence,
    )
    score -= dampening
    if score_cap is not None:
        score = min(score, score_cap)
    score = max(0.0, min(score, 100.0))

    factors = risk_factors_for(original_alert_summary, asset_context, identity_context, policy_context)
    if dampening_factor:
        factors.append(dampening_factor)
    label = label_for_score(score)
    explanation = (
        f"Business risk is {label} because the alert has {original_alert_summary.get('severity_normalized', 'unknown')} "
        f"technical severity and maps to {asset_context.get('logical_asset_name') or 'unknown asset context'} "
        f"supporting {asset_context.get('business_service') or 'unknown service context'}."
    )
    if identity_context.get("logical_username"):
        explanation += f" Identity context maps to {identity_context['logical_username']}."
    if context_confidence < 0.7:
        explanation += " Confidence is reduced because one or more context dimensions are missing."

    return BusinessRiskResult(
        business_risk_score=round(score, 2),
        business_risk_label=label,
        risk_factors=factors,
        risk_explanation=explanation,
        risk_confidence=round(max(0.0, min(context_confidence, 1.0)), 4),
        score_components={
            "severity_score": float(severity_score),
            "asset_criticality_score": float(asset_score),
            "identity_risk_score": float(identity_score),
            "data_classification_score": float(data_score),
            "exposure_score": float(exposure_score),
            "service_importance_score": float(service_score),
            "context_confidence_adjustment": round(confidence_adjustment, 2),
            "noise_dampening": round(dampening, 2),
            "score_cap": float(score_cap) if score_cap is not None else 100.0,
            "mapping_confidence": float(mapping_confidence) if mapping_confidence is not None else 0.0,
        },
    )
