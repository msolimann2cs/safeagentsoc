from __future__ import annotations

from typing import Any

from safeagentsoc.cases.behavior_family_mapper import map_behavior_family
from safeagentsoc.cases.schemas import CaseSeed


def _has_runtime_evidence(alert: dict[str, Any]) -> bool:
    summary = alert.get("original_alert_summary") or {}
    process = summary.get("process") or {}
    user = summary.get("user") or {}
    network = summary.get("network") or {}
    file_info = summary.get("file") or {}
    identity = alert.get("identity_context") or {}
    return any(
        [
            summary.get("mitre_technique_ids"),
            user.get("username"),
            process.get("name"),
            process.get("command_line"),
            network.get("src_ip"),
            network.get("dst_ip"),
            file_info.get("path"),
            identity.get("privileged_account") is True,
        ]
    )


def seed_reason(alert: dict[str, Any], behavior_family: str) -> str:
    analyst_priority = alert.get("analyst_priority") or {}
    asset = alert.get("asset_context") or {}
    business_risk = alert.get("business_risk") or {}
    if analyst_priority.get("urgent_priority_gate_passed"):
        return f"Urgent analyst-priority alert with {behavior_family} behavior"
    if asset.get("business_service") == "Security Monitoring":
        return "Security Monitoring asset with high business risk and security-relevant behavior"
    return f"Runtime seed selected from {behavior_family} behavior"


def generate_case_seeds(alerts: list[dict[str, Any]]) -> list[CaseSeed]:
    seeds: list[CaseSeed] = []
    security_seed_families = {
        "linux_authentication",
        "linux_integrity_monitoring",
        "linux_privilege_activity",
        "wazuh_security_infrastructure",
        "windows_persistence_or_privilege",
        "windows_suspicious_execution",
    }

    for alert in alerts:
        summary = alert.get("original_alert_summary") or {}
        metadata = alert.get("context_metadata") or {}
        analyst_priority = alert.get("analyst_priority") or {}
        business_risk = alert.get("business_risk") or {}
        asset = alert.get("asset_context") or {}
        identity = alert.get("identity_context") or {}
        behavior_family = map_behavior_family(alert)
        priority_label = analyst_priority.get("analyst_priority_label")
        gate_passed = bool(analyst_priority.get("urgent_priority_gate_passed"))
        weak_fallback = metadata.get("mapping_rule_type") == "agent_fallback" and not _has_runtime_evidence(alert)
        security_monitoring_seed = (
            asset.get("business_service") == "Security Monitoring"
            and business_risk.get("business_risk_label") in {"high", "critical"}
            and priority_label in {"medium", "high", "critical"}
            and behavior_family in security_seed_families
            and _has_runtime_evidence(alert)
        )
        if priority_label in {"high", "critical"} and gate_passed and not weak_fallback:
            selected = True
        elif security_monitoring_seed and not weak_fallback:
            selected = True
        else:
            selected = False
        if not selected:
            continue
        seeds.append(
            CaseSeed(
                case_seed_id=f"seed_rt_{len(seeds) + 1:06d}",
                seed_alert_uid=str(alert["alert_uid"]),
                seed_evidence_id=str(alert["evidence_id"]),
                seed_reason=seed_reason(alert, behavior_family),
                seed_priority_score=float(analyst_priority.get("analyst_priority_score") or 0.0),
                seed_business_risk_score=float(business_risk.get("business_risk_score") or 0.0),
                seed_asset_id=asset.get("asset_id"),
                seed_identity_id=identity.get("identity_id"),
                seed_rule_id=summary.get("rule_id"),
                seed_behavior_family=behavior_family,
                seed_mitre_techniques=list(summary.get("mitre_technique_ids") or []),
                seed_time=str(alert.get("event_time_utc") or ""),
            )
        )

    seeds.sort(
        key=lambda seed: (
            -seed.seed_priority_score,
            -seed.seed_business_risk_score,
            seed.seed_time,
            seed.seed_alert_uid,
        )
    )
    return [
        CaseSeed(
            case_seed_id=f"seed_rt_{index + 1:06d}",
            seed_alert_uid=seed.seed_alert_uid,
            seed_evidence_id=seed.seed_evidence_id,
            seed_reason=seed.seed_reason,
            seed_priority_score=seed.seed_priority_score,
            seed_business_risk_score=seed.seed_business_risk_score,
            seed_asset_id=seed.seed_asset_id,
            seed_identity_id=seed.seed_identity_id,
            seed_rule_id=seed.seed_rule_id,
            seed_behavior_family=seed.seed_behavior_family,
            seed_mitre_techniques=seed.seed_mitre_techniques,
            seed_time=seed.seed_time,
        )
        for index, seed in enumerate(seeds)
    ]

