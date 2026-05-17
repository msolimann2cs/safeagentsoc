from __future__ import annotations

from statistics import mean
from typing import Any


ROLE_STRENGTH = {
    "trigger": 1.0,
    "supporting": 0.75,
    "duplicate_visible": 0.55,
    "duplicate": 0.30,
    "context": 0.20,
    "noise": 0.20,
}

MAPPING_STRENGTH = {
    "direct_mitre": 1.0,
    "rule_inferred": 0.75,
    "behavior_inferred": 0.55,
    "unknown": 0.20,
}


def confidence_label(score: float) -> str:
    if score >= 0.80:
        return "high"
    if score >= 0.55:
        return "medium"
    if score >= 0.30:
        return "low"
    return "weak"


def score_technique_confidence(mapping: dict[str, Any]) -> dict[str, Any]:
    source_records = mapping.get("source_records") or []
    role_strength = max((role_strength_for_record(record) for record in source_records), default=0.20)
    mapping_strength = MAPPING_STRENGTH.get(str(mapping.get("mapping_source") or "unknown"), 0.20)
    evidence_richness = max((evidence_richness_for_record(record) for record in source_records), default=0.05)
    priority_strength = max(
        (float((record.get("link") or {}).get("analyst_priority_score") or 0) / 100 for record in source_records),
        default=0.0,
    )
    context_strength = mean(
        [
            float(((record.get("enriched") or {}).get("context_metadata") or {}).get("context_confidence") or 0)
            for record in source_records
        ]
        or [0.0]
    )
    score = (
        0.30 * role_strength
        + 0.25 * mapping_strength
        + 0.20 * evidence_richness
        + 0.15 * priority_strength
        + 0.10 * context_strength
    )
    score = round(max(0.0, min(score, 1.0)), 4)
    return {
        "confidence_score": score,
        "confidence_label": confidence_label(score),
        "confidence_components": {
            "role_strength": round(role_strength, 4),
            "mapping_strength": round(mapping_strength, 4),
            "evidence_richness": round(evidence_richness, 4),
            "analyst_priority_strength": round(priority_strength, 4),
            "context_confidence": round(context_strength, 4),
        },
        "confidence_reasons": confidence_reasons(mapping, role_strength, evidence_richness),
    }


def role_strength_for_record(record: dict[str, Any]) -> float:
    link = record.get("link") or {}
    role = str(link.get("runtime_alert_role") or "")
    visibility = str(link.get("visibility_level") or "")
    if role == "duplicate" and visibility.startswith("visible"):
        return ROLE_STRENGTH["duplicate_visible"]
    return ROLE_STRENGTH.get(role, 0.20)


def evidence_richness_for_record(record: dict[str, Any]) -> float:
    enriched = record.get("enriched") or {}
    summary = enriched.get("original_alert_summary") or {}
    process = summary.get("process") or {}
    file_info = summary.get("file") or {}
    network = summary.get("network") or {}
    user = summary.get("user") or {}
    identity = enriched.get("identity_context") or {}
    points = 0.05
    points += 0.35 if process.get("command_line") else 0
    points += 0.20 if process.get("name") else 0
    points += 0.15 if file_info.get("path") else 0
    points += 0.15 if network.get("src_ip") or network.get("dst_ip") else 0
    points += 0.15 if user.get("username") or identity.get("identity_id") else 0
    points += 0.10 if identity.get("privileged_account") is True else 0
    return round(min(points, 1.0), 4)


def confidence_reasons(mapping: dict[str, Any], role_strength: float, evidence_richness: float) -> list[str]:
    reasons = [f"mapping_source={mapping.get('mapping_source')}"]
    if role_strength >= 1.0:
        reasons.append("supported by trigger evidence")
    elif role_strength >= 0.75:
        reasons.append("supported by visible supporting evidence")
    elif mapping.get("duplicate_count", 0):
        reasons.append("duplicate volume was treated as repetition, not stronger evidence")
    if evidence_richness >= 0.70:
        reasons.append("process/user/file/network evidence is present")
    elif evidence_richness <= 0.10:
        reasons.append("claim relies mostly on rule text")
    return reasons

