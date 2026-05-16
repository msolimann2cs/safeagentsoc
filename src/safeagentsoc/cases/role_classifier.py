from __future__ import annotations

from typing import Any

from safeagentsoc.cases.behavior_family_mapper import is_noisy_behavior_family
from safeagentsoc.cases.duplicate_detector import evidence_completeness


def role_features(alert: dict[str, Any], behavior_family: str) -> list[str]:
    summary = alert.get("original_alert_summary") or {}
    features: list[str] = [f"behavior_family={behavior_family}"]
    if summary.get("mitre_technique_ids"):
        features.append("mitre_present")
    if evidence_completeness(alert) > 0:
        features.append("runtime_entity_evidence_present")
    if (alert.get("identity_context") or {}).get("privileged_account") is True:
        features.append("privileged_identity")
    if (alert.get("analyst_priority") or {}).get("urgent_priority_gate_passed"):
        features.append("urgent_priority_gate")
    return features


def select_trigger(candidates: list[dict[str, Any]], behavior_families: dict[str, str]) -> str:
    eligible = []
    for candidate in candidates:
        alert = candidate["alert"]
        uid = str(alert["alert_uid"])
        analyst_priority = alert.get("analyst_priority") or {}
        metadata = alert.get("context_metadata") or {}
        family = behavior_families.get(uid, "unknown_low_signal")
        evidence_rich = evidence_completeness(alert) > 0 or bool((alert.get("original_alert_summary") or {}).get("mitre_technique_ids"))
        weak_noise = is_noisy_behavior_family(family) and not evidence_rich
        if analyst_priority.get("urgent_priority_gate_passed") and not weak_noise:
            eligible.append(candidate)
        elif evidence_rich and metadata.get("mapping_rule_type") != "agent_fallback":
            eligible.append(candidate)
    pool = eligible or candidates
    selected = sorted(
        pool,
        key=lambda candidate: (
            -float((candidate["alert"].get("analyst_priority") or {}).get("analyst_priority_score") or 0),
            -float((candidate["alert"].get("business_risk") or {}).get("business_risk_score") or 0),
            -evidence_completeness(candidate["alert"]),
            str(candidate["alert"].get("event_time_utc") or ""),
        ),
    )[0]
    return str(selected["alert"]["alert_uid"])


def classify_case_alert_roles(
    candidates: list[dict[str, Any]],
    behavior_families: dict[str, str],
    duplicate_group_by_alert: dict[str, Any],
) -> list[dict[str, Any]]:
    trigger_uid = select_trigger(candidates, behavior_families)
    rows: list[dict[str, Any]] = []
    seen_duplicate_representatives: set[str] = set()

    for candidate in candidates:
        alert = candidate["alert"]
        uid = str(alert["alert_uid"])
        family = behavior_families.get(uid, "unknown_low_signal")
        duplicate_group = duplicate_group_by_alert.get(uid)
        features = role_features(alert, family)
        evidence_score = evidence_completeness(alert)
        analyst_priority = alert.get("analyst_priority") or {}

        if uid == trigger_uid:
            role = "trigger"
            confidence = 0.95
            reason = "Selected as the strongest runtime alert explaining why the case exists"
        elif duplicate_group and duplicate_group.representative_alert_uid != uid:
            role = "duplicate"
            confidence = 0.90
            reason = f"Repeated signal in duplicate group {duplicate_group.duplicate_group_id}"
        elif duplicate_group and duplicate_group.representative_alert_uid == uid and duplicate_group.duplicate_group_id not in seen_duplicate_representatives:
            seen_duplicate_representatives.add(duplicate_group.duplicate_group_id)
            role = "supporting"
            confidence = 0.82
            reason = "Representative alert for a duplicate group"
        elif is_noisy_behavior_family(family) and analyst_priority.get("analyst_priority_label") == "low":
            role = "noise"
            confidence = 0.80
            reason = f"Low-priority noisy telemetry family: {family}"
        elif candidate["case_affinity_score"] >= 0.55 and evidence_score > 0:
            role = "supporting"
            confidence = 0.78
            reason = "Adds runtime evidence to the case timeline"
        elif candidate["case_affinity_score"] >= 0.35:
            role = "context"
            confidence = 0.70
            reason = "Provides related background context for the case"
        else:
            role = "unrelated"
            confidence = 0.60
            reason = "Candidate was considered but did not meet case affinity thresholds"

        rows.append(
            {
                **candidate,
                "runtime_alert_role": role,
                "role_confidence": confidence,
                "role_reason": reason,
                "role_features": features,
                "duplicate_group_id": duplicate_group.duplicate_group_id if duplicate_group else None,
                "representative_alert_uid": duplicate_group.representative_alert_uid if duplicate_group else None,
            }
        )
    return rows

