from __future__ import annotations

from datetime import datetime
from typing import Any

from safeagentsoc.cases.mitre_relation_mapper import mitre_relation_score
from safeagentsoc.cases.schemas import CaseSeed


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def minutes_between(left: str | None, right: str | None) -> float:
    left_time = parse_time(left)
    right_time = parse_time(right)
    if left_time is None or right_time is None:
        return 999999.0
    return abs((left_time - right_time).total_seconds()) / 60


def value_match(left: Any, right: Any) -> bool:
    return left not in (None, "", [], {}) and right not in (None, "", [], {}) and left == right


def extract_user(alert: dict[str, Any]) -> str | None:
    summary = alert.get("original_alert_summary") or {}
    user = summary.get("user") or {}
    identity = alert.get("identity_context") or {}
    return identity.get("identity_id") or user.get("username")


def extract_process_or_file(alert: dict[str, Any]) -> str | None:
    summary = alert.get("original_alert_summary") or {}
    process = summary.get("process") or {}
    file_info = summary.get("file") or {}
    return process.get("command_line") or process.get("name") or file_info.get("path")


def calculate_affinity(
    seed: CaseSeed,
    seed_alert: dict[str, Any],
    candidate: dict[str, Any],
    *,
    seed_behavior_family: str,
    candidate_behavior_family: str,
    duplicate_group_match: bool,
) -> tuple[float, list[str]]:
    reasons: list[str] = []
    seed_summary = seed_alert.get("original_alert_summary") or {}
    candidate_summary = candidate.get("original_alert_summary") or {}
    seed_asset = seed_alert.get("asset_context") or {}
    candidate_asset = candidate.get("asset_context") or {}
    seed_network = seed_alert.get("network_context") or {}
    candidate_network = candidate.get("network_context") or {}
    seed_policy = seed_alert.get("policy_context") or {}
    candidate_policy = candidate.get("policy_context") or {}

    delta = minutes_between(seed.seed_time, candidate.get("event_time_utc"))
    time_score = max(0.0, 1.0 - (delta / 60.0))
    score = 0.20 * time_score
    if time_score > 0:
        reasons.append(f"time proximity {delta:.1f} minutes")

    if value_match(seed_asset.get("asset_id"), candidate_asset.get("asset_id")):
        score += 0.15
        reasons.append("same logical asset")
    elif value_match(seed_summary.get("agent_name"), candidate_summary.get("agent_name")):
        score += 0.10
        reasons.append("same observed host")

    if value_match(extract_user(seed_alert), extract_user(candidate)):
        score += 0.15
        reasons.append("same identity/user")

    if value_match(seed_asset.get("business_service"), candidate_asset.get("business_service")):
        score += 0.10
        reasons.append("same business service")

    if seed_behavior_family == candidate_behavior_family:
        score += 0.10
        reasons.append(f"same behavior family {candidate_behavior_family}")
    elif value_match(seed_summary.get("rule_id"), candidate_summary.get("rule_id")):
        score += 0.07
        reasons.append("same rule family")

    mitre_score, mitre_reasons = mitre_relation_score(
        list(seed_summary.get("mitre_technique_ids") or []),
        list(candidate_summary.get("mitre_technique_ids") or []),
        list(seed_summary.get("mitre_tactics") or []),
        list(candidate_summary.get("mitre_tactics") or []),
    )
    score += 0.10 * mitre_score
    reasons.extend(mitre_reasons)

    if value_match(extract_process_or_file(seed_alert), extract_process_or_file(candidate)):
        score += 0.10
        reasons.append("same process/file evidence")

    if value_match(seed_network.get("network_zone_id"), candidate_network.get("network_zone_id")):
        score += 0.05
        reasons.append("same network zone")

    seed_policies = set(seed_policy.get("relevant_policy_ids") or [])
    candidate_policies = set(candidate_policy.get("relevant_policy_ids") or [])
    if seed_policies and seed_policies & candidate_policies:
        score += 0.05
        reasons.append("shared policy relevance")

    if duplicate_group_match:
        score += 0.10
        reasons.append("same duplicate group")

    analyst_priority = candidate.get("analyst_priority") or {}
    if analyst_priority.get("analyst_priority_label") in {"high", "critical"}:
        score += 0.10
        reasons.append("urgent analyst priority")

    business_risk = candidate.get("business_risk") or {}
    if business_risk.get("business_risk_label") in {"high", "critical"}:
        score += 0.05
        reasons.append("high business risk")

    return round(min(score, 1.0), 4), reasons


def build_candidate_links(
    alerts: list[dict[str, Any]],
    seeds: list[CaseSeed],
    behavior_families: dict[str, str],
    duplicate_group_by_alert: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    alerts_by_uid = {str(alert["alert_uid"]): alert for alert in alerts}
    linked_alerts: set[str] = set()
    case_candidates: dict[str, list[dict[str, Any]]] = {}

    for index, seed in enumerate(seeds):
        seed_alert = alerts_by_uid[seed.seed_alert_uid]
        case_id = f"case_rt_{index + 1:06d}"
        seed_duplicate_group = duplicate_group_by_alert.get(seed.seed_alert_uid)
        candidates: list[dict[str, Any]] = []

        for candidate in alerts:
            candidate_uid = str(candidate["alert_uid"])
            if candidate_uid in linked_alerts and candidate_uid != seed.seed_alert_uid:
                continue
            delta = minutes_between(seed.seed_time, candidate.get("event_time_utc"))
            candidate_priority = (candidate.get("analyst_priority") or {}).get("analyst_priority_label")
            if candidate_priority in {"high", "critical"}:
                window = 60.0
            elif candidate_priority == "medium":
                window = 30.0
            else:
                window = 10.0
            if delta > window and candidate_uid != seed.seed_alert_uid:
                continue
            score, reasons = calculate_affinity(
                seed,
                seed_alert,
                candidate,
                seed_behavior_family=behavior_families.get(seed.seed_alert_uid, "unknown_low_signal"),
                candidate_behavior_family=behavior_families.get(candidate_uid, "unknown_low_signal"),
                duplicate_group_match=bool(
                    seed_duplicate_group
                    and duplicate_group_by_alert.get(candidate_uid)
                    and seed_duplicate_group.duplicate_group_id == duplicate_group_by_alert[candidate_uid].duplicate_group_id
                ),
            )
            if candidate_uid == seed.seed_alert_uid:
                score = 1.0
                reasons = ["case seed alert"]
            if score >= 0.35 or candidate_uid == seed.seed_alert_uid:
                candidates.append(
                    {
                        "case_id": case_id,
                        "alert": candidate,
                        "case_affinity_score": score,
                        "case_affinity_reasons": reasons,
                        "joined": score >= 0.55 or candidate_uid == seed.seed_alert_uid,
                    }
                )
        joined = [candidate for candidate in candidates if candidate["joined"]]
        if not joined:
            joined = [candidate for candidate in candidates if candidate["alert"]["alert_uid"] == seed.seed_alert_uid]
        for candidate in joined:
            linked_alerts.add(str(candidate["alert"]["alert_uid"]))
        case_candidates[case_id] = joined

    # Account for every remaining alert in deterministic low-priority background cases.
    remaining = [alert for alert in alerts if str(alert["alert_uid"]) not in linked_alerts]
    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for alert in remaining:
        asset = alert.get("asset_context") or {}
        summary = alert.get("original_alert_summary") or {}
        time_value = str(alert.get("event_time_utc") or "")
        day = time_value[:10] if time_value else "unknown-date"
        key = (day, str(asset.get("asset_id") or summary.get("agent_name") or "unknown"), behavior_families.get(str(alert["alert_uid"]), "unknown_low_signal"))
        buckets.setdefault(key, []).append(alert)
    for bucket_alerts in buckets.values():
        case_id = f"case_rt_{len(case_candidates) + 1:06d}"
        case_candidates[case_id] = [
            {
                "case_id": case_id,
                "alert": alert,
                "case_affinity_score": 0.40,
                "case_affinity_reasons": ["background accounting case"],
                "joined": True,
            }
            for alert in bucket_alerts
        ]
    return case_candidates

