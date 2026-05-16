from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import hashlib
import re
from typing import Any

from safeagentsoc.cases.schemas import DuplicateGroup


def stable_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def normalize_text(value: Any) -> str:
    text = str(value or "").lower()
    text = re.sub(r"\b\d+\b", "<num>", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def duplicate_fingerprint(alert: dict[str, Any], behavior_family: str | None = None) -> str:
    summary = alert.get("original_alert_summary") or {}
    asset = alert.get("asset_context") or {}
    identity = alert.get("identity_context") or {}
    process = summary.get("process") or {}
    file_info = summary.get("file") or {}
    parts = [
        summary.get("rule_id"),
        normalize_text(summary.get("rule_description")),
        asset.get("asset_id") or summary.get("agent_name"),
        identity.get("identity_id") or "",
        normalize_text(process.get("name")),
        normalize_text(process.get("command_line")),
        normalize_text(file_info.get("path")),
        ",".join(sorted(summary.get("mitre_technique_ids") or [])),
        summary.get("event_category"),
        summary.get("event_action"),
        behavior_family or "",
    ]
    return "|".join(str(part or "") for part in parts)


def evidence_completeness(alert: dict[str, Any]) -> int:
    summary = alert.get("original_alert_summary") or {}
    process = summary.get("process") or {}
    file_info = summary.get("file") or {}
    network = summary.get("network") or {}
    user = summary.get("user") or {}
    return sum(
        1
        for value in [
            process.get("name"),
            process.get("command_line"),
            file_info.get("path"),
            network.get("src_ip"),
            network.get("dst_ip"),
            user.get("username"),
            summary.get("mitre_technique_ids"),
        ]
        if value
    )


def select_representative(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    return sorted(
        alerts,
        key=lambda alert: (
            -float((alert.get("analyst_priority") or {}).get("analyst_priority_score") or 0),
            -float((alert.get("business_risk") or {}).get("business_risk_score") or 0),
            -evidence_completeness(alert),
            str(alert.get("event_time_utc") or ""),
            str(alert.get("alert_uid") or ""),
        ),
    )[0]


def detect_duplicate_groups(alerts: list[dict[str, Any]], behavior_families: dict[str, str]) -> tuple[list[DuplicateGroup], dict[str, DuplicateGroup]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        grouped[duplicate_fingerprint(alert, behavior_families.get(str(alert.get("alert_uid"))))].append(alert)

    groups: list[DuplicateGroup] = []
    by_alert_uid: dict[str, DuplicateGroup] = {}
    for fingerprint, rows in grouped.items():
        if len(rows) < 2:
            continue
        rows.sort(key=lambda alert: (str(alert.get("event_time_utc") or ""), str(alert.get("alert_uid") or "")))
        times = [parse_time(row.get("event_time_utc")) for row in rows]
        span_minutes = 999999.0
        if times[0] and times[-1]:
            span_minutes = abs((times[-1] - times[0]).total_seconds()) / 60
        duplicate_type = "family_duplicate"
        if span_minutes <= 5:
            duplicate_type = "exact_duplicate"
        elif span_minutes <= 15:
            duplicate_type = "near_duplicate"
        representative = select_representative(rows)
        group = DuplicateGroup(
            duplicate_group_id=f"dup_rt_{len(groups) + 1:06d}",
            duplicate_type=duplicate_type,
            duplicate_fingerprint=stable_hash(fingerprint, 32),
            representative_alert_uid=str(representative["alert_uid"]),
            duplicate_alert_uids=[str(row["alert_uid"]) for row in rows],
            duplicate_count=len(rows),
        )
        groups.append(group)
        for row in rows:
            by_alert_uid[str(row["alert_uid"])] = group
    return groups, by_alert_uid

