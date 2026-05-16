from __future__ import annotations

from datetime import UTC, datetime
from statistics import mean
from typing import Any


def evidence_strength(alert: dict[str, Any]) -> float:
    summary = alert.get("original_alert_summary") or {}
    process = summary.get("process") or {}
    file_info = summary.get("file") or {}
    network = summary.get("network") or {}
    user = summary.get("user") or {}
    points = 0
    points += 20 if summary.get("mitre_technique_ids") else 0
    points += 20 if process.get("command_line") or process.get("name") else 0
    points += 15 if file_info.get("path") else 0
    points += 15 if network.get("src_ip") or network.get("dst_ip") else 0
    points += 15 if user.get("username") else 0
    points += 15 if (alert.get("identity_context") or {}).get("privileged_account") is True else 0
    return float(min(points, 100))


def label_for_score(score: float) -> str:
    if score >= 90:
        return "P1 critical"
    if score >= 75:
        return "P2 high"
    if score >= 50:
        return "P3 medium"
    return "P4 low"


def score_case(case_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    alerts = [row["alert"] for row in rows]
    trigger_rows = [row for row in rows if row["runtime_alert_role"] == "trigger"]
    trigger_alert = (trigger_rows[0] if trigger_rows else rows[0])["alert"]
    priorities = [float((alert.get("analyst_priority") or {}).get("analyst_priority_score") or 0) for alert in alerts]
    risks = [float((alert.get("business_risk") or {}).get("business_risk_score") or 0) for alert in alerts]
    confidences = [float((alert.get("context_metadata") or {}).get("context_confidence") or 0) for alert in alerts]
    trigger_strength = evidence_strength(trigger_alert)
    mitre_values = sorted({tech for alert in alerts for tech in ((alert.get("original_alert_summary") or {}).get("mitre_technique_ids") or [])})
    tactic_values = sorted({tactic for alert in alerts for tactic in ((alert.get("original_alert_summary") or {}).get("mitre_tactics") or [])})
    policy_values = sorted({policy for alert in alerts for policy in ((alert.get("policy_context") or {}).get("relevant_policy_ids") or [])})
    visible_count = sum(1 for row in rows if row["visibility_level"].startswith("visible"))
    suppressed_count = len(rows) - visible_count
    noise_ratio = suppressed_count / len(rows) if rows else 0.0
    asset_identity_score = 100.0 if (trigger_alert.get("asset_context") or {}).get("asset_id") and (trigger_alert.get("identity_context") or {}).get("identity_id") else 70.0
    priority_score = (
        0.30 * max(priorities or [0])
        + 0.20 * max(risks or [0])
        + 0.15 * trigger_strength
        + 0.10 * (mean(confidences or [0]) * 100)
        + 0.10 * min(len(mitre_values) * 20, 100)
        + 0.10 * asset_identity_score
        + 0.05 * min(len(policy_values) * 20, 100)
        - 0.10 * (noise_ratio * 100)
    )
    priority_score = round(max(0.0, min(priority_score, 100.0)), 2)
    start_time = min(str(alert.get("event_time_utc") or "") for alert in alerts)
    end_time = max(str(alert.get("event_time_utc") or "") for alert in alerts)
    asset = trigger_alert.get("asset_context") or {}
    identity = trigger_alert.get("identity_context") or {}
    summary = trigger_alert.get("original_alert_summary") or {}
    rule_ids = sorted({str((alert.get("original_alert_summary") or {}).get("rule_id")) for alert in alerts if (alert.get("original_alert_summary") or {}).get("rule_id")})
    evidence_ids = sorted({str(alert.get("evidence_id")) for alert in alerts if alert.get("evidence_id")})
    roles = {role: sum(1 for row in rows if row["runtime_alert_role"] == role) for role in ["trigger", "supporting", "duplicate", "noise", "context"]}
    return {
        "case_id": case_id,
        "case_schema_version": "phase5_case_v1",
        "case_status": "generated",
        "case_created_at_utc": datetime.now(UTC).isoformat(),
        "case_start_time_utc": start_time,
        "case_end_time_utc": end_time,
        "case_duration_minutes": 0.0,
        "primary_asset_id": asset.get("asset_id"),
        "primary_identity_id": identity.get("identity_id"),
        "business_unit": asset.get("business_unit"),
        "business_service": asset.get("business_service"),
        "case_priority_score": priority_score,
        "case_priority_label": label_for_score(priority_score),
        "case_business_impact_score": round(max(risks or [0]), 2),
        "case_confidence": round(mean(confidences or [0]), 4),
        "alert_count_total": len(rows),
        "visible_alert_count": visible_count,
        "suppressed_alert_count": suppressed_count,
        "trigger_alert_count": roles["trigger"],
        "supporting_alert_count": roles["supporting"],
        "duplicate_alert_count": roles["duplicate"],
        "noise_alert_count": roles["noise"],
        "context_alert_count": roles["context"],
        "mitre_technique_ids": mitre_values,
        "mitre_tactics": tactic_values,
        "rule_ids": rule_ids,
        "evidence_ids": evidence_ids,
        "case_title": build_case_title(asset, summary),
        "case_summary": build_case_summary(asset, rows, mitre_values),
        "case_rationale": build_case_rationale(rows),
        "max_analyst_priority_score": round(max(priorities or [0]), 2),
        "max_business_risk_score": round(max(risks or [0]), 2),
        "primary_behavior_family": rows[0].get("behavior_family"),
        "case_alerts": [],
    }


def build_case_title(asset: dict[str, Any], summary: dict[str, Any]) -> str:
    asset_name = asset.get("logical_asset_name") or summary.get("agent_name") or "observed asset"
    description = str(summary.get("rule_description") or summary.get("event_category") or "security activity")
    return f"{description[:70]} on {asset_name}"


def build_case_summary(asset: dict[str, Any], rows: list[dict[str, Any]], mitre_values: list[str]) -> str:
    asset_name = asset.get("logical_asset_name") or "observed asset"
    visible = sum(1 for row in rows if row["visibility_level"].startswith("visible"))
    collapsed = len(rows) - visible
    mitre_text = ", ".join(mitre_values[:5]) if mitre_values else "no MITRE technique"
    return f"{len(rows)} related alerts on {asset_name}; {visible} visible by default and {collapsed} collapsed with recoverable evidence. MITRE context: {mitre_text}."


def build_case_rationale(rows: list[dict[str, Any]]) -> list[str]:
    reasons = []
    trigger = next((row for row in rows if row["runtime_alert_role"] == "trigger"), rows[0])
    reasons.append(trigger["role_reason"])
    if any(row["runtime_alert_role"] == "duplicate" for row in rows):
        reasons.append("Duplicate telemetry was collapsed behind representative evidence.")
    if any(row["preserved_unique_evidence_types"] for row in rows):
        reasons.append("Unique evidence was kept visible by suppression safety checks.")
    return reasons

