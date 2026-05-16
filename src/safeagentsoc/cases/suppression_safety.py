from __future__ import annotations

from collections import Counter
from typing import Any


def _evidence_values(alert: dict[str, Any]) -> dict[str, str]:
    summary = alert.get("original_alert_summary") or {}
    process = summary.get("process") or {}
    file_info = summary.get("file") or {}
    network = summary.get("network") or {}
    values: dict[str, str] = {}
    if summary.get("mitre_technique_ids"):
        values["mitre"] = ",".join(sorted(summary.get("mitre_technique_ids") or []))
    if process.get("command_line"):
        values["process_command_line"] = str(process["command_line"])
    if file_info.get("path"):
        values["file_path"] = str(file_info["path"])
    if network.get("src_ip") or network.get("dst_ip"):
        values["network"] = f"{network.get('src_ip') or ''}->{network.get('dst_ip') or ''}"
    return values


def apply_suppression_safety(role_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence_counters: dict[str, Counter[str]] = {
        "mitre": Counter(),
        "process_command_line": Counter(),
        "file_path": Counter(),
        "network": Counter(),
    }
    for row in role_rows:
        for evidence_type, value in _evidence_values(row["alert"]).items():
            evidence_counters[evidence_type][value] += 1

    highest_priority_uid = max(
        role_rows,
        key=lambda row: float((row["alert"].get("analyst_priority") or {}).get("analyst_priority_score") or 0),
    )["alert"]["alert_uid"]
    highest_risk_uid = max(
        role_rows,
        key=lambda row: float((row["alert"].get("business_risk") or {}).get("business_risk_score") or 0),
    )["alert"]["alert_uid"]

    safe_rows: list[dict[str, Any]] = []
    for row in role_rows:
        alert = row["alert"]
        uid = str(alert["alert_uid"])
        role = row["runtime_alert_role"]
        asset = alert.get("asset_context") or {}
        identity = alert.get("identity_context") or {}
        preserved_unique: list[str] = []
        for evidence_type, value in _evidence_values(alert).items():
            if evidence_counters[evidence_type][value] == 1:
                preserved_unique.append(evidence_type)

        must_remain_visible_reason = None
        if role == "trigger":
            must_remain_visible_reason = "case trigger alert"
        elif uid == str(highest_priority_uid):
            must_remain_visible_reason = "highest analyst-priority alert in case"
        elif uid == str(highest_risk_uid):
            must_remain_visible_reason = "highest business-risk alert in case"
        elif preserved_unique:
            must_remain_visible_reason = f"only alert with unique evidence: {', '.join(preserved_unique)}"
        elif identity.get("privileged_account") is True:
            must_remain_visible_reason = "alert involves privileged identity"
        elif asset.get("crown_jewel") is True:
            must_remain_visible_reason = "alert touches crown-jewel asset"
        elif row.get("representative_alert_uid") == uid:
            must_remain_visible_reason = "representative alert for duplicate group"

        if must_remain_visible_reason:
            visibility = "visible_primary" if role == "trigger" else "visible_supporting"
            suppression_safe = False
            suppression_reason = None
        elif role == "duplicate":
            visibility = "collapsed_duplicate"
            suppression_safe = True
            suppression_reason = "duplicate alert collapsed behind visible representative"
        elif role in {"noise", "context"}:
            visibility = "collapsed_noise"
            suppression_safe = True
            suppression_reason = f"{role} alert collapsed from default analyst view"
        else:
            visibility = "visible_supporting"
            suppression_safe = False
            suppression_reason = None

        safe_rows.append(
            {
                **row,
                "visibility_level": visibility,
                "suppression_safe": suppression_safe,
                "suppression_reason": suppression_reason,
                "must_remain_visible_reason": must_remain_visible_reason,
                "preserved_unique_evidence_types": preserved_unique,
            }
        )
    return safe_rows

