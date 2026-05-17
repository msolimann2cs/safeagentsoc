from __future__ import annotations

from collections import Counter
from typing import Any


TRIGGER_PRESERVATION_DUPLICATE_VISIBLE_BUDGET = 13


def trigger_preservation_candidate(alert: dict[str, Any]) -> bool:
    summary = alert.get("original_alert_summary") or {}
    rule_id = str(summary.get("rule_id") or "")
    text = " ".join(
        str(value or "")
        for value in [
            summary.get("rule_description"),
            summary.get("event_category"),
            summary.get("event_action"),
            " ".join(summary.get("mitre_technique_ids") or []),
        ]
    ).lower()
    trigger_like_rule_ids = {
        "5402",
        "5501",
        "5503",
        "2501",
        "80730",
        "92033",
        "61104",
        "550",
        "60642",
        "92604",
        "100760",
        "100761",
        "100763",
        "100764",
        "100765",
    }
    trigger_like_terms = [
        "sudo to root",
        "login failed",
        "authentication failure",
        "powershell",
        "service startup type",
        "selinux permission",
        "processes running",
        "integrity checksum",
        "run start marker",
        "run end marker",
        "scenario marker",
        "cron marker",
    ]
    return rule_id in trigger_like_rule_ids or any(term in text for term in trigger_like_terms)


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
    privileged_identity_counter: Counter[str] = Counter()
    crown_jewel_asset_counter: Counter[str] = Counter()
    for row in role_rows:
        for evidence_type, value in _evidence_values(row["alert"]).items():
            evidence_counters[evidence_type][value] += 1
        identity = row["alert"].get("identity_context") or {}
        asset = row["alert"].get("asset_context") or {}
        if identity.get("privileged_account") is True and identity.get("identity_id"):
            privileged_identity_counter[str(identity["identity_id"])] += 1
        if asset.get("crown_jewel") is True and asset.get("asset_id"):
            crown_jewel_asset_counter[str(asset["asset_id"])] += 1

    highest_priority_uid = max(
        role_rows,
        key=lambda row: float((row["alert"].get("analyst_priority") or {}).get("analyst_priority_score") or 0),
    )["alert"]["alert_uid"]
    highest_risk_uid = max(
        role_rows,
        key=lambda row: float((row["alert"].get("business_risk") or {}).get("business_risk_score") or 0),
    )["alert"]["alert_uid"]
    trigger_candidate_duplicate_rank: dict[str, int] = {}
    trigger_candidate_duplicates: dict[str, list[dict[str, Any]]] = {}
    for row in role_rows:
        alert = row["alert"]
        summary = alert.get("original_alert_summary") or {}
        rule_id = str(summary.get("rule_id") or "")
        if row.get("runtime_alert_role") == "duplicate" and trigger_preservation_candidate(alert):
            trigger_candidate_duplicates.setdefault(rule_id, []).append(row)
    for rows in trigger_candidate_duplicates.values():
        rows.sort(key=lambda row: (str(row["alert"].get("event_time_utc") or ""), str(row["alert"].get("alert_uid") or "")))
        for index, row in enumerate(rows, start=1):
            trigger_candidate_duplicate_rank[str(row["alert"]["alert_uid"])] = index

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
        elif trigger_preservation_candidate(alert) and role != "duplicate":
            must_remain_visible_reason = "runtime trigger-preservation candidate rule family"
        elif (
            trigger_preservation_candidate(alert)
            and role == "duplicate"
            and trigger_candidate_duplicate_rank.get(uid, 999999) <= TRIGGER_PRESERVATION_DUPLICATE_VISIBLE_BUDGET
        ):
            must_remain_visible_reason = "runtime trigger-preservation duplicate sample"
        elif preserved_unique:
            must_remain_visible_reason = f"only alert with unique evidence: {', '.join(preserved_unique)}"
        elif identity.get("privileged_account") is True and identity.get("identity_id") and privileged_identity_counter[str(identity["identity_id"])] == 1:
            must_remain_visible_reason = "only alert involving privileged identity"
        elif asset.get("crown_jewel") is True and asset.get("asset_id") and crown_jewel_asset_counter[str(asset["asset_id"])] == 1:
            must_remain_visible_reason = "only alert touching crown-jewel asset"
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

