from __future__ import annotations

from datetime import datetime
from typing import Any

from safeagentsoc.timeline.attack_catalog import BEHAVIOR_FAMILY_TECHNIQUES, technique_info


SOURCE_PRIORITY = {"direct_mitre": 3, "rule_inferred": 2, "behavior_inferred": 1, "unknown": 0}


def build_case_mitre_mappings(case: dict[str, Any], alerts_by_uid: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    mappings: dict[tuple[str, str], dict[str, Any]] = {}
    for link in case.get("case_alerts") or []:
        enriched = alerts_by_uid.get(str(link.get("alert_uid"))) or {}
        for item in techniques_for_link(link, enriched):
            info = technique_info(item["technique_id"])
            tactics = item.get("tactics") or info.tactics
            for tactic in tactics:
                key = (item["technique_id"], tactic)
                if key not in mappings:
                    mappings[key] = new_mapping(case, item["technique_id"], info.name, tactic, item["mapping_source"])
                update_mapping(mappings[key], link, enriched, item["mapping_source"], item["reason"])
    return sorted(
        mappings.values(),
        key=lambda row: (
            row.get("first_seen") or "",
            row.get("technique_id") or "",
            row.get("tactic") or "",
        ),
    )


def techniques_for_link(link: dict[str, Any], enriched: dict[str, Any]) -> list[dict[str, Any]]:
    summary = enriched.get("original_alert_summary") or {}
    direct_ids = [str(item) for item in (summary.get("mitre_technique_ids") or []) if item]
    tactics = [str(item) for item in (summary.get("mitre_tactics") or []) if item]
    if direct_ids:
        results: list[dict[str, Any]] = []
        for technique_id in direct_ids:
            info = technique_info(technique_id)
            matched_tactics = [tactic for tactic in tactics if tactic in info.tactics]
            results.append(
                {
                    "technique_id": technique_id,
                    "tactics": matched_tactics or info.tactics,
                    "mapping_source": "direct_mitre",
                    "reason": "Technique ID was present in enriched runtime alert.",
                }
            )
        return results

    description = str(summary.get("rule_description") or "").lower()
    process = summary.get("process") or {}
    process_text = " ".join(str(process.get(key) or "") for key in ["name", "path", "command_line"]).lower()
    combined = f"{description} {process_text}"
    rule_inferred = infer_from_rule_text(combined)
    if rule_inferred:
        return [
            {
                "technique_id": technique_id,
                "tactics": technique_info(technique_id).tactics,
                "mapping_source": "rule_inferred",
                "reason": reason,
            }
            for technique_id, reason in rule_inferred
        ]

    family = str(link.get("behavior_family") or "")
    if family in BEHAVIOR_FAMILY_TECHNIQUES:
        return [
            {
                "technique_id": technique_id,
                "tactics": technique_info(technique_id).tactics,
                "mapping_source": "behavior_inferred",
                "reason": f"Technique inferred from behavior_family={family}.",
            }
            for technique_id in BEHAVIOR_FAMILY_TECHNIQUES[family]
        ]
    return []


def infer_from_rule_text(text: str) -> list[tuple[str, str]]:
    if "application compatibility database" in text or "sdbinst" in text:
        return [("T1546.011", "Application Compatibility Database execution implies Application Shimming behavior.")]
    if "powershell" in text:
        return [("T1059.001", "PowerShell rule text implies PowerShell command execution.")]
    if "cmd.exe" in text or "command prompt" in text or "windows command shell" in text:
        return [("T1059.003", "Command shell rule text implies Windows Command Shell execution.")]
    if "secedit" in text or "service startup type" in text:
        return [("T1562.001", "Security tooling or policy modification rule text implies possible defense impairment.")]
    if "sudo to root" in text or "sudo" in text:
        return [("T1548.003", "Sudo activity implies elevation-control behavior.")]
    if "authentication failure" in text or "password guessing" in text or "brute force" in text:
        return [("T1110.001", "Repeated authentication failure text implies password guessing behavior.")]
    if "new user added" in text or "user account was created" in text:
        return [("T1136", "Account creation rule text implies Create Account behavior.")]
    if "file deleted" in text or "delete files" in text:
        return [("T1070.004", "File deletion rule text implies indicator removal or file deletion behavior.")]
    return []


def new_mapping(case: dict[str, Any], technique_id: str, technique_name: str, tactic: str, mapping_source: str) -> dict[str, Any]:
    return {
        "case_id": case["case_id"],
        "technique_id": technique_id,
        "technique_name": technique_name,
        "tactic": tactic,
        "mapping_source": mapping_source,
        "mapping_reasons": [],
        "alert_count": 0,
        "trigger_count": 0,
        "supporting_count": 0,
        "duplicate_count": 0,
        "context_count": 0,
        "noise_count": 0,
        "first_seen": None,
        "last_seen": None,
        "alert_uids": [],
        "evidence_ids": [],
        "source_roles": [],
        "visibility_levels": [],
        "behavior_families": [],
        "source_records": [],
    }


def update_mapping(
    mapping: dict[str, Any],
    link: dict[str, Any],
    enriched: dict[str, Any],
    mapping_source: str,
    reason: str,
) -> None:
    if SOURCE_PRIORITY[mapping_source] > SOURCE_PRIORITY[str(mapping["mapping_source"])]:
        mapping["mapping_source"] = mapping_source
    mapping["alert_count"] += 1
    role = str(link.get("runtime_alert_role") or "unknown")
    role_key = f"{role}_count"
    if role_key in mapping:
        mapping[role_key] += 1
    event_time = str(link.get("event_time_utc") or enriched.get("event_time_utc") or "")
    if event_time:
        mapping["first_seen"] = min_time(mapping.get("first_seen"), event_time)
        mapping["last_seen"] = max_time(mapping.get("last_seen"), event_time)
    append_unique(mapping["alert_uids"], link.get("alert_uid"))
    append_unique(mapping["evidence_ids"], link.get("evidence_id"))
    append_unique(mapping["source_roles"], role)
    append_unique(mapping["visibility_levels"], link.get("visibility_level"))
    append_unique(mapping["behavior_families"], link.get("behavior_family"))
    append_unique(mapping["mapping_reasons"], reason)
    mapping["source_records"].append({"link": link, "enriched": enriched, "mapping_source": mapping_source, "reason": reason})


def append_unique(values: list[Any], value: Any) -> None:
    if value not in {None, ""} and value not in values:
        values.append(value)


def min_time(current: str | None, candidate: str) -> str:
    if not current:
        return candidate
    return candidate if parse_time(candidate) < parse_time(current) else current


def max_time(current: str | None, candidate: str) -> str:
    if not current:
        return candidate
    return candidate if parse_time(candidate) > parse_time(current) else current


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
