from __future__ import annotations

from typing import Any


def _text(alert: dict[str, Any]) -> str:
    summary = alert.get("original_alert_summary") or {}
    process = summary.get("process") or {}
    file_info = summary.get("file") or {}
    fields = [
        summary.get("rule_description"),
        summary.get("event_category"),
        summary.get("event_action"),
        process.get("name"),
        process.get("command_line"),
        file_info.get("path"),
        " ".join(alert.get("analyst_priority", {}).get("suppressors") or []),
    ]
    return " ".join(str(value or "") for value in fields).lower()


def map_behavior_family(alert: dict[str, Any]) -> str:
    summary = alert.get("original_alert_summary") or {}
    platform = str(summary.get("platform") or "").lower()
    rule_id = str(summary.get("rule_id") or "")
    text = _text(alert)
    service = str((alert.get("asset_context") or {}).get("business_service") or "").lower()
    asset_role = str((alert.get("asset_context") or {}).get("asset_role") or "").lower()

    if "case-boundary" in text or "case boundary" in text or "lab case-boundary" in text:
        return "case_boundary_marker"
    if "sca" in text or "cis" in text or "policy monitoring" in text or "compliance" in text:
        return "sca_compliance_backlog"
    if "defender" in text or "pua" in text or "potentially unwanted" in text:
        return "windows_defender_pua"
    if "dpkg" in text or "package" in text or rule_id in {"2901", "2902", "2903", "2904"}:
        return "linux_package_management"
    if "pam" in text or "login" in text or "session" in text or "authentication" in text or "sshd" in text:
        return "linux_authentication" if platform == "linux" else "network_activity"
    if "sudo" in text or "root" in text or "privilege" in text:
        return "linux_privilege_activity" if platform == "linux" else "windows_persistence_or_privilege"
    if "powershell" in text:
        return "windows_powershell_activity"
    if "sdbinst" in text or "persistence" in text or "privilege escalation" in text or "secedit" in text:
        return "windows_persistence_or_privilege"
    if "process" in text or "command" in text or "execution" in text or "cmd.exe" in text:
        return "windows_suspicious_execution" if platform == "windows" else "linux_privilege_activity"
    if "syscheck" in text or "integrity" in text or "file added" in text or "file modified" in text:
        return "linux_integrity_monitoring"
    if (service == "security monitoring" and platform == "linux") or "wazuh" in text or "siem" in asset_role:
        return "wazuh_security_infrastructure"
    if "network" in text or "connection" in text or "firewall" in text:
        return "network_activity"
    return "unknown_low_signal"


NOISY_BEHAVIOR_FAMILIES = {
    "linux_package_management",
    "sca_compliance_backlog",
    "case_boundary_marker",
    "unknown_low_signal",
}


def is_noisy_behavior_family(family: str) -> bool:
    return family in NOISY_BEHAVIOR_FAMILIES

