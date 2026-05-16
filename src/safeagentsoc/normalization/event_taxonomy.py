from __future__ import annotations

import re


EVENT_CATEGORIES = {
    "authentication",
    "process_execution",
    "privilege_activity",
    "persistence",
    "discovery",
    "collection_or_staging",
    "network_activity",
    "file_activity",
    "system_activity",
    "monitoring_internal",
    "background",
    "unknown",
}


def _contains(text: str, patterns: list[str]) -> bool:
    return any(pattern in text for pattern in patterns)


def infer_event_category(rule_description: str | None, decoder_name: str | None, rule_groups: list[str]) -> str:
    text = " ".join([rule_description or "", decoder_name or "", " ".join(rule_groups)]).lower()

    if _contains(text, ["sudo", "privilege", "root executed", "elevated"]):
        return "privilege_activity"
    if _contains(text, ["login", "logon", "authentication", "pam", "sshd", "invalid user"]):
        return "authentication"
    if _contains(text, ["whoami", "hostname", "discovery", "queried with ps", "processes running", "net user"]):
        return "discovery"
    if _contains(text, ["powershell", "cmd shell", "command shell", "process spawned", "binary", "process execution"]):
        return "process_execution"
    if _contains(text, ["scheduled", "cron", "service", "startup", "autorun", "persistence"]):
        return "persistence"
    if _contains(text, ["archive", "compress", "zip", "staging", "collection"]):
        return "collection_or_staging"
    if _contains(text, ["network", "connection", "rdp", "remote", "srcip", "dstip"]):
        return "network_activity"
    if _contains(text, ["syscheck", "file", "registry", "checksum", "integrity", "added", "deleted"]):
        return "file_activity"
    if _contains(text, ["sca", "vulnerability", "ossec", "wazuh", "agent keepalive"]):
        return "monitoring_internal"
    if _contains(text, ["dpkg", "package", "apparmor", "kernel", "systemd"]):
        return "system_activity"
    return "unknown"


def infer_event_action(rule_description: str | None, decoder_name: str | None, rule_id: str | None) -> str:
    text = (rule_description or "").lower()
    decoder = (decoder_name or "unknown").lower()

    action_patterns = [
        ("login session opened", "login_session_opened"),
        ("login session closed", "login_session_closed"),
        ("successful sudo", "sudo_success"),
        ("sudo", "sudo_activity"),
        ("powershell", "powershell_activity"),
        ("cmd shell", "command_shell_activity"),
        ("command shell", "command_shell_activity"),
        ("processes running", "process_listing"),
        ("discovery", "discovery_activity"),
        ("checksum changed", "integrity_checksum_changed"),
        ("file added", "file_created"),
        ("deleted", "file_deleted"),
        ("dpkg", "package_activity"),
        ("vulnerability", "vulnerability_detection"),
        ("apparmor denied", "apparmor_denied"),
        ("scheduled", "scheduled_activity"),
    ]

    for pattern, action in action_patterns:
        if pattern in text:
            return action

    cleaned_decoder = re.sub(r"[^a-z0-9]+", "_", decoder).strip("_") or "unknown"
    if rule_id:
        return f"wazuh_rule_{rule_id}"
    return cleaned_decoder


def infer_event_outcome(rule_description: str | None, rule_level: int | None) -> str:
    text = (rule_description or "").lower()

    if _contains(text, ["denied", "blocked"]):
        return "blocked"
    if _contains(text, ["failed", "failure", "invalid", "error"]):
        return "failure"
    if _contains(text, ["suspicious", "attack", "threat", "malware"]):
        return "suspicious"
    if _contains(text, ["successful", "opened", "closed", "installed", "added", "changed", "queried", "executed", "detected"]):
        return "success"
    if rule_level is not None and rule_level >= 8:
        return "suspicious"
    return "unknown"
