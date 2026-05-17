from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any


MIN_RECOMMENDED_CHECKS = 3
MAX_RECOMMENDED_CHECKS = 5


CHECK_CATALOG = [
    "review parent process",
    "inspect command line",
    "verify user login source",
    "check MFA logs",
    "review authentication timeline",
    "review network connections",
    "inspect file path",
    "check related host activity",
    "review EDR/Sysmon if available",
    "escalate to Tier 2 for validation",
    "review proxy and DNS telemetry",
    "review file creation and deletion events",
    "review scheduled task and service configuration",
    "review privileged account activity",
    "review endpoint recovery and backup telemetry",
    "review sudo UAC privilege and administrator group changes",
    "review scheduled tasks services startup registry PAM and account creation events",
    "review telemetry ingestion quality and parser health",
    "review change management and deployment records",
    "review administrative activity and maintenance windows",
    "review application compatibility shim and registry configuration",
    "review Wazuh manager queue, pipeline lag, and backlog state",
]

CHECK_CATEGORY_CATALOG = {
    "telemetry_pipeline_review": "review telemetry ingestion quality and parser health",
    "change_management_review": "review change management and deployment records",
    "admin_activity_review": "review administrative activity and maintenance windows",
    "application_shim_validation": "review application compatibility shim and registry configuration",
    "wazuh_feed_backlog_review": "review Wazuh manager queue, pipeline lag, and backlog state",
    "credential_dumping": "review authentication timeline",
    "identity_compromise": "review privileged account activity",
    "lateral_movement": "check related host activity",
    "external_c2": "review proxy and DNS telemetry",
    "exfiltration": "review proxy and DNS telemetry",
    "impact": "review endpoint recovery and backup telemetry",
    "malware_download": "review file creation and deletion events",
    "privilege_escalation": "review sudo UAC privilege and administrator group changes",
    "persistence": "review scheduled tasks services startup registry PAM and account creation events",
    "defense_evasion": "review EDR/Sysmon if available",
}

CHECK_CATEGORY_KEYWORDS = {
    "telemetry_pipeline_review": ("telemetry ingestion", "parser", "pipeline", "normalizer", "mapping", "field extraction"),
    "change_management_review": ("change management", "deployment", "release", "maintenance ticket", "approved change", "configuration drift"),
    "admin_activity_review": ("admin activity", "administrator activity", "maintenance window", "operational task", "it admin", "service desk"),
    "application_shim_validation": ("application shimming", "shim", "sdb", "appcompat", "secedit", "registry run key"),
    "wazuh_feed_backlog_review": ("wazuh", "manager queue", "backlog", "queue lag", "ingest lag", "event backlog"),
    "credential_dumping": ("credential", "lsass", "credential store", "authentication"),
    "identity_compromise": ("identity", "account", "user", "privileged"),
    "lateral_movement": ("remote", "rdp", "ssh", "smb", "cross host", "cross-host"),
    "external_c2": ("dns", "proxy", "firewall", "network connection", "c2"),
    "exfiltration": ("dlp", "outbound", "transfer", "storage", "exfil"),
    "impact": ("recovery", "backup", "availability", "integrity", "file modification"),
    "malware_download": ("download", "payload", "quarantine", "web/proxy"),
    "privilege_escalation": ("sudo", "uac", "privilege", "token", "administrator group"),
    "persistence": ("scheduled", "service", "startup", "registry", "pam", "account creation"),
    "defense_evasion": ("edr", "sysmon", "defense", "indicator", "log deletion"),
}

FORBIDDEN_ACTIONS = (
    "disable user",
    "isolate host",
    "delete file",
    "block ip",
    "reset password",
    "run powershell",
    "execute shell",
    "modify firewall",
    "quarantine host",
    "kill process",
)

ALLOWED_CHECK_PREFIXES = (
    "review ",
    "inspect ",
    "verify ",
    "check ",
    "escalate ",
)

INVESTIGATION_TERMS = (
    "log",
    "telemetry",
    "timeline",
    "connection",
    "process",
    "file",
    "host",
    "user",
    "identity",
    "mfa",
    "edr",
    "sysmon",
    "dns",
    "proxy",
    "firewall",
    "authentication",
    "remote",
    "network",
    "backup",
    "integrity",
    "tier 2",
    "validation",
    "sudo",
    "uac",
    "privilege",
    "administrator",
    "scheduled",
    "service",
    "startup",
    "registry",
    "pam",
    "account",
)


def normalize_check(value: str) -> str:
    text = value.strip().lower().replace("-", " ")
    return " ".join(text.split())


def check_allowed(value: str) -> bool:
    text = normalize_check(value)
    if any(action in text for action in FORBIDDEN_ACTIONS):
        return False
    if best_catalog_match(text)["score"] >= 0.54:
        return True
    return text.startswith(ALLOWED_CHECK_PREFIXES) and any(term in text for term in INVESTIGATION_TERMS)


def best_catalog_match(value: str) -> dict[str, Any]:
    text = normalize_check(value)
    category = check_category(text)
    if category:
        return {"catalog_check": CHECK_CATEGORY_CATALOG[category], "score": 1.0, "category": category}
    candidates = [
        {
            "catalog_check": item,
            "score": max(
                SequenceMatcher(None, text, normalize_check(item)).ratio(),
                1.0 if normalize_check(item) in text or text in normalize_check(item) else 0.0,
            ),
        }
        for item in CHECK_CATALOG
    ]
    best = max(candidates, key=lambda row: row["score"])
    best["category"] = "generic"
    return best


def check_category(text: str) -> str | None:
    for category, keywords in CHECK_CATEGORY_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            return category
    return None


def validate_recommended_checks(checks: list[str]) -> dict[str, Any]:
    rows = []
    for check in checks:
        match = best_catalog_match(check)
        rows.append(
            {
                "recommended_check": check,
                "allowed": check_allowed(check),
                "catalog_match": match["catalog_check"],
                "check_category": match.get("category", "generic"),
                "match_score": round(float(match["score"]), 4),
            }
        )
    return {
        "valid": bool(checks) and all(row["allowed"] for row in rows),
        "rows": rows,
    }


def normalize_recommended_checks(
    checks: list[Any],
    *,
    min_checks: int = MIN_RECOMMENDED_CHECKS,
    max_checks: int = MAX_RECOMMENDED_CHECKS,
) -> tuple[list[str], bool]:
    changed = False
    normalized: list[str] = []
    for check in checks:
        original = " ".join(str(check).strip().split())
        text = normalize_check(original)
        if not text:
            changed = True
            continue
        match = best_catalog_match(original)
        if check_allowed(original):
            selected = match["catalog_check"] if float(match["score"]) >= 0.9 else original
            normalized.append(selected)
            if normalize_check(selected) != normalize_check(original):
                changed = True
        else:
            normalized.append(match["catalog_check"])
            changed = True
    if not normalized:
        normalized = CHECK_CATALOG[: max(min_checks, 1)]
        changed = True
    deduped = list(dict.fromkeys(normalized))
    if deduped != normalized:
        changed = True
    if len(deduped) > max_checks:
        deduped = deduped[:max_checks]
        changed = True
    return deduped, changed
