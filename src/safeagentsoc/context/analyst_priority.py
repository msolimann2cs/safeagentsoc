from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from safeagentsoc.context.business_risk import SEVERITY_SCORES, safe_lower


@dataclass(frozen=True)
class AnalystPriorityResult:
    analyst_priority_score: float
    analyst_priority_label: str
    urgent_priority_gate_passed: bool
    gate_reasons: list[str]
    priority_factors: list[str]
    suppressors: list[str]
    explanation: str
    score_components: dict[str, Any]


def label_for_score(score: float, urgent_priority_gate_passed: bool) -> str:
    if score >= 85 and urgent_priority_gate_passed:
        return "critical"
    if score >= 70 and urgent_priority_gate_passed:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def text_blob(summary: dict[str, Any]) -> str:
    fields = [
        summary.get("rule_id"),
        summary.get("rule_description"),
        summary.get("event_category"),
        summary.get("event_action"),
        summary.get("event_outcome"),
        summary.get("decoder_name"),
    ]
    process = summary.get("process") or {}
    file_entity = summary.get("file") or {}
    fields.extend(
        [
            process.get("name"),
            process.get("command_line"),
            process.get("parent_name"),
            file_entity.get("path"),
            file_entity.get("name"),
        ]
    )
    return " ".join(str(field).lower() for field in fields if field not in (None, ""))


def non_empty_list(value: Any) -> list[Any]:
    if not value:
        return []
    if isinstance(value, list):
        return [item for item in value if item not in (None, "", "N/A", "n/a")]
    return [value] if value not in ("", "N/A", "n/a") else []


def has_any_entity_value(entity: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return any(entity.get(key) not in (None, "", [], {}) for key in keys)


def has_runtime_evidence(summary: dict[str, Any]) -> dict[str, bool]:
    process = summary.get("process") or {}
    network = summary.get("network") or {}
    file_entity = summary.get("file") or {}
    user = summary.get("user") or {}
    return {
        "mitre": bool(non_empty_list(summary.get("mitre_technique_ids"))),
        "user": has_any_entity_value(user, ("username", "user_id", "domain", "privilege_hint")),
        "process": has_any_entity_value(process, ("name", "command_line", "pid", "path", "parent_name")),
        "network": has_any_entity_value(network, ("source_ip", "src_ip", "destination_ip", "dst_ip", "destination_port", "dst_port")),
        "file": has_any_entity_value(file_entity, ("path", "name", "hash_sha256", "extension")),
    }


def is_noise_or_backlog_family(summary: dict[str, Any]) -> tuple[bool, str | None]:
    text = text_blob(summary)
    rule_id = str(summary.get("rule_id") or "")
    if "cis " in text or "benchmark" in text or "security configuration assessment" in text or rule_id in {"19007", "19008", "19009"}:
        return True, "SCA/CIS compliance backlog telemetry"
    if "dpkg" in text or "debian package" in text or "package" in text:
        return True, "package-management operational telemetry"
    if "safeagentsoc run start marker" in text or "safeagentsoc run end marker" in text or "scenario marker" in text:
        return True, "lab case-boundary marker telemetry"
    if "pam: login session opened" in text or "pam: login session closed" in text:
        return True, "PAM session open/close noise without correlation"
    if "windows defender" in text and ("potentially unwanted" in text or "pua" in text):
        return True, "endpoint-protection PUA telemetry without execution context"
    return False, None


def is_syscheck_family(summary: dict[str, Any]) -> bool:
    text = text_blob(summary)
    return "syscheck" in text or "integrity checksum changed" in text or "integrity" in text


def is_critical_file_or_security_path(summary: dict[str, Any]) -> bool:
    text = text_blob(summary)
    critical_terms = (
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "authorized_keys",
        "sshd_config",
        "wazuh",
        "ossec",
        "security",
    )
    return any(term in text for term in critical_terms)


def high_signal_behavior(summary: dict[str, Any]) -> tuple[bool, list[str]]:
    text = text_blob(summary)
    reasons: list[str] = []
    sudo_success = "successful sudo to root" in text
    sudo_suspicious_context_terms = (
        "authentication failure",
        "login failed",
        "multiple authentication failures",
        "non-existent user",
        "brute force",
        "curl ",
        "wget ",
        "base64",
        "nc ",
        "netcat",
        "bash -c",
        "python -c",
        "perl -e",
        "chmod 777",
        "chown ",
        "useradd",
        "adduser",
        "visudo",
        "sudoers",
    )
    patterns = [
        ("powershell", "PowerShell activity"),
        ("command prompt", "Windows command prompt activity"),
        ("cmd shell", "Windows command shell activity"),
        ("abnormal process", "abnormal parent/child process relationship"),
        ("suspicious", "suspicious execution rule semantics"),
        ("sudo", "Linux sudo activity"),
        ("authentication failure", "authentication failure"),
        ("login failed", "login failure"),
        ("non-existent user", "non-existent user login attempt"),
        ("multiple authentication failures", "multiple authentication failures"),
        ("sshd: authentication failed", "SSH authentication failure"),
        ("processes running for all users", "process discovery"),
        ("ps command", "process discovery command"),
        ("service startup type was changed", "service configuration change"),
        ("application compatibility database launched", "application compatibility database execution"),
        ("secedit.exe", "suspicious SecEdit execution path"),
        ("auditd: selinux permission check", "SELinux permission check"),
    ]
    for term, reason in patterns:
        if term in text:
            reasons.append(reason)
    if sudo_success and any(term in text for term in sudo_suspicious_context_terms):
        reasons.append("successful sudo to ROOT with suspicious context")
    return bool(reasons), sorted(set(reasons))


def high_priority_gate(
    *,
    original_alert_summary: dict[str, Any],
    asset_context: dict[str, Any],
    identity_context: dict[str, Any],
    context_metadata: dict[str, Any],
) -> tuple[bool, list[str]]:
    mapping_type = context_metadata.get("mapping_rule_type")
    evidence = has_runtime_evidence(original_alert_summary)
    behavior, behavior_reasons = high_signal_behavior(original_alert_summary)
    mitre_present = evidence["mitre"]
    event_category = safe_lower(original_alert_summary.get("event_category"), "")
    severity = safe_lower(original_alert_summary.get("severity_normalized"), "")
    asset_role = safe_lower(asset_context.get("asset_role"), "")
    reasons: list[str] = []

    if mapping_type == "exact_identity" and identity_context.get("privileged_account") is True and behavior:
        reasons.append("Exact privileged identity plus suspicious behavior")
    if mapping_type == "behavioral" and mitre_present:
        reasons.append("Behavioral mapping with MITRE technique evidence")
    if mapping_type == "behavioral" and behavior and (evidence["process"] or evidence["network"] or evidence["file"]):
        reasons.append("Behavioral mapping with suspicious runtime entity evidence")
    if asset_role in {"siem_server", "detection_data_store", "security_console", "config_monitoring_node"}:
        if severity in {"high", "critical"} and not is_noise_or_backlog_family(original_alert_summary)[0]:
            reasons.append("Critical security infrastructure with high technical severity")
    if behavior and event_category in {"authentication", "privilege_activity", "process_execution", "network_activity"}:
        reasons.extend(behavior_reasons[:2])

    return bool(reasons), sorted(set(reasons))


def cap_score(score: float, cap: float, suppressors: list[str], reason: str) -> float:
    if score > cap:
        suppressors.append(f"{reason}; score capped at {cap}")
    return min(score, cap)


def calculate_analyst_priority(
    *,
    original_alert_summary: dict[str, Any],
    asset_context: dict[str, Any],
    identity_context: dict[str, Any],
    identity_applicability: dict[str, Any],
    policy_context: dict[str, Any],
    business_risk: dict[str, Any],
    context_metadata: dict[str, Any],
) -> AnalystPriorityResult:
    business_score = float(business_risk.get("business_risk_score") or 0.0)
    severity_score = SEVERITY_SCORES.get(safe_lower(original_alert_summary.get("severity_normalized")), 35)
    context_confidence = float(context_metadata.get("context_confidence") or 0.0)
    mapping_type = context_metadata.get("mapping_rule_type") or "unknown"
    mapping_confidence = float(context_metadata.get("mapping_confidence") or 0.0)
    evidence = has_runtime_evidence(original_alert_summary)
    behavior_present, behavior_reasons = high_signal_behavior(original_alert_summary)
    gate_passed, gate_reasons = high_priority_gate(
        original_alert_summary=original_alert_summary,
        asset_context=asset_context,
        identity_context=identity_context,
        context_metadata=context_metadata,
    )

    evidence_strength = 0.0
    evidence_strength += 24 if evidence["mitre"] else 0
    evidence_strength += 18 if behavior_present else 0
    evidence_strength += 12 if evidence["user"] or identity_context.get("identity_id") else 0
    evidence_strength += 8 if evidence["process"] else 0
    evidence_strength += 6 if evidence["network"] else 0
    evidence_strength += 4 if evidence["file"] else 0
    evidence_strength = min(evidence_strength, 60.0)

    score = (
        0.48 * business_score
        + 0.18 * float(severity_score)
        + 0.14 * context_confidence * 100
        + 0.20 * evidence_strength
    )

    priority_factors: list[str] = []
    suppressors: list[str] = []

    if mapping_type == "exact_identity":
        score += 7
        priority_factors.append("Exact identity mapping")
    elif mapping_type == "behavioral":
        score += 3
        priority_factors.append("Behavioral context mapping")
    elif mapping_type in {"agent_fallback", "generic_unknown_fallback"}:
        score -= 12
        suppressors.append("Host-level fallback mapping is weaker than behavior or identity evidence")

    if identity_context.get("privileged_account") is True:
        score += 8
        priority_factors.append("Privileged identity context")
    if evidence["mitre"]:
        priority_factors.append("MITRE technique evidence present")
    if behavior_present:
        priority_factors.extend(behavior_reasons)
    if policy_context.get("relevant_policy_ids"):
        priority_factors.append("Governance policy relevance")
    if identity_applicability.get("status") == "missing":
        suppressors.append("Identity applicable but not resolved")
    if identity_applicability.get("status") == "unknown":
        suppressors.append("Identity applicability is unknown")

    noise_family, noise_reason = is_noise_or_backlog_family(original_alert_summary)
    event_category = safe_lower(original_alert_summary.get("event_category"), "")
    severity = safe_lower(original_alert_summary.get("severity_normalized"), "")
    no_strong_runtime_evidence = not any([evidence["mitre"], evidence["user"], evidence["network"], evidence["file"], behavior_present])

    if noise_family and noise_reason:
        if "SCA/CIS" in noise_reason:
            cap = 49.9 if safe_lower(asset_context.get("asset_role")) in {"siem_server", "detection_data_store"} else 39.9
        elif "package-management" in noise_reason:
            cap = 44.9
        elif "PAM session" in noise_reason:
            cap = 49.9
        elif "marker" in noise_reason:
            cap = 49.9
        elif "PUA" in noise_reason:
            cap = 59.9
        else:
            cap = 54.9
        score = cap_score(score, cap, suppressors, noise_reason)

    if is_syscheck_family(original_alert_summary):
        cap = 74.9 if is_critical_file_or_security_path(original_alert_summary) else 59.9
        score = cap_score(score, cap, suppressors, "Syscheck/integrity alert requires correlation before urgent review")

    if mapping_type in {"agent_fallback", "generic_unknown_fallback"} and no_strong_runtime_evidence:
        fallback_cap = 69.9 if severity in {"high", "critical"} else 59.9
        score = cap_score(score, fallback_cap, suppressors, "Fallback-only context lacks strong runtime evidence")

    if not gate_passed and score >= 70:
        score = cap_score(score, 69.9, suppressors, "Urgent-priority gate did not pass")

    score = round(max(0.0, min(score, 100.0)), 2)
    label = label_for_score(score, gate_passed)
    if label in {"low", "medium"} and not gate_passed:
        gate_reasons = gate_reasons or ["No urgent-priority gate passed"]

    explanation = (
        f"Analyst priority is {label} because business impact score {business_score:.2f} was adjusted by "
        f"runtime evidence strength, mapping confidence {mapping_confidence:.2f}, and alert-fatigue suppressors."
    )

    return AnalystPriorityResult(
        analyst_priority_score=score,
        analyst_priority_label=label,
        urgent_priority_gate_passed=gate_passed,
        gate_reasons=gate_reasons,
        priority_factors=sorted(set(priority_factors)) or ["No strong urgent-review signal"],
        suppressors=suppressors,
        explanation=explanation,
        score_components={
            "business_risk_score": business_score,
            "severity_score": float(severity_score),
            "context_confidence": round(context_confidence, 4),
            "mapping_confidence": round(mapping_confidence, 4),
            "evidence_strength": round(evidence_strength, 2),
            "mapping_rule_type": mapping_type,
            "event_category": event_category,
            "urgent_priority_gate_passed": gate_passed,
        },
    )
