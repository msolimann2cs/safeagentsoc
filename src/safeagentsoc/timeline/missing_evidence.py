from __future__ import annotations

from typing import Any


MISSING_EVIDENCE_CATEGORIES: dict[str, dict[str, Any]] = {
    "credential_dumping": {
        "tactics": {"Credential Access"},
        "reason_absent": "No Credential Access tactic, credential dumping technique, or credential artifact evidence was observed.",
        "check": "Review authentication logs, LSASS access telemetry, and credential store access events.",
    },
    "lateral_movement": {
        "tactics": {"Lateral Movement"},
        "reason_absent": "No Lateral Movement tactic, remote service technique, cross-host sequence, or remote execution evidence was observed.",
        "check": "Review remote logons, SSH/RDP/SMB activity, and cross-host process execution.",
    },
    "external_c2": {
        "tactics": {"Command and Control"},
        "reason_absent": "No Command and Control tactic, external destination pattern, or C2-like network evidence was observed.",
        "check": "Review DNS, proxy, firewall, and EDR network connection telemetry.",
    },
    "exfiltration": {
        "tactics": {"Exfiltration"},
        "reason_absent": "No Exfiltration tactic, external transfer evidence, or bulk outbound data movement was observed.",
        "check": "Review proxy, firewall, DLP, storage, and unusual outbound transfer records.",
    },
    "impact": {
        "tactics": {"Impact"},
        "reason_absent": "No confirmed destructive, disruptive, encryption, or data manipulation impact evidence was observed.",
        "check": "Review endpoint recovery events, file modification spikes, service availability, and backup integrity.",
    },
    "malware_download": {
        "tactics": {"Command and Control", "Initial Access"},
        "reason_absent": "No malware download, ingress tool transfer, or external payload retrieval evidence was observed.",
        "check": "Review web/proxy downloads, file creation, and endpoint quarantine telemetry.",
    },
    "privilege_escalation": {
        "tactics": {"Privilege Escalation"},
        "reason_absent": "No Privilege Escalation tactic or elevation-control technique was observed.",
        "check": "Review sudo, UAC, privilege assignment, token, and administrator group changes.",
    },
    "persistence": {
        "tactics": {"Persistence"},
        "reason_absent": "No Persistence tactic, autostart, account creation, or event-triggered execution evidence was observed.",
        "check": "Review scheduled tasks, services, startup folders, registry run keys, PAM, and account creation events.",
    },
    "defense_evasion": {
        "tactics": {"Defense Evasion"},
        "reason_absent": "No Defense Evasion tactic, log clearing, tool impairment, or indicator removal evidence was observed.",
        "check": "Review logging changes, security tool state, registry policy changes, and deletion events.",
    },
    "identity_compromise": {
        "tactics": {"Credential Access", "Initial Access"},
        "reason_absent": "No clear identity compromise evidence, valid-account abuse sequence, or account takeover signal was observed.",
        "check": "Review MFA, impossible travel, account lockouts, risky sign-ins, and privileged account activity.",
    },
}


VISIBILITY_LIMITATION = "The dataset is Wazuh alert telemetry and enriched case context, not complete packet capture, full EDR telemetry, or identity-provider telemetry."


def build_missing_evidence(case: dict[str, Any], technique_claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observed_tactics = {claim["tactic"] for claim in technique_claims if claim.get("claim_type") == "observed"}
    inferred_tactics = {claim["tactic"] for claim in technique_claims if claim.get("claim_type") == "inferred"}
    entries: list[dict[str, Any]] = []
    for category, config in MISSING_EVIDENCE_CATEGORIES.items():
        relevant = set(config["tactics"])
        if observed_tactics & relevant:
            status = "observed"
            reason = f"At least one observed ATT&CK claim exists for {', '.join(sorted(observed_tactics & relevant))}."
        elif inferred_tactics & relevant:
            status = "unknown"
            reason = f"Only inferred evidence exists for {', '.join(sorted(inferred_tactics & relevant))}; this is not enough for a direct claim."
        else:
            status = "not_observed"
            reason = str(config["reason_absent"])
        entries.append(
            {
                "case_id": case["case_id"],
                "missing_evidence_type": category,
                "status": status,
                "reason": reason,
                "visibility_limitation": VISIBILITY_LIMITATION,
                "recommended_check_for_phase7": config["check"],
            }
        )
    return entries

