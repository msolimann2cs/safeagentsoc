from __future__ import annotations

from statistics import mean
from typing import Any

from safeagentsoc.timeline.attack_catalog import TACTIC_ORDER


BACKLOG_FAMILIES = {"wazuh_security_infrastructure", "sca_compliance_backlog", "linux_package_management"}


def build_kill_chain_progression(case: dict[str, Any], technique_claims: list[dict[str, Any]]) -> dict[str, Any]:
    observed = ordered_stages({claim["tactic"] for claim in technique_claims if claim.get("claim_type") == "observed"})
    inferred = ordered_stages({claim["tactic"] for claim in technique_claims if claim.get("claim_type") == "inferred"})
    not_observed = [stage for stage in TACTIC_ORDER if stage not in set(observed) | set(inferred)]
    progression_label = progression_label_for_case(case, observed, inferred)
    confidence_values = [float(claim.get("confidence_score") or 0) for claim in technique_claims if claim.get("claim_type") in {"observed", "inferred"}]
    return {
        "case_id": case["case_id"],
        "observed_stages": observed,
        "inferred_stages": inferred,
        "not_observed_stages": not_observed,
        "progression_depth": progression_label,
        "progression_confidence": round(mean(confidence_values or [0.0]), 4),
        "reason": progression_reason(case, observed, inferred, progression_label),
    }


def ordered_stages(stages: set[str]) -> list[str]:
    return [stage for stage in TACTIC_ORDER if stage in stages]


def progression_label_for_case(case: dict[str, Any], observed: list[str], inferred: list[str]) -> str:
    family = str(case.get("primary_behavior_family") or "")
    title = str(case.get("case_title") or "").lower()
    if "vulnerability backlog" in title or family in BACKLOG_FAMILIES and int(case.get("suppressed_alert_count") or 0) > int(case.get("visible_alert_count") or 0):
        return "telemetry_backlog"
    observed_set = set(observed)
    if not observed_set:
        return "single_host_activity"
    if observed_set <= {"Discovery", "Defense Evasion"}:
        return "single_host_activity"
    if observed_set <= {"Execution"}:
        return "local_execution"
    if observed_set & {"Persistence", "Privilege Escalation"} and not observed_set & {"Lateral Movement", "Command and Control", "Exfiltration", "Impact"}:
        return "multi_step_local_activity" if len(observed_set) > 1 else "local_persistence"
    if observed_set & {"Lateral Movement", "Command and Control", "Exfiltration"}:
        return "possible_intrusion_chain"
    if observed_set & {"Impact"} and observed_set & {"Execution", "Persistence", "Credential Access", "Lateral Movement"}:
        return "confirmed_intrusion_chain"
    if inferred:
        return "possible_intrusion_chain"
    return "single_host_activity"


def progression_reason(case: dict[str, Any], observed: list[str], inferred: list[str], label: str) -> str:
    if label == "telemetry_backlog":
        return "Case is dominated by backlog/compliance/repeated telemetry and should not be presented as an intrusion chain."
    if observed:
        return f"Observed ATT&CK stages: {', '.join(observed)}."
    if inferred:
        return f"Only inferred ATT&CK stages are present: {', '.join(inferred)}."
    return "No ATT&CK stage was directly observed from the available runtime evidence."

