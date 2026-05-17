from __future__ import annotations

from pathlib import Path
from typing import Any


SAFE_NEGATIONS = ("no confirmed", "does not confirm", "not observed", "unconfirmed", "not enough evidence")
UNSUPPORTED_TERMS = {
    "full compromise": "full_compromise",
    "credential dumping": "credential_dumping",
    "lateral movement": "lateral_movement",
    "command and control": "external_c2",
    "exfiltration": "exfiltration",
    "impact": "impact",
}


def build_attack_story(
    case: dict[str, Any],
    timeline_steps: list[dict[str, Any]],
    technique_claims: list[dict[str, Any]],
    missing_entries: list[dict[str, Any]],
    kill_chain: dict[str, Any],
) -> dict[str, Any]:
    observed = [claim for claim in technique_claims if claim["claim_type"] == "observed"]
    inferred = [claim for claim in technique_claims if claim["claim_type"] == "inferred"]
    unconfirmed = [entry for entry in missing_entries if entry["status"] in {"not_observed", "unknown"}]
    primary_behavior = display_behavior(case)
    asset = display_asset(case)
    evidence_ids = sorted({evidence_id for step in timeline_steps for evidence_id in step.get("evidence_ids", [])})
    observed_chain = ordered_unique([claim["tactic"] for claim in observed])
    inferred_chain = ordered_unique([claim["tactic"] for claim in inferred])
    safe_conclusion = build_safe_conclusion(observed_chain, unconfirmed, kill_chain)
    recommended_checks = ordered_unique([entry["recommended_check_for_phase7"] for entry in unconfirmed])
    forbidden_claims = [f"Do not claim {entry['missing_evidence_type'].replace('_', ' ')} without new supporting evidence." for entry in unconfirmed]
    executive_summary = (
        f"SafeAgentSOC observed {primary_behavior} on {asset}. "
        f"The deterministic progression label is {kill_chain['progression_depth']}."
    )
    analyst_summary = (
        f"The case contains {case.get('visible_alert_count')} visible alerts and "
        f"{case.get('suppressed_alert_count')} collapsed alerts. "
        f"Observed claims are limited to: {', '.join(observed_chain) if observed_chain else 'none'}."
    )
    story = {
        "case_id": case["case_id"],
        "case_title": case["case_title"],
        "story_type": "deterministic_template",
        "executive_summary": executive_summary,
        "analyst_summary": analyst_summary,
        "observed_chain": observed_chain,
        "inferred_chain": inferred_chain,
        "not_observed": [entry["missing_evidence_type"] for entry in unconfirmed if entry["status"] == "not_observed"],
        "missing_evidence": unconfirmed,
        "evidence_ids": evidence_ids,
        "safe_conclusion": safe_conclusion,
        "recommended_investigation_checks": recommended_checks,
        "llm_forbidden_claims": forbidden_claims,
        "overclaiming_warnings": lint_story_text(
            "\n".join([executive_summary, analyst_summary, safe_conclusion]),
            technique_claims,
        ),
    }
    story["markdown"] = render_story_markdown(case, timeline_steps, story)
    return story


def build_safe_conclusion(observed_chain: list[str], missing_entries: list[dict[str, Any]], kill_chain: dict[str, Any]) -> str:
    observed_text = ", ".join(observed_chain) if observed_chain else "case activity with limited ATT&CK support"
    missing_text = ", ".join(entry["missing_evidence_type"].replace("_", " ") for entry in missing_entries[:6])
    if kill_chain["progression_depth"] == "telemetry_backlog":
        return f"The evidence supports backlog or repeated telemetry review for {observed_text}. It does not confirm an intrusion chain or {missing_text}."
    return f"The evidence supports {observed_text}. It does not confirm {missing_text}."


def render_story_markdown(case: dict[str, Any], timeline_steps: list[dict[str, Any]], story: dict[str, Any]) -> str:
    observed_lines = [
        f"- {step['step_order']}. {step['evidence_summary']} Evidence: {', '.join(step.get('evidence_ids', [])[:5])}"
        for step in timeline_steps[:12]
    ]
    missing_lines = [
        f"- {entry['missing_evidence_type']}: {entry['reason']}"
        for entry in story["missing_evidence"][:10]
    ]
    check_lines = [f"- {check}" for check in story["recommended_investigation_checks"][:10]]
    return "\n".join(
        [
            f"# Case {case['case_id']}: {case['case_title']}",
            "",
            "## Summary",
            story["executive_summary"],
            "",
            "## Analyst Summary",
            story["analyst_summary"],
            "",
            "## Observed Timeline",
            "\n".join(observed_lines) if observed_lines else "- No timeline evidence available.",
            "",
            "## Missing or Unconfirmed Evidence",
            "\n".join(missing_lines) if missing_lines else "- No missing evidence entries generated.",
            "",
            "## Analyst-Safe Conclusion",
            story["safe_conclusion"],
            "",
            "## Recommended Checks for Phase 7",
            "\n".join(check_lines) if check_lines else "- No additional checks generated.",
            "",
        ]
    )


def write_story_markdown(story_dir: Path, story: dict[str, Any]) -> str:
    story_dir.mkdir(parents=True, exist_ok=True)
    path = story_dir / f"{story['case_id']}.md"
    path.write_text(story["markdown"], encoding="utf-8", newline="\n")
    return str(path)


def lint_story_text(text: str, technique_claims: list[dict[str, Any]]) -> list[str]:
    lower = text.lower()
    observed_terms = {claim["tactic"].lower() for claim in technique_claims if claim.get("claim_type") == "observed"}
    warnings: list[str] = []
    for term, category in UNSUPPORTED_TERMS.items():
        if term not in lower:
            continue
        sentence = sentence_containing(lower, term)
        if any(negation in sentence for negation in SAFE_NEGATIONS):
            continue
        if category.replace("_", " ") in observed_terms:
            continue
        warnings.append(f"Potential unsupported claim phrase: {term}")
    return warnings


def sentence_containing(text: str, term: str) -> str:
    index = text.find(term)
    if index < 0:
        return ""
    start = max(text.rfind(".", 0, index), text.rfind("\n", 0, index)) + 1
    end_candidates = [candidate for candidate in [text.find(".", index), text.find("\n", index)] if candidate >= 0]
    end = min(end_candidates) if end_candidates else len(text)
    return text[start:end]


def ordered_unique(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def display_asset(case: dict[str, Any]) -> str:
    title = str(case.get("case_title") or "")
    if " on " in title:
        return title.rsplit(" on ", 1)[-1].strip()
    return str(case.get("primary_asset_id") or "observed asset")


def display_behavior(case: dict[str, Any]) -> str:
    title = str(case.get("case_title") or "").lower()
    family = str(case.get("primary_behavior_family") or "case activity")
    if "vulnerability backlog" in title:
        return "vulnerability backlog telemetry"
    if family == "sca_compliance_backlog":
        return "compliance backlog telemetry"
    if family == "linux_package_management":
        return "package-management telemetry"
    return humanize_behavior(family)


def humanize_behavior(value: str) -> str:
    return value.replace("_", " ").strip()
