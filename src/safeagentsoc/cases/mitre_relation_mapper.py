from __future__ import annotations


ADJACENT_TACTICS = {
    ("Execution", "Persistence"),
    ("Execution", "Privilege Escalation"),
    ("Credential Access", "Lateral Movement"),
    ("Discovery", "Lateral Movement"),
}


def normalize_tactic(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").strip().title()


def mitre_relation_score(
    seed_techniques: list[str],
    candidate_techniques: list[str],
    seed_tactics: list[str],
    candidate_tactics: list[str],
) -> tuple[float, list[str]]:
    reasons: list[str] = []
    seed_technique_set = {str(item) for item in seed_techniques if item}
    candidate_technique_set = {str(item) for item in candidate_techniques if item}
    seed_tactic_set = {normalize_tactic(str(item)) for item in seed_tactics if item}
    candidate_tactic_set = {normalize_tactic(str(item)) for item in candidate_tactics if item}

    if seed_technique_set and seed_technique_set & candidate_technique_set:
        reasons.append("same MITRE technique")
        return 1.0, reasons
    if seed_tactic_set and seed_tactic_set & candidate_tactic_set:
        reasons.append("same MITRE tactic")
        return 0.7, reasons
    for left in seed_tactic_set:
        for right in candidate_tactic_set:
            if (left, right) in ADJACENT_TACTICS or (right, left) in ADJACENT_TACTICS:
                reasons.append(f"adjacent MITRE tactics: {left} / {right}")
                return 0.35, reasons
    return 0.0, reasons

