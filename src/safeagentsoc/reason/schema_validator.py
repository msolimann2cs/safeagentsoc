from __future__ import annotations

from typing import Any

from safeagentsoc.reason.recommended_checks import FORBIDDEN_ACTIONS


FORBIDDEN_RUNTIME_FIELDS = {
    "ground_truth",
    "expected_conclusion",
    "casebook_answer",
    "true_positive",
    "false_positive",
    "event_role",
    "scenario_label",
    "gold_label",
    "answer_key",
}

REQUIRED_HYPOTHESIS_FIELDS = {
    "hypothesis_id",
    "title",
    "description",
    "claim_type",
    "confidence_score",
    "confidence_label",
    "supporting_evidence_ids",
    "supporting_alert_uids",
    "mitre_techniques",
    "mitre_tactic_mappings",
    "observed_facts",
    "inferred_facts",
    "missing_evidence",
    "recommended_checks",
    "forbidden_claims_respected",
    "limitations",
}


def validate_hypothesis_response(response: Any, case_context: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(response, dict):
        return validation_result(False, ["Output is not a JSON object."])
    if contains_forbidden_field(response):
        errors.append("Output contains forbidden runtime/evaluation field names.")
    if response.get("case_id") != case_context.get("case_id"):
        errors.append("case_id does not match prompt case.")
    hypotheses = response.get("hypotheses")
    if not isinstance(hypotheses, list):
        errors.append("hypotheses must be a list.")
        hypotheses = []
    if not (2 <= len(hypotheses) <= 4):
        errors.append("hypotheses must contain 2 to 4 items.")
    seen_ids: set[str] = set()
    for index, hypothesis in enumerate(hypotheses, start=1):
        if not isinstance(hypothesis, dict):
            errors.append(f"hypothesis {index} is not an object.")
            continue
        missing = REQUIRED_HYPOTHESIS_FIELDS - set(hypothesis)
        if missing:
            errors.append(f"hypothesis {index} missing fields: {', '.join(sorted(missing))}.")
        hypothesis_id = str(hypothesis.get("hypothesis_id") or "")
        if not hypothesis_id:
            errors.append(f"hypothesis {index} missing hypothesis_id.")
        if hypothesis_id in seen_ids:
            errors.append(f"duplicate hypothesis_id: {hypothesis_id}.")
        seen_ids.add(hypothesis_id)
        confidence = hypothesis.get("confidence_score")
        if not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
            errors.append(f"hypothesis {hypothesis_id or index} confidence_score must be 0..1.")
        if isinstance(confidence, (int, float)) and confidence_label(float(confidence)) != hypothesis.get("confidence_label"):
            errors.append(f"hypothesis {hypothesis_id or index} confidence_label does not match score.")
        if not hypothesis.get("supporting_evidence_ids"):
            errors.append(f"hypothesis {hypothesis_id or index} must cite evidence IDs.")
        if not hypothesis.get("missing_evidence"):
            errors.append(f"hypothesis {hypothesis_id or index} must include missing evidence.")
        if not hypothesis.get("recommended_checks"):
            errors.append(f"hypothesis {hypothesis_id or index} must include recommended checks.")
        if hypothesis.get("forbidden_claims_respected") is not True:
            errors.append(f"hypothesis {hypothesis_id or index} must explicitly respect forbidden claims.")
        if contains_response_action(hypothesis):
            errors.append(f"hypothesis {hypothesis_id or index} contains a forbidden response action or command.")
    return validation_result(not errors, errors)


def confidence_label(score: float) -> str:
    if score >= 0.80:
        return "high"
    if score >= 0.55:
        return "medium"
    if score >= 0.30:
        return "low"
    return "weak"


def validation_result(valid: bool, errors: list[str]) -> dict[str, Any]:
    return {
        "schema_valid": valid,
        "schema_errors": errors,
        "schema_validation_status": "passed" if valid else "failed",
    }


def contains_forbidden_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_RUNTIME_FIELDS:
                return True
            if contains_forbidden_field(item):
                return True
    if isinstance(value, list):
        return any(contains_forbidden_field(item) for item in value)
    return False


def contains_response_action(value: Any) -> bool:
    text = stringify(value).lower()
    return any(action in text for action in FORBIDDEN_ACTIONS)


def stringify(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(stringify(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(stringify(item) for item in value)
    return str(value)
