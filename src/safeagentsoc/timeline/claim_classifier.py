from __future__ import annotations

from typing import Any


def classify_technique_claim(mapping: dict[str, Any], confidence: dict[str, Any]) -> dict[str, Any]:
    source = str(mapping.get("mapping_source") or "unknown")
    evidence_ids = mapping.get("evidence_ids") or []
    limitations = limitations_for_mapping(mapping, confidence)
    if source == "direct_mitre" and evidence_ids:
        claim_type = "observed"
        reason = "Technique is directly present in enriched runtime alert evidence."
        inference_reason = None
    elif source in {"rule_inferred", "behavior_inferred"} and evidence_ids:
        claim_type = "inferred"
        reason = "Technique is inferred from trusted runtime rule or behavior context."
        inference_reason = "; ".join(mapping.get("mapping_reasons") or [])
    else:
        claim_type = "unknown"
        reason = "No reliable ATT&CK mapping was available for this case evidence."
        inference_reason = None
        limitations.append("Technique could not be mapped from available runtime fields.")
    return {
        "claim_type": claim_type,
        "claim_reason": reason,
        "inference_reason": inference_reason,
        "limitations": limitations,
    }


def limitations_for_mapping(mapping: dict[str, Any], confidence: dict[str, Any]) -> list[str]:
    limitations: list[str] = []
    if mapping.get("duplicate_count", 0) > max(mapping.get("trigger_count", 0) + mapping.get("supporting_count", 0), 1) * 5:
        limitations.append("Duplicate-heavy evidence was collapsed and does not independently strengthen the claim.")
    if confidence.get("confidence_label") in {"low", "weak"}:
        limitations.append("Technique confidence is limited by weak or sparse evidence fields.")
    if set(mapping.get("visibility_levels") or []) <= {"collapsed_duplicate", "collapsed_noise"}:
        limitations.append("Technique appears only in collapsed evidence, not the primary visible analyst view.")
    return limitations

