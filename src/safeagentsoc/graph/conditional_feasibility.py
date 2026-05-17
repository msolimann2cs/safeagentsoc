from __future__ import annotations

from dataclasses import asdict
from typing import Any

from safeagentsoc.graph.claim_taxonomy import CRITICAL_CLAIM_TYPES
from safeagentsoc.graph.feasibility_rules import FeasibilityRule, rule_for
from safeagentsoc.graph.graph_explainer import build_claim_explanation, build_hypothesis_explanation
from safeagentsoc.graph.schemas import (
    ClaimEntityResolution,
    ClaimPathValidation,
    GraphValidationResult,
    HypothesisGraphClaim,
)


def classify_claim(
    claim: HypothesisGraphClaim,
    resolution: ClaimEntityResolution,
    path_validation: ClaimPathValidation,
    rules: dict[str, FeasibilityRule] | None = None,
) -> GraphValidationResult:
    rule = rule_for(claim.claim_type, rules)
    score = (
        0.25 * resolution.entity_resolution_score
        + 0.25 * path_validation.path_existence_score
        + 0.20 * path_validation.evidence_alignment_score
        + 0.15 * path_validation.privilege_or_access_score
        + 0.15 * path_validation.network_reachability_score
    )
    score = round(min(max(score, 0.0), 1.0), 4)

    invalid_evidence = [
        item
        for item in resolution.unresolved_entities
        if item.get("entity_type") == "Evidence" or item.get("entity_type") == "evidence_ids"
    ]
    if invalid_evidence or not claim.evidence_ids:
        status = "unsupported"
    elif path_validation.contradictions and claim.claim_type in {"lateral_movement_claim", "network_reachability_claim"}:
        status = "infeasible" if score < rule.conditional_threshold else "conditional"
    elif score >= rule.feasible_threshold and not _has_critical_missing_context(path_validation):
        status = "feasible"
    elif score >= rule.conditional_threshold:
        status = "conditional"
    elif score <= 0.24:
        status = "unsupported"
    elif path_validation.missing_requirements:
        status = "not_enough_graph_context"
    else:
        status = "conditional"

    explanation, facts, missing = build_claim_explanation(claim, resolution, path_validation, status, score)
    return GraphValidationResult(
        case_id=claim.case_id,
        hypothesis_id=claim.hypothesis_id,
        claim_id=claim.claim_id,
        claim_type=claim.claim_type,
        graph_validation_status=status,
        feasibility_score=score,
        graph_explanation=explanation,
        supporting_graph_facts=facts,
        missing_graph_requirements=missing,
        validated_claims=[claim.claim_id] if status == "feasible" else [],
        conditional_claims=[claim.claim_id] if status in {"conditional", "not_enough_graph_context"} else [],
        rejected_claims=[claim.claim_id] if status in {"infeasible", "unsupported"} else [],
        evidence_ids=claim.evidence_ids,
        alert_uids=claim.alert_uids,
        mitre_techniques=claim.techniques,
        decision_ledger_id=claim.decision_ledger_id,
    )


def roll_up_hypotheses(
    claim_results: list[GraphValidationResult],
    hypotheses: dict[tuple[str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[GraphValidationResult]] = {}
    for result in claim_results:
        grouped.setdefault((result.case_id, result.hypothesis_id), []).append(result)

    rollups: list[dict[str, Any]] = []
    for key, results in sorted(grouped.items()):
        case_id, hypothesis_id = key
        status = _rollup_status(results)
        score = round(sum(result.feasibility_score for result in results) / max(len(results), 1), 4)
        hypothesis = hypotheses.get(key, {})
        rollups.append(
            {
                "case_id": case_id,
                "hypothesis_id": hypothesis_id,
                "hypothesis_title": hypothesis.get("title", ""),
                "hypothesis_confidence": hypothesis.get("confidence_score"),
                "graph_validation_status": status,
                "feasibility_score": score,
                "validated_claims": _claim_ids(results, {"feasible"}),
                "conditional_claims": _claim_ids(results, {"conditional", "not_enough_graph_context"}),
                "rejected_claims": _claim_ids(results, {"infeasible", "unsupported"}),
                "missing_graph_evidence": _missing(results),
                "graph_explanation": build_hypothesis_explanation(status, results),
                "evidence_ids": _dedupe([item for result in results for item in result.evidence_ids]),
                "alert_uids": _dedupe([item for result in results for item in result.alert_uids]),
                "mitre_techniques": _dedupe([item for result in results for item in result.mitre_techniques]),
                "decision_ledger_id": hypothesis.get("decision_ledger_id") or _first_ledger(results),
            }
        )
    return rollups


def validation_result_to_dict(result: GraphValidationResult) -> dict[str, Any]:
    return asdict(result)


def _rollup_status(results: list[GraphValidationResult]) -> str:
    if not results:
        return "not_enough_graph_context"
    critical_results = [
        result for result in results if result.claim_type in CRITICAL_CLAIM_TYPES
    ] or results
    statuses = {result.graph_validation_status for result in critical_results}
    if "infeasible" in statuses:
        return "infeasible"
    if statuses and statuses <= {"unsupported"}:
        return "unsupported"
    if "unsupported" in statuses and len(statuses) > 1:
        return "mixed"
    if "not_enough_graph_context" in statuses:
        return "not_enough_graph_context"
    if "conditional" in statuses:
        return "conditional"
    if statuses <= {"feasible"}:
        return "feasible"
    return "mixed"


def _has_critical_missing_context(path_validation: ClaimPathValidation) -> bool:
    critical_missing = {
        "missing_case_local_evidence",
        "missing_source_asset",
        "missing_target_asset",
        "missing_external_destination",
        "missing_exfiltration_technique",
    }
    return any(item in critical_missing for item in path_validation.missing_requirements)


def _claim_ids(results: list[GraphValidationResult], statuses: set[str]) -> list[str]:
    return [result.claim_id for result in results if result.graph_validation_status in statuses]


def _missing(results: list[GraphValidationResult]) -> list[str]:
    return _dedupe([item for result in results for item in result.missing_graph_requirements])


def _first_ledger(results: list[GraphValidationResult]) -> str | None:
    for result in results:
        if result.decision_ledger_id:
            return result.decision_ledger_id
    return None


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
