from __future__ import annotations

from safeagentsoc.graph.schemas import ClaimEntityResolution, ClaimPathValidation, GraphValidationResult, HypothesisGraphClaim


def build_claim_explanation(
    claim: HypothesisGraphClaim,
    resolution: ClaimEntityResolution,
    path_validation: ClaimPathValidation,
    status: str,
    score: float,
) -> tuple[str, list[str], list[str]]:
    entities = resolution.resolved_entities
    facts: list[str] = []
    if entities.get("evidence_ids"):
        facts.append(f"{len(entities['evidence_ids'])} cited evidence ID(s) resolved inside the case graph.")
    if entities.get("alert_uids"):
        facts.append(f"{len(entities['alert_uids'])} cited alert UID(s) resolved inside the case graph.")
    if entities.get("assets"):
        facts.append(f"Resolved asset context: {', '.join(entities['assets'][:4])}.")
    if entities.get("hosts"):
        facts.append(f"Resolved host context: {', '.join(entities['hosts'][:4])}.")
    if entities.get("identities"):
        facts.append(f"Resolved identity context: {', '.join(entities['identities'][:4])}.")
    if entities.get("techniques"):
        facts.append(f"Resolved MITRE technique context: {', '.join(entities['techniques'][:6])}.")

    missing = list(path_validation.missing_requirements)
    if not missing and resolution.unresolved_entities:
        missing = [str(item.get("reason")) for item in resolution.unresolved_entities if item.get("reason")]

    if status == "feasible":
        explanation = (
            f"Feasible: the {claim.claim_type} is structurally supported by case-local evidence, "
            f"resolved entities, and typed graph relationships. Graph feasibility score: {score:.2f}."
        )
    elif status == "conditional":
        explanation = (
            f"Conditional: the {claim.claim_type} has case-local evidence and partial graph support, "
            "but important graph context is missing. Analyst validation is required before it can drive risk or response."
        )
    elif status == "infeasible":
        explanation = (
            f"Infeasible: the {claim.claim_type} conflicts with the modeled graph relationships or lacks a required typed path. "
            "This does not prove benign activity; it prevents the hypothesis from being treated as structurally supported."
        )
    elif status == "unsupported":
        explanation = (
            f"Unsupported: the {claim.claim_type} does not have enough case-local evidence or graph basis to support the claim."
        )
    else:
        explanation = (
            f"Not enough graph context: the {claim.claim_type} cannot be decided because required graph context is absent."
        )

    return explanation, facts, missing


def build_hypothesis_explanation(
    status: str,
    claim_results: list[GraphValidationResult],
) -> str:
    total = len(claim_results)
    counts: dict[str, int] = {}
    for result in claim_results:
        counts[result.graph_validation_status] = counts.get(result.graph_validation_status, 0) + 1
    count_text = ", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "no claims"
    return (
        f"Graph validation status is {status}. SafeAgentSOC evaluated {total} extracted claim(s) "
        f"({count_text}). This is a structural feasibility decision, not confirmation of compromise."
    )
