from __future__ import annotations

from typing import Any

from safeagentsoc.graph.claim_taxonomy import claim_types_for_technique, claim_types_for_text
from safeagentsoc.graph.schemas import HypothesisGraphClaim


def extract_claims_from_records(records: list[dict[str, Any]]) -> list[HypothesisGraphClaim]:
    claims: list[HypothesisGraphClaim] = []
    for record in records:
        if record.get("validation_status") != "passed":
            continue
        case_id = str(record.get("case_id"))
        for hypothesis in record.get("hypotheses") or []:
            claims.extend(extract_hypothesis_claims(case_id, hypothesis))
    return claims


def extract_hypothesis_claims(case_id: str, hypothesis: dict[str, Any]) -> list[HypothesisGraphClaim]:
    hypothesis_id = str(hypothesis.get("hypothesis_id") or "hypothesis")
    evidence_ids = dedupe([str(item) for item in hypothesis.get("supporting_evidence_ids") or [] if item])
    alert_uids = dedupe([str(item) for item in hypothesis.get("supporting_alert_uids") or [] if item])
    techniques = dedupe([str(item) for item in hypothesis.get("mitre_techniques") or [] if item])
    for mapping in hypothesis.get("mitre_tactic_mappings") or []:
        if isinstance(mapping, dict) and mapping.get("technique_id"):
            techniques = dedupe(techniques + [str(mapping["technique_id"])])
    text_parts = [
        hypothesis.get("title") or "",
        hypothesis.get("description") or "",
        " ".join(str(item) for item in hypothesis.get("observed_facts") or []),
        " ".join(str(item) for item in hypothesis.get("inferred_facts") or []),
        " ".join(str(item.get("missing_evidence_type") or "") for item in hypothesis.get("missing_evidence") or [] if isinstance(item, dict)),
    ]
    text = " ".join(text_parts)
    claim_specs: list[tuple[str, str, str, list[str], bool]] = []
    for technique_id in techniques:
        for info in claim_types_for_technique(technique_id):
            claim_specs.append((info.claim_type, info.reason, text, [technique_id], info.critical))
    for info in claim_types_for_text(text):
        claim_specs.append((info.claim_type, info.reason, text, techniques, info.critical))
    if not claim_specs:
        claim_specs.append(("technique_claim", "fallback:no_specific_claim", text, techniques, False))
    claims: list[HypothesisGraphClaim] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for index, (claim_type, source, claim_text, claim_techniques, critical) in enumerate(claim_specs, start=1):
        key = (claim_type, tuple(sorted(claim_techniques)))
        if key in seen:
            continue
        seen.add(key)
        claims.append(
            HypothesisGraphClaim(
                claim_id=f"{case_id}|{hypothesis_id}|claim_{len(claims) + 1:04d}",
                case_id=case_id,
                hypothesis_id=hypothesis_id,
                claim_type=claim_type,
                claim_text=clean_claim_text(claim_text),
                techniques=dedupe(claim_techniques),
                evidence_ids=evidence_ids,
                alert_uids=alert_uids,
                claim_source=source,
                critical=critical,
            )
        )
    return claims


def clean_claim_text(text: str) -> str:
    compact = " ".join(str(text).split())
    return compact[:600] if compact else "Graph-checkable hypothesis claim."


def dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))

