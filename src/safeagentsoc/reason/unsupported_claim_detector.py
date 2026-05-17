from __future__ import annotations

from typing import Any


FORBIDDEN_CLAIM_PATTERNS = {
    "confirmed compromise": "confirmed compromise",
    "credential dumping occurred": "credential dumping",
    "lateral movement occurred": "lateral movement",
    "data exfiltration occurred": "exfiltration",
    "domain controller compromise": "domain controller compromise",
    "malware downloaded": "malware download",
    "impact confirmed": "impact",
    "command and control established": "command and control",
}


def detect_unsupported_claims(response: dict[str, Any], case_context: dict[str, Any]) -> dict[str, Any]:
    forbidden = [item.lower() for item in (case_context.get("llm_forbidden_claims") or [])]
    observed_terms = {
        str(item.get("tactic") or "").lower()
        for item in (case_context.get("observed_technique_chain") or [])
    }
    rows: list[dict[str, Any]] = []
    for hypothesis in response.get("hypotheses") or []:
        text = stringify(hypothesis).lower()
        unsupported: list[str] = []
        contradicted: list[str] = []
        for pattern, category in FORBIDDEN_CLAIM_PATTERNS.items():
            if pattern in text and category not in observed_terms:
                unsupported.append(pattern)
        for forbidden_claim in forbidden:
            normalized = forbidden_claim.replace("do not claim ", "").split(" without ", 1)[0]
            if normalized and f"{normalized} occurred" in text:
                contradicted.append(normalized)
        rows.append(
            {
                "case_id": response.get("case_id"),
                "hypothesis_id": hypothesis.get("hypothesis_id"),
                "unsupported_claims": unsupported,
                "contradicted_forbidden_claims": contradicted,
                "claim_status": "supported" if not unsupported and not contradicted else "forbidden",
            }
        )
    unsupported_count = sum(len(row["unsupported_claims"]) + len(row["contradicted_forbidden_claims"]) for row in rows)
    return {
        "unsupported_claim_count": unsupported_count,
        "unsupported_claim_rate": round(unsupported_count / max(len(rows), 1), 4),
        "rows": rows,
    }


def stringify(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(stringify(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(stringify(item) for item in value)
    return str(value)

