from __future__ import annotations

from typing import Any


def verify_evidence(response: dict[str, Any], case_context: dict[str, Any]) -> dict[str, Any]:
    valid_evidence = case_evidence_ids(case_context)
    valid_alerts = case_alert_uids(case_context)
    valid_techniques = {
        item.get("technique_id")
        for item in (case_context.get("observed_technique_chain") or [])
        if item.get("technique_id")
    } | {
        item.get("technique_id")
        for item in (case_context.get("inferred_relationships") or [])
        if item.get("technique_id")
    }
    rows: list[dict[str, Any]] = []
    total_checks = 0
    passed_checks = 0
    for hypothesis in response.get("hypotheses") or []:
        evidence_ids = set(hypothesis.get("supporting_evidence_ids") or [])
        alert_uids = set(hypothesis.get("supporting_alert_uids") or [])
        techniques = set(hypothesis.get("mitre_techniques") or [])
        mapping_techniques = {
            item.get("technique_id")
            for item in hypothesis.get("mitre_tactic_mappings") or []
            if isinstance(item, dict) and item.get("technique_id")
        }
        invalid_evidence = sorted(evidence_ids - valid_evidence)
        invalid_alerts = sorted(alert_uids - valid_alerts) if alert_uids else []
        unsupported_techniques = sorted((techniques | mapping_techniques) - valid_techniques) if (techniques or mapping_techniques) else []
        checks = [
            not invalid_evidence,
            not invalid_alerts,
            not unsupported_techniques,
            bool(evidence_ids),
        ]
        total_checks += len(checks)
        passed_checks += sum(1 for item in checks if item)
        rows.append(
            {
                "case_id": response.get("case_id"),
                "hypothesis_id": hypothesis.get("hypothesis_id"),
                "invalid_evidence_ids": invalid_evidence,
                "invalid_alert_uids": invalid_alerts,
                "unsupported_techniques": unsupported_techniques,
                "evidence_supported": all(checks),
            }
        )
    rate = round(passed_checks / total_checks, 4) if total_checks else 0.0
    return {
        "evidence_validation_status": "passed" if all(row["evidence_supported"] for row in rows) else "failed",
        "evidence_support_rate": rate,
        "rows": rows,
    }


def sanitize_case_citations(response: dict[str, Any], case_context: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    valid_evidence = case_evidence_ids(case_context)
    valid_alerts = case_alert_uids(case_context)
    repaired = {**response, "hypotheses": []}
    repair_rows: list[dict[str, Any]] = []
    for hypothesis in response.get("hypotheses") or []:
        if not isinstance(hypothesis, dict):
            continue
        original_evidence = list(hypothesis.get("supporting_evidence_ids") or [])
        original_alerts = list(hypothesis.get("supporting_alert_uids") or [])
        kept_evidence = [item for item in original_evidence if item in valid_evidence]
        kept_alerts = [item for item in original_alerts if item in valid_alerts]
        clean_hypothesis = {
            **hypothesis,
            "supporting_evidence_ids": kept_evidence,
            "supporting_alert_uids": kept_alerts,
        }
        repaired["hypotheses"].append(clean_hypothesis)
        removed_evidence = sorted(set(original_evidence) - set(kept_evidence))
        removed_alerts = sorted(set(original_alerts) - set(kept_alerts))
        if removed_evidence or removed_alerts:
            repair_rows.append(
                {
                    "case_id": response.get("case_id"),
                    "hypothesis_id": hypothesis.get("hypothesis_id"),
                    "removed_invalid_evidence_ids": removed_evidence,
                    "removed_invalid_alert_uids": removed_alerts,
                    "repair_action": "removed_non_case_local_citations",
                }
            )
    return repaired, repair_rows


def case_evidence_ids(case_context: dict[str, Any]) -> set[str]:
    evidence_ids = set(case_context.get("evidence_ids") or [])
    for step in case_context.get("observed_timeline", []):
        evidence_ids.update(step.get("evidence_ids") or [])
    return evidence_ids


def case_alert_uids(case_context: dict[str, Any]) -> set[str]:
    return {
        alert_uid
        for step in case_context.get("observed_timeline", [])
        for alert_uid in (step.get("alert_uids") or [])
    }
