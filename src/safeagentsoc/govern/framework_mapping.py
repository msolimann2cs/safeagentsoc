from __future__ import annotations

from safeagentsoc.govern.schemas import FrameworkMapping, IncidentRiskScore, SafeRecommendation


def build_framework_mappings(risk: IncidentRiskScore, recommendations: list[SafeRecommendation]) -> list[FrameworkMapping]:
    outputs = ["risk score", "uncertainty", "policy decision", "recommendation", "decision ledger"]
    action_outputs = [rec.recommended_action_id for rec in recommendations[:5]]
    return [
        FrameworkMapping(
            mapping_id=f"{risk.case_id}|nist_csf|govern",
            case_id=risk.case_id,
            framework="NIST CSF 2.0",
            function_or_domain="Govern",
            mapped_outputs=["approval matrix", "policy engine", "risk ownership"] + action_outputs,
            evidence=risk.evidence_ids[:5],
        ),
        FrameworkMapping(
            mapping_id=f"{risk.case_id}|nist_csf|respond",
            case_id=risk.case_id,
            framework="NIST CSF 2.0",
            function_or_domain="Respond",
            mapped_outputs=["CSIRT pack", "safe recommendations", "SOAR dry-run"],
            evidence=risk.evidence_ids[:5],
        ),
        FrameworkMapping(
            mapping_id=f"{risk.case_id}|nist_ai_rmf|manage",
            case_id=risk.case_id,
            framework="NIST AI RMF",
            function_or_domain="Manage",
            mapped_outputs=["blocked actions", "human approval", "decision traceability"],
            evidence=risk.evidence_ids[:5],
        ),
        FrameworkMapping(
            mapping_id=f"{risk.case_id}|first_csirt|coordination",
            case_id=risk.case_id,
            framework="FIRST CSIRT Services Framework",
            function_or_domain="Incident Management",
            mapped_outputs=["incident summary", "scope", "containment options", "communications status"],
            evidence=risk.evidence_ids[:5],
        ),
        FrameworkMapping(
            mapping_id=f"{risk.case_id}|internal_policy|governance",
            case_id=risk.case_id,
            framework="Internal Policy Catalog",
            function_or_domain="Response Governance",
            mapped_outputs=outputs,
            evidence=risk.evidence_ids[:5],
        ),
    ]
