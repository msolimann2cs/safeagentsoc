from __future__ import annotations

from safeagentsoc.govern.schemas import BusinessImpactAssessment, CisoDecisionBrief, IncidentRiskScore, StakeholderMessage, UncertaintyAssessment


AUDIENCES = {
    "soc_analyst": ("internal", False),
    "soc_lead": ("internal", False),
    "csirt_lead": ("restricted", False),
    "ciso": ("restricted", False),
    "legal_privacy": ("restricted", True),
    "it_ops": ("internal", False),
    "business_owner": ("internal", True),
    "employee_advisory": ("internal_draft", True),
    "public_customer": ("external_draft", True),
}
FORBIDDEN_PUBLIC = ["confirmed breach", "confirmed exfiltration", "customer data impact", "attribution"]


def build_stakeholder_messages(
    risk: IncidentRiskScore,
    uncertainty: UncertaintyAssessment,
    business: BusinessImpactAssessment,
    brief: CisoDecisionBrief | None = None,
) -> list[StakeholderMessage]:
    messages: list[StakeholderMessage] = []
    for audience, (classification, approval_required) in AUDIENCES.items():
        messages.append(
            StakeholderMessage(
                message_id=f"{risk.case_id}|{audience}|message",
                case_id=risk.case_id,
                audience=audience,
                classification=classification,
                approval_required=approval_required,
                allowed_claims=["evidence-linked case", risk.graph_feasibility_status, risk.risk_label],
                forbidden_claims=FORBIDDEN_PUBLIC if approval_required else ["unsupported compromise claim"],
                evidence_basis=risk.evidence_ids[:8],
                uncertainty=uncertainty.uncertainty_label,
                message=_message_for(audience, risk, uncertainty, business),
            )
        )
    return messages


def lint_messages(messages: list[StakeholderMessage]) -> list[dict[str, str]]:
    findings = []
    unsafe_terms = ["confirmed compromise", "confirmed breach", "exfiltration confirmed", "customer data impacted"]
    for message in messages:
        lowered = message.message.lower()
        for term in unsafe_terms:
            if term in lowered:
                findings.append({"case_id": message.case_id, "message_id": message.message_id, "unsafe_term": term})
    return findings


def _message_for(audience: str, risk: IncidentRiskScore, uncertainty: UncertaintyAssessment, business: BusinessImpactAssessment) -> str:
    if audience == "soc_analyst":
        return f"Review cited evidence for {risk.case_id}, focusing on host, identity, command line, and related alerts. Do not claim compromise beyond the evidence."
    if audience == "soc_lead":
        return f"{risk.case_id} is {risk.risk_label} risk with {uncertainty.uncertainty_label} uncertainty. Assign Tier 2 validation and track blocked or approval-gated actions."
    if audience == "csirt_lead":
        return f"{risk.case_id} may require CSIRT coordination if validation confirms scope expansion. Current graph status is {risk.graph_feasibility_status}."
    if audience == "ciso":
        return f"{risk.case_id} affects {business.business_service or 'a business service'} with {risk.risk_label} risk and {uncertainty.uncertainty_label} uncertainty. High-impact containment remains policy constrained."
    if audience == "legal_privacy":
        return f"{risk.case_id} has no approved conclusion of data exposure. Preserve evidence and review whether any regulatory or privacy triggers emerge."
    if audience == "it_ops":
        return f"Validate operational impact for {business.affected_asset or 'the affected asset'} before any containment or change action."
    if audience == "business_owner":
        return f"A security case may affect {business.business_service or 'your service'}. No disruptive action is approved without business-impact review."
    if audience == "employee_advisory":
        return "Draft only: security teams are reviewing activity and may request validation steps. No confirmed impact statement is approved."
    return "Draft only: we are investigating a cybersecurity event and assessing scope and impact. There is currently no approved evidence statement of customer data impact."
