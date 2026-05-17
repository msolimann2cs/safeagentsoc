from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentPermission:
    agent_id: str
    can_read: tuple[str, ...]
    can_write: tuple[str, ...]
    cannot_read: tuple[str, ...]
    cannot_write: tuple[str, ...]


AGENT_PERMISSIONS: dict[str, AgentPermission] = {
    "hypothesis_generator": AgentPermission(
        agent_id="hypothesis_generator",
        can_read=("case_llm_context_pack", "hypothesis_schema", "prompt_templates"),
        can_write=("case_llm_prompt_pack", "raw_hypotheses"),
        cannot_read=("ground_truth", "casebook", "scenario_labels", "gold_links"),
        cannot_write=("response_actions", "validated_hypotheses", "decision_ledger"),
    ),
    "schema_validator": AgentPermission(
        agent_id="schema_validator",
        can_read=("raw_hypotheses", "hypothesis_schema"),
        can_write=("validation_report", "invalid_hypothesis_outputs"),
        cannot_read=("ground_truth", "casebook"),
        cannot_write=("response_actions",),
    ),
    "evidence_verifier": AgentPermission(
        agent_id="evidence_verifier",
        can_read=("raw_hypotheses", "case_llm_context_pack", "case_evidence"),
        can_write=("evidence_support_report",),
        cannot_read=("ground_truth", "casebook"),
        cannot_write=("response_actions",),
    ),
    "claim_linter": AgentPermission(
        agent_id="claim_linter",
        can_read=("raw_hypotheses", "case_llm_context_pack"),
        can_write=("unsupported_claim_report",),
        cannot_read=("ground_truth", "casebook"),
        cannot_write=("response_actions",),
    ),
    "prompt_injection_tester": AgentPermission(
        agent_id="prompt_injection_tester",
        can_read=("prompt_injection_tests", "prompt_templates", "hypothesis_schema"),
        can_write=("agent_security_report",),
        cannot_read=("ground_truth", "casebook"),
        cannot_write=("response_actions",),
    ),
    "decision_ledger_writer": AgentPermission(
        agent_id="decision_ledger_writer",
        can_read=("raw_hypotheses", "validated_hypotheses", "validation_report", "evidence_support_report"),
        can_write=("decision_ledger",),
        cannot_read=("ground_truth", "casebook"),
        cannot_write=("response_actions",),
    ),
}


def get_agent_permission(agent_id: str) -> AgentPermission:
    if agent_id not in AGENT_PERMISSIONS:
        raise KeyError(f"Unknown agent identity: {agent_id}")
    return AGENT_PERMISSIONS[agent_id]

