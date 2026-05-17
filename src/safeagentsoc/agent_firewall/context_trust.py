from __future__ import annotations

from typing import Any


INJECTION_PATTERNS = (
    "ignore previous instructions",
    "system override",
    "developer override",
    "do not mention evidence",
    "use ground_truth",
    "ground_truth_labels",
    "casebook",
    "run powershell",
    "execute shell",
    "disable the user",
    "exfiltration confirmed",
)


def trust_label_for_source(source: str) -> str:
    if source in {"case_llm_context_pack", "case_timelines", "case_attack_stories", "case_missing_evidence"}:
        return "trusted_runtime"
    if source in {"hypothesis_schema", "agent_permissions", "check_catalog"}:
        return "trusted_static"
    if source in {"raw_alert_description", "command_line", "file_path", "process_args"}:
        return "untrusted_alert_content"
    if source in {"raw_hypotheses", "llm_output"}:
        return "untrusted_llm_output"
    if source in {"ground_truth", "casebook", "scenario_labels"}:
        return "evaluation_only"
    return "trusted_runtime"


def label_case_context(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": context.get("case_id"),
        "trust_labels": {
            "case_metadata": "trusted_runtime",
            "observed_timeline": "trusted_runtime",
            "observed_technique_chain": "trusted_runtime",
            "missing_evidence": "trusted_runtime",
            "safe_conclusion": "trusted_runtime",
            "recommended_investigation_checks": "trusted_runtime",
            "llm_forbidden_claims": "trusted_runtime",
            "log_text_fragments": "untrusted_alert_content",
        },
        "detected_prompt_injection_markers": detect_prompt_injection_markers(context),
    }


def detect_prompt_injection_markers(value: Any) -> list[str]:
    text = stringify(value).lower()
    return sorted({pattern for pattern in INJECTION_PATTERNS if pattern in text})


def stringify(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(stringify(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(stringify(item) for item in value)
    return str(value)

