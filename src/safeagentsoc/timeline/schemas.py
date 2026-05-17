from __future__ import annotations

from dataclasses import dataclass
from typing import Any


CLAIM_TYPES = {"observed", "inferred", "not_observed", "unknown"}
CONFIDENCE_LABELS = {"high", "medium", "low", "weak"}
MAPPING_SOURCES = {"direct_mitre", "rule_inferred", "behavior_inferred", "unknown"}


@dataclass(frozen=True)
class TimelineBuildResult:
    timelines: list[dict[str, Any]]
    timeline_steps: list[dict[str, Any]]
    technique_claims: list[dict[str, Any]]
    missing_evidence: list[dict[str, Any]]
    attack_stories: list[dict[str, Any]]
    kill_chain_progression: list[dict[str, Any]]
    mitre_coverage_matrix: list[dict[str, Any]]
    mitre_heatmap_by_case: list[dict[str, Any]]
    mitre_tactic_summary: list[dict[str, Any]]
    navigator_layer: dict[str, Any]
    llm_context_pack: list[dict[str, Any]]
    unsupported_claim_report: list[dict[str, Any]]
    quality_metrics: dict[str, Any]

