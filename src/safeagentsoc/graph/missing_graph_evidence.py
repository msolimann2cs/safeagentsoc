from __future__ import annotations

from dataclasses import asdict
from typing import Any

from safeagentsoc.graph.schemas import GraphValidationResult, MissingGraphEvidence


REASON_BY_TYPE = {
    "missing_source_asset": "No source asset node or source asset relationship was resolved for the claim.",
    "missing_target_asset": "No target asset node or target asset relationship was resolved for the claim.",
    "missing_asset_or_host": "No case-local asset or host node was resolved for the claim.",
    "missing_identity": "No identity node was resolved for the claim.",
    "missing_identity_access_edge": "No IDENTITY_CAN_LOGIN_TO_ASSET edge supports identity access to the modeled asset.",
    "missing_privilege_edge": "No IDENTITY_HAS_PRIVILEGE_ON_ASSET edge supports the privilege assertion.",
    "missing_network_zone": "No network zone node was resolved for the relevant asset or host.",
    "missing_network_reachability_edge": "No NETWORK_ZONE_CAN_REACH_ZONE edge supports source-to-target reachability.",
    "missing_external_destination": "No external destination IP or destination network node was resolved.",
    "missing_process_node": "No process node was resolved from the cited alert evidence.",
    "missing_file_node": "No file node was resolved from the cited alert evidence.",
    "missing_technique_mapping": "No MITRE technique node was resolved for the claim.",
    "missing_cross_host_sequence": "No cross-host alert/evidence sequence was resolved for the claim.",
    "missing_case_local_evidence": "No case-local evidence node supports the claim.",
    "missing_exfiltration_technique": "No exfiltration technique or rule was resolved for the claim.",
    "missing_remote_service_or_lateral_movement_technique": "No remote-service or lateral-movement technique was resolved for the claim.",
}


def build_missing_graph_evidence(
    validation_results: list[GraphValidationResult],
) -> list[MissingGraphEvidence]:
    rows: list[MissingGraphEvidence] = []
    for result in validation_results:
        for index, missing_type in enumerate(result.missing_graph_requirements, start=1):
            rows.append(
                MissingGraphEvidence(
                    case_id=result.case_id,
                    hypothesis_id=result.hypothesis_id,
                    claim_id=result.claim_id,
                    missing_type=missing_type,
                    reason=REASON_BY_TYPE.get(missing_type, f"Missing graph context: {missing_type}."),
                    effect=_effect(result.graph_validation_status),
                )
            )
    return rows


def missing_graph_evidence_to_dict(row: MissingGraphEvidence) -> dict[str, Any]:
    return asdict(row)


def _effect(status: str) -> str:
    if status == "feasible":
        return "not material to the final feasible status"
    if status == "conditional":
        return "downgrades the claim to conditional"
    if status == "not_enough_graph_context":
        return "prevents a structural decision"
    if status == "infeasible":
        return "contributes to graph rejection"
    return "contributes to unsupported classification"
