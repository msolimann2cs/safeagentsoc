from __future__ import annotations

from dataclasses import asdict
from typing import Any

from safeagentsoc.graph.graph_builder import GraphBuildResult
from safeagentsoc.graph.schemas import ClaimEntityResolution, ClaimPathValidation, HypothesisGraphClaim


TECHNIQUE_REQUIRED_CLAIMS = {
    "execution_claim",
    "persistence_claim",
    "privilege_claim",
    "credential_access_claim",
    "lateral_movement_claim",
    "defense_evasion_claim",
    "exfiltration_claim",
    "impact_claim",
    "technique_claim",
}


def validate_claim_path(
    claim: HypothesisGraphClaim,
    resolution: ClaimEntityResolution,
    build_result: GraphBuildResult,
) -> ClaimPathValidation:
    entities = resolution.resolved_entities
    missing: list[str] = []
    contradictions: list[str] = []
    supporting_paths: list[list[str]] = []

    evidence_alignment = _evidence_alignment_score(claim, entities, build_result, missing)
    path_score = _base_path_score(claim, entities, missing)
    privilege_score = _privilege_or_access_score(claim, entities, build_result, missing)
    reachability_score = _network_reachability_score(claim, entities, build_result, missing, contradictions)

    if claim.claim_type == "lateral_movement_claim":
        path_score = _lateral_movement_path_score(claim, entities, build_result, missing, contradictions, supporting_paths)
    elif claim.claim_type == "network_reachability_claim":
        path_score = max(path_score, reachability_score)
    elif claim.claim_type == "exfiltration_claim":
        path_score = _exfiltration_path_score(claim, entities, missing)
    elif claim.claim_type == "telemetry_backlog_claim":
        path_score = max(path_score, evidence_alignment)

    for evidence_id in entities.get("evidence_ids", []):
        for alert_uid in entities.get("alert_uids", []):
            source = f"Evidence:{evidence_id}"
            target = f"Alert:{alert_uid}"
            if build_result.graph.has_typed_path(source, target, {"EVIDENCE_FROM_ALERT"}, max_depth=1):
                supporting_paths.append([source, target])

    return ClaimPathValidation(
        case_id=claim.case_id,
        hypothesis_id=claim.hypothesis_id,
        claim_id=claim.claim_id,
        path_exists=path_score >= 0.5,
        path_existence_score=round(min(path_score, 1.0), 4),
        evidence_alignment_score=round(evidence_alignment, 4),
        privilege_or_access_score=round(privilege_score, 4),
        network_reachability_score=round(reachability_score, 4),
        supporting_paths=supporting_paths[:5],
        missing_requirements=_dedupe(missing),
        contradictions=_dedupe(contradictions),
    )


def path_validation_to_dict(path_validation: ClaimPathValidation) -> dict[str, Any]:
    return asdict(path_validation)


def _evidence_alignment_score(
    claim: HypothesisGraphClaim,
    entities: dict[str, list[str]],
    build_result: GraphBuildResult,
    missing: list[str],
) -> float:
    evidence_ids = entities.get("evidence_ids", [])
    alert_uids = entities.get("alert_uids", [])
    if not claim.evidence_ids:
        missing.append("missing_case_local_evidence")
        return 0.0
    if not evidence_ids:
        missing.append("missing_case_local_evidence")
        return 0.0
    if not alert_uids:
        missing.append("missing_alert_uid")
        return 0.6
    mapped_count = 0
    for evidence_id in evidence_ids:
        mapped_alert = build_result.evidence_to_alert.get(evidence_id)
        if mapped_alert in alert_uids:
            mapped_count += 1
    return max(0.6, mapped_count / max(len(evidence_ids), 1))


def _base_path_score(
    claim: HypothesisGraphClaim,
    entities: dict[str, list[str]],
    missing: list[str],
) -> float:
    score = 0.0
    if entities.get("evidence_ids"):
        score += 0.3
    else:
        missing.append("missing_case_local_evidence")
    if entities.get("alert_uids"):
        score += 0.2
    else:
        missing.append("missing_alert_uid")
    if entities.get("assets") or entities.get("hosts"):
        score += 0.25
    else:
        missing.append("missing_asset_or_host")
    if claim.claim_type in TECHNIQUE_REQUIRED_CLAIMS:
        if entities.get("techniques"):
            score += 0.25
        else:
            missing.append("missing_technique_mapping")
    else:
        score += 0.25
    return score


def _privilege_or_access_score(
    claim: HypothesisGraphClaim,
    entities: dict[str, list[str]],
    build_result: GraphBuildResult,
    missing: list[str],
) -> float:
    if claim.claim_type not in {"identity_claim", "privilege_claim", "credential_access_claim", "lateral_movement_claim"}:
        return 0.5 if entities.get("identities") else 0.25
    identities = entities.get("identities", [])
    assets = entities.get("assets", [])
    if not identities:
        missing.append("missing_identity")
        return 0.0
    if not assets:
        missing.append("missing_target_asset")
        return 0.25
    has_login = False
    has_privilege = False
    for identity_id in identities:
        for asset_id in assets:
            if build_result.graph.has_edge(f"Identity:{identity_id}", f"Asset:{asset_id}", "IDENTITY_CAN_LOGIN_TO_ASSET"):
                has_login = True
            if build_result.graph.has_edge(f"Identity:{identity_id}", f"Asset:{asset_id}", "IDENTITY_HAS_PRIVILEGE_ON_ASSET"):
                has_privilege = True
    if claim.claim_type == "privilege_claim":
        if has_privilege:
            return 1.0
        missing.append("missing_privilege_edge")
        return 0.55 if has_login else 0.25
    if has_login or has_privilege:
        return 1.0 if has_privilege else 0.75
    missing.append("missing_identity_access_edge")
    return 0.35


def _network_reachability_score(
    claim: HypothesisGraphClaim,
    entities: dict[str, list[str]],
    build_result: GraphBuildResult,
    missing: list[str],
    contradictions: list[str],
) -> float:
    zones = entities.get("network_zones", [])
    if claim.claim_type not in {"lateral_movement_claim", "network_reachability_claim", "exfiltration_claim"}:
        return 0.5 if zones else 0.25
    if not zones:
        missing.append("missing_network_zone")
        return 0.0
    if claim.claim_type == "exfiltration_claim":
        if entities.get("ip_addresses"):
            return 0.75
        missing.append("missing_external_destination")
        return 0.1
    if len(zones) == 1:
        return 0.45
    reachable = False
    for source_zone in zones:
        for target_zone in zones:
            if source_zone == target_zone:
                continue
            if build_result.graph.has_edge(
                f"NetworkZone:{source_zone}",
                f"NetworkZone:{target_zone}",
                "NETWORK_ZONE_CAN_REACH_ZONE",
            ):
                reachable = True
    if reachable:
        return 1.0
    contradictions.append("network_zone_reachability_not_modeled_or_denied")
    return 0.15


def _lateral_movement_path_score(
    claim: HypothesisGraphClaim,
    entities: dict[str, list[str]],
    build_result: GraphBuildResult,
    missing: list[str],
    contradictions: list[str],
    supporting_paths: list[list[str]],
) -> float:
    assets = entities.get("assets", [])
    techniques = [tech for tech in entities.get("techniques", []) if tech.startswith("T1021")]
    if not techniques:
        missing.append("missing_remote_service_or_lateral_movement_technique")
    if len(assets) < 2:
        missing.append("missing_cross_host_sequence")
        return 0.42 if techniques and entities.get("evidence_ids") else 0.25

    zone_score = _network_reachability_score(claim, entities, build_result, missing, contradictions)
    access_score = _privilege_or_access_score(claim, entities, build_result, missing)
    if zone_score >= 0.75 and access_score >= 0.75 and techniques:
        source = f"Asset:{assets[0]}"
        target = f"Asset:{assets[1]}"
        supporting_paths.append([source, target])
        return 0.9
    return max(0.45, 0.35 + (0.2 if techniques else 0) + (0.2 if zone_score >= 0.5 else 0))


def _exfiltration_path_score(
    claim: HypothesisGraphClaim,
    entities: dict[str, list[str]],
    missing: list[str],
) -> float:
    techniques = set(entities.get("techniques", []))
    has_exfil_technique = any(tech.startswith("T1041") or tech.startswith("T1567") for tech in techniques)
    if not has_exfil_technique:
        missing.append("missing_exfiltration_technique")
    if not entities.get("ip_addresses"):
        missing.append("missing_external_destination")
    if has_exfil_technique and entities.get("ip_addresses") and entities.get("evidence_ids"):
        return 0.85
    return 0.18 if not has_exfil_technique else 0.45


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
