from __future__ import annotations

from dataclasses import asdict
from typing import Any

from safeagentsoc.graph.graph_builder import GraphBuildResult
from safeagentsoc.graph.schemas import ClaimEntityResolution, HypothesisGraphClaim


IDENTITY_SENSITIVE_CLAIMS = {
    "identity_claim",
    "privilege_claim",
    "credential_access_claim",
    "lateral_movement_claim",
}


def resolve_claim_entities(
    claim: HypothesisGraphClaim,
    build_result: GraphBuildResult,
) -> ClaimEntityResolution:
    """Resolve a graph-checkable claim back to case-local runtime entities."""
    resolved: dict[str, list[str]] = {
        "evidence_ids": [],
        "alert_uids": [],
        "assets": [],
        "hosts": [],
        "identities": [],
        "users": [],
        "network_zones": [],
        "techniques": [],
        "processes": [],
        "files": [],
        "ip_addresses": [],
        "business_services": [],
    }
    unresolved: list[dict[str, Any]] = []

    alerts_from_evidence: list[str] = []
    for evidence_id in claim.evidence_ids:
        if evidence_id in build_result.evidence_nodes:
            resolved["evidence_ids"].append(evidence_id)
            alert_uid = build_result.evidence_to_alert.get(evidence_id)
            if alert_uid:
                alerts_from_evidence.append(alert_uid)
        else:
            unresolved.append({"entity_type": "Evidence", "entity_id": evidence_id, "reason": "Evidence ID not found"})

    for alert_uid in claim.alert_uids + alerts_from_evidence:
        if alert_uid in build_result.alert_nodes:
            resolved["alert_uids"].append(alert_uid)
        elif alert_uid:
            unresolved.append({"entity_type": "Alert", "entity_id": alert_uid, "reason": "Alert UID not found"})

    for alert_uid in resolved["alert_uids"]:
        resolved["assets"].extend(build_result.alert_assets.get(alert_uid, []))
        resolved["hosts"].extend(build_result.alert_hosts.get(alert_uid, []))
        resolved["identities"].extend(build_result.alert_identities.get(alert_uid, []))
        resolved["techniques"].extend(build_result.alert_techniques.get(alert_uid, []))
        resolved["processes"].extend(_targets_from_alert(build_result, alert_uid, "ALERT_INVOLVES_PROCESS"))
        resolved["files"].extend(_targets_from_alert(build_result, alert_uid, "ALERT_TOUCHES_FILE"))
        resolved["ip_addresses"].extend(_targets_from_alert(build_result, alert_uid, "ALERT_CONNECTS_TO_IP"))

    resolved["assets"].extend(build_result.case_assets.get(claim.case_id, []))
    resolved["identities"].extend(build_result.case_identities.get(claim.case_id, []))
    resolved["techniques"].extend(claim.techniques)

    for asset_id in list(resolved["assets"]):
        zone_id = build_result.asset_zones.get(asset_id)
        if zone_id:
            resolved["network_zones"].append(zone_id)
        service_ids = _targets_from_node(build_result, f"Asset:{asset_id}", "ASSET_SUPPORTS_SERVICE")
        resolved["business_services"].extend(service_ids)

    for identity_id in list(resolved["identities"]):
        identity_node = build_result.graph.nodes.get(f"Identity:{identity_id}") or {}
        username = (identity_node.get("properties") or {}).get("logical_username") or (
            identity_node.get("properties") or {}
        ).get("observed_username")
        if username:
            resolved["users"].append(str(username))
        resolved["assets"].extend(build_result.identity_assets.get(identity_id, []))

    for key in resolved:
        resolved[key] = _dedupe([item for item in resolved[key] if item])

    expected_categories = ["evidence_ids", "alert_uids", "assets", "hosts"]
    if claim.techniques:
        expected_categories.append("techniques")
    if claim.claim_type in IDENTITY_SENSITIVE_CLAIMS:
        expected_categories.append("identities")
    if claim.claim_type in {"network_reachability_claim", "exfiltration_claim"}:
        expected_categories.append("ip_addresses")

    resolved_count = sum(1 for category in expected_categories if resolved.get(category))
    score = resolved_count / max(len(expected_categories), 1)

    for category in expected_categories:
        if not resolved.get(category):
            unresolved.append(
                {
                    "entity_type": category,
                    "entity_id": "",
                    "reason": f"No {category} resolved for {claim.claim_type}",
                }
            )

    return ClaimEntityResolution(
        case_id=claim.case_id,
        hypothesis_id=claim.hypothesis_id,
        claim_id=claim.claim_id,
        resolved_entities=resolved,
        entity_resolution_score=round(score, 4),
        unresolved_entities=unresolved,
    )


def _targets_from_alert(build_result: GraphBuildResult, alert_uid: str, relationship: str) -> list[str]:
    return _targets_from_node(build_result, f"Alert:{alert_uid}", relationship, strip_type=True)


def _targets_from_node(
    build_result: GraphBuildResult,
    node_id: str,
    relationship: str,
    *,
    strip_type: bool = False,
) -> list[str]:
    values: list[str] = []
    for edge in build_result.graph.out_edges.get(node_id, []):
        if edge.relationship != relationship:
            continue
        values.append(edge.target.split(":", 1)[1] if strip_type and ":" in edge.target else edge.target)
    return values


def resolution_to_dict(resolution: ClaimEntityResolution) -> dict[str, Any]:
    return asdict(resolution)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
