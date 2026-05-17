from __future__ import annotations

from dataclasses import dataclass


CLAIM_TYPES = {
    "identity_claim",
    "host_claim",
    "asset_claim",
    "business_context_claim",
    "technique_claim",
    "execution_claim",
    "persistence_claim",
    "privilege_claim",
    "credential_access_claim",
    "lateral_movement_claim",
    "network_reachability_claim",
    "exfiltration_claim",
    "impact_claim",
    "defense_evasion_claim",
    "telemetry_backlog_claim",
}


TECHNIQUE_CLAIM_MAP: dict[str, tuple[str, ...]] = {
    "T1546.011": ("persistence_claim", "privilege_claim"),
    "T1059": ("execution_claim",),
    "T1059.001": ("execution_claim",),
    "T1059.003": ("execution_claim",),
    "T1087": ("technique_claim",),
    "T1078": ("identity_claim", "persistence_claim", "privilege_claim"),
    "T1548.003": ("privilege_claim",),
    "T1021": ("lateral_movement_claim",),
    "T1021.004": ("lateral_movement_claim",),
    "T1110.001": ("credential_access_claim",),
    "T1070.004": ("defense_evasion_claim",),
    "T1484": ("defense_evasion_claim", "privilege_claim"),
    "T1486": ("impact_claim",),
    "T1490": ("impact_claim",),
    "T1531": ("impact_claim",),
}


LANGUAGE_CLAIM_MAP: tuple[tuple[str, str], ...] = (
    ("lateral movement", "lateral_movement_claim"),
    ("remote service", "lateral_movement_claim"),
    ("external c2", "network_reachability_claim"),
    ("command and control", "network_reachability_claim"),
    ("exfiltration", "exfiltration_claim"),
    ("outbound transfer", "exfiltration_claim"),
    ("impact", "impact_claim"),
    ("privilege", "privilege_claim"),
    ("persistence", "persistence_claim"),
    ("defense evasion", "defense_evasion_claim"),
    ("credential", "credential_access_claim"),
    ("identity", "identity_claim"),
    ("telemetry backlog", "telemetry_backlog_claim"),
    ("backlog", "telemetry_backlog_claim"),
)


CRITICAL_CLAIM_TYPES = {
    "credential_access_claim",
    "lateral_movement_claim",
    "network_reachability_claim",
    "exfiltration_claim",
    "impact_claim",
    "privilege_claim",
    "persistence_claim",
}


@dataclass(frozen=True)
class ClaimTypeInfo:
    claim_type: str
    critical: bool
    reason: str


def claim_types_for_technique(technique_id: str) -> list[ClaimTypeInfo]:
    exact = TECHNIQUE_CLAIM_MAP.get(technique_id)
    if exact is None and technique_id.startswith("T1059"):
        exact = ("execution_claim",)
    if exact is None and technique_id.startswith("T1021"):
        exact = ("lateral_movement_claim",)
    if exact is None:
        exact = ("technique_claim",)
    return [
        ClaimTypeInfo(claim_type=item, critical=item in CRITICAL_CLAIM_TYPES, reason=f"technique:{technique_id}")
        for item in exact
    ]


def claim_types_for_text(text: str) -> list[ClaimTypeInfo]:
    lowered = text.lower()
    result: list[ClaimTypeInfo] = []
    seen: set[str] = set()
    for phrase, claim_type in LANGUAGE_CLAIM_MAP:
        if phrase in lowered and claim_type not in seen:
            result.append(ClaimTypeInfo(claim_type=claim_type, critical=claim_type in CRITICAL_CLAIM_TYPES, reason=f"language:{phrase}"))
            seen.add(claim_type)
    return result

