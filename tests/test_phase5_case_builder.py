from __future__ import annotations

from safeagentsoc.cases.behavior_family_mapper import map_behavior_family
from safeagentsoc.cases.case_seed import generate_case_seeds
from safeagentsoc.cases.suppression_safety import apply_suppression_safety


def alert(
    alert_uid: str,
    *,
    rule_id: str = "92058",
    description: str = "Application Compatibility Database launched",
    priority: str = "high",
    gate: bool = True,
    process: str | None = "sdbinst.exe",
    mitre: list[str] | None = None,
) -> dict:
    return {
        "alert_uid": alert_uid,
        "evidence_id": f"evidence_{alert_uid}",
        "event_time_utc": "2026-05-14T20:00:00+00:00",
        "original_alert_summary": {
            "rule_id": rule_id,
            "rule_description": description,
            "event_category": "process_activity",
            "event_action": "execution",
            "platform": "windows",
            "agent_name": "safesoc-win-01",
            "mitre_technique_ids": mitre or ["T1546.011"],
            "mitre_tactics": ["Persistence"],
            "process": {"name": process, "command_line": process},
            "file": {"path": None},
            "network": {},
            "user": {},
        },
        "asset_context": {
            "asset_id": "AST-002",
            "logical_asset_name": "win-itadmin-01",
            "business_service": "Corporate Identity",
            "business_unit": "IT Operations",
            "crown_jewel": False,
        },
        "identity_context": {"identity_id": "ID-003", "privileged_account": True},
        "business_risk": {"business_risk_score": 81.0, "business_risk_label": "high"},
        "analyst_priority": {
            "analyst_priority_score": 91.0,
            "analyst_priority_label": priority,
            "urgent_priority_gate_passed": gate,
        },
        "context_metadata": {"mapping_rule_type": "behavioral", "context_confidence": 0.9},
        "policy_context": {"relevant_policy_ids": ["POL-007"]},
    }


def test_seed_selection_uses_urgent_runtime_alerts() -> None:
    selected = alert("a1")
    rejected = alert("a2", priority="low", gate=False, process=None, mitre=[])
    seeds = generate_case_seeds([rejected, selected])
    assert [seed.seed_alert_uid for seed in seeds] == ["a1"]
    assert seeds[0].seed_evidence_id == "evidence_a1"


def test_behavior_family_separates_powershell_from_package_noise() -> None:
    powershell = alert("a1", description="Powershell process spawned Windows command shell instance", process="powershell.exe")
    package = alert("a2", rule_id="2901", description="New dpkg (Debian Package) requested to install.", process=None, mitre=[])
    assert map_behavior_family(powershell) == "windows_powershell_activity"
    assert map_behavior_family(package) == "linux_package_management"


def test_suppression_safety_keeps_trigger_visible() -> None:
    row = {
        "alert": alert("a1"),
        "runtime_alert_role": "trigger",
        "representative_alert_uid": "",
        "case_affinity_score": 1.0,
    }
    safe = apply_suppression_safety([row])[0]
    assert safe["visibility_level"] == "visible_primary"
    assert safe["suppression_safe"] is False

