from __future__ import annotations

from safeagentsoc.timeline.attack_catalog import technique_info
from safeagentsoc.timeline.kill_chain import build_kill_chain_progression
from safeagentsoc.timeline.mitre_mapper import build_case_mitre_mappings
from safeagentsoc.timeline.technique_confidence import score_technique_confidence


def enriched_alert(alert_uid: str, *, mitre: list[str] | None = None) -> dict:
    return {
        "alert_uid": alert_uid,
        "evidence_id": f"evidence_{alert_uid}",
        "event_time_utc": "2026-05-14T20:00:00+00:00",
        "original_alert_summary": {
            "rule_id": "92058",
            "rule_description": "Application Compatibility Database launched",
            "mitre_technique_ids": mitre or ["T1546.011"],
            "mitre_tactics": ["Persistence"],
            "process": {"name": "sdbinst.exe", "command_line": "sdbinst.exe test.sdb"},
            "file": {"path": "C:\\Windows\\Temp\\test.sdb"},
            "network": {},
            "user": {"username": "Administrator"},
        },
        "identity_context": {"identity_id": "ID-003", "privileged_account": True},
        "context_metadata": {"context_confidence": 0.9},
    }


def case(alert_uid: str = "a1") -> dict:
    return {
        "case_id": "case_rt_000001",
        "case_title": "Application Compatibility Database execution on win-itadmin-01",
        "primary_behavior_family": "windows_persistence_or_privilege",
        "visible_alert_count": 1,
        "suppressed_alert_count": 0,
        "case_alerts": [
            {
                "case_id": "case_rt_000001",
                "alert_uid": alert_uid,
                "evidence_id": f"evidence_{alert_uid}",
                "runtime_alert_role": "trigger",
                "visibility_level": "visible_primary",
                "analyst_priority_score": 95,
                "behavior_family": "windows_persistence_or_privilege",
                "event_time_utc": "2026-05-14T20:00:00+00:00",
            }
        ],
    }


def test_direct_mitre_mapping_is_preserved() -> None:
    alert = enriched_alert("a1")
    mappings = build_case_mitre_mappings(case(), {"a1": alert})
    assert mappings[0]["technique_id"] == "T1546.011"
    assert mappings[0]["mapping_source"] == "direct_mitre"
    assert mappings[0]["evidence_ids"] == ["evidence_a1"]


def test_confidence_prefers_trigger_evidence_not_duplicate_volume() -> None:
    alert = enriched_alert("a1")
    mappings = build_case_mitre_mappings(case(), {"a1": alert})
    confidence = score_technique_confidence(mappings[0])
    assert confidence["confidence_label"] == "high"
    assert confidence["confidence_components"]["role_strength"] == 1.0


def test_backlog_case_gets_telemetry_backlog_label() -> None:
    row = {
        "case_id": "case_rt_000053",
        "case_title": "Vulnerability backlog for libfreerdp-server3-3 (CVE-2026-27951) on lnx-app-01",
        "primary_behavior_family": "wazuh_security_infrastructure",
        "visible_alert_count": 195,
        "suppressed_alert_count": 2654,
    }
    progression = build_kill_chain_progression(row, [])
    assert progression["progression_depth"] == "telemetry_backlog"


def test_local_attack_catalog_has_common_phase6_technique() -> None:
    assert technique_info("T1059.001").name.endswith("PowerShell")

