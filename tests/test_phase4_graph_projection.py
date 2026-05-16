from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.graph_projection import build_graph_projection


def test_graph_projection_preserves_alert_evidence_and_priority():
    result = build_graph_projection(
        [
            {
                "alert_uid": "alert_test",
                "evidence_id": "evidence_test",
                "event_time_utc": "2026-05-16T00:00:00+00:00",
                "source_system": "wazuh",
                "source_adapter": "wazuh_jsonl_v1",
                "original_alert_summary": {
                    "agent_name": "safesoc-win-01",
                    "hostname": "safesoc-win-01",
                    "agent_ip": "10.10.10.21",
                    "platform": "windows",
                    "rule_id": "92021",
                    "rule_level": 4,
                    "rule_description": "Powershell was used to delete files or directories",
                    "event_category": "process_execution",
                    "event_action": "powershell_activity",
                    "event_outcome": "unknown",
                    "severity_normalized": "medium",
                    "mitre_technique_ids": ["T1070.004"],
                    "mitre_tactics": ["Defense Evasion"],
                    "user": {"username": "Administrator"},
                    "process": {"name": "powershell.exe", "command_line": "powershell.exe Remove-Item"},
                    "network": {},
                    "file": {"path": "C:\\Temp\\example.txt", "name": "example.txt"},
                },
                "asset_context": {
                    "asset_id": "AST-002",
                    "logical_asset_name": "win-itadmin-01",
                    "business_unit": "IT Operations",
                    "business_service": "Corporate Identity",
                    "asset_criticality": "high",
                    "asset_role": "admin_workstation",
                    "data_classification": "confidential",
                    "network_zone_id": "NZ-002",
                },
                "identity_context": {
                    "identity_id": "ID-003",
                    "logical_username": "it_admin",
                    "observed_username": "Administrator",
                    "privileged_account": True,
                    "identity_risk_score": 90,
                },
                "identity_applicability": {"status": "resolved"},
                "network_context": {"network_zone_id": "NZ-002", "network_zone": "admin_workstations"},
                "policy_context": {"relevant_policy_ids": ["POL-001"]},
                "business_risk": {"business_risk_score": 78, "business_risk_label": "high"},
                "analyst_priority": {
                    "analyst_priority_score": 76,
                    "analyst_priority_label": "high",
                    "urgent_priority_gate_passed": True,
                    "suppressors": [],
                },
                "context_metadata": {
                    "context_confidence": 0.86,
                    "mapping_rule_id": "MAP-003",
                    "mapping_rule_type": "exact_identity",
                    "mapping_confidence": 0.9,
                    "missing_context_fields": [],
                },
            }
        ]
    )

    node_types = {node["node_type"] for node in result.nodes}
    relationships = {edge["relationship_type"] for edge in result.edges}

    assert "Alert" in node_types
    assert "Evidence" in node_types
    assert "AnalystPriorityLabel" in node_types
    assert "ALERT_HAS_EVIDENCE" in relationships
    assert "ALERT_HAS_ANALYST_PRIORITY_LABEL" in relationships
    assert result.metrics["alert_nodes"] == 1
    assert result.metrics["evidence_nodes"] == 1
