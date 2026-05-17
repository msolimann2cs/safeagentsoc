from __future__ import annotations

from pathlib import Path

from safeagentsoc.graph.claim_extractor import extract_claims_from_records
from safeagentsoc.graph.graph_builder import EnterpriseGraph, GraphBuildResult
from safeagentsoc.graph.hallucination_report import scan_forbidden_terms
from safeagentsoc.graph.path_validator import validate_claim_path
from safeagentsoc.graph.schemas import ClaimEntityResolution, GraphNode, HypothesisGraphClaim


def test_claim_extractor_maps_lateral_movement_technique() -> None:
    records = [
        {
            "case_id": "case_rt_000001",
            "validation_status": "passed",
            "hypotheses": [
                {
                    "hypothesis_id": "hyp_001",
                    "title": "SSH lateral movement may be possible",
                    "description": "Remote service use may indicate lateral movement.",
                    "mitre_techniques": ["T1021.004"],
                    "supporting_evidence_ids": ["evidence_1"],
                    "supporting_alert_uids": ["alert_1"],
                }
            ],
        }
    ]
    claims = extract_claims_from_records(records)
    assert any(claim.claim_type == "lateral_movement_claim" for claim in claims)


def test_graph_adapter_typed_path_works_without_networkx_dependency() -> None:
    graph = EnterpriseGraph()
    graph.add_node(GraphNode("A:1", "A", "1", "one"))
    graph.add_node(GraphNode("B:2", "B", "2", "two"))
    graph.edge("A:1", "B:2", "ALLOWED")
    assert graph.has_typed_path("A:1", "B:2", {"ALLOWED"})
    assert not graph.has_typed_path("A:1", "B:2", {"DENIED"})


def test_lateral_movement_is_not_supported_by_single_asset_only() -> None:
    graph = EnterpriseGraph()
    graph.add_node(GraphNode("Asset:AST-001", "Asset", "AST-001", "asset"))
    build_result = GraphBuildResult(graph=graph)
    claim = HypothesisGraphClaim(
        claim_id="claim_1",
        case_id="case_rt_000001",
        hypothesis_id="hyp_001",
        claim_type="lateral_movement_claim",
        claim_text="Lateral movement may have occurred.",
        techniques=["T1021.004"],
        evidence_ids=["evidence_1"],
        alert_uids=["alert_1"],
        claim_source="test",
    )
    resolution = ClaimEntityResolution(
        claim_id="claim_1",
        case_id="case_rt_000001",
        hypothesis_id="hyp_001",
        resolved_entities={
            "evidence_ids": ["evidence_1"],
            "alert_uids": ["alert_1"],
            "assets": ["AST-001"],
            "hosts": ["host1"],
            "identities": [],
            "network_zones": ["NZ-001"],
            "techniques": ["T1021.004"],
        },
        entity_resolution_score=0.75,
        unresolved_entities=[],
    )
    path = validate_claim_path(claim, resolution, build_result)
    assert path.path_existence_score < 0.55
    assert "missing_cross_host_sequence" in path.missing_requirements


def test_leakage_scanner_ignores_metric_key_but_catches_actual_forbidden_content(tmp_path: Path) -> None:
    metric_file = tmp_path / "metrics.json"
    metric_file.write_text('{"runtime_ground_truth_exposure_count": 0}', encoding="utf-8")
    leak_file = tmp_path / "bad.json"
    leak_file.write_text('{"field": "ground_truth_labels.csv"}', encoding="utf-8")
    findings = scan_forbidden_terms([metric_file, leak_file])
    assert len(findings) == 1
    assert findings[0]["path"].endswith("bad.json")
