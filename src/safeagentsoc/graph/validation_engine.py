from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safeagentsoc.graph.claim_extractor import extract_claims_from_records
from safeagentsoc.graph.conditional_feasibility import (
    classify_claim,
    roll_up_hypotheses,
    validation_result_to_dict,
)
from safeagentsoc.graph.entity_resolution import resolve_claim_entities, resolution_to_dict
from safeagentsoc.graph.graph_builder import (
    GraphBuildResult,
    build_enterprise_graph,
    read_jsonl,
)
from safeagentsoc.graph.graph_export import (
    write_case_graph_exports,
    write_csv,
    write_enterprise_graph,
    write_jsonl,
)
from safeagentsoc.graph.hallucination_report import (
    build_graph_validation_metrics,
    scan_forbidden_terms,
    write_hallucination_report,
    write_metrics_files,
)
from safeagentsoc.graph.missing_graph_evidence import (
    build_missing_graph_evidence,
    missing_graph_evidence_to_dict,
)
from safeagentsoc.graph.path_validator import path_validation_to_dict, validate_claim_path
from safeagentsoc.graph.schemas import (
    ClaimEntityResolution,
    ClaimPathValidation,
    GraphValidationResult,
    HypothesisGraphClaim,
    MissingGraphEvidence,
)


@dataclass
class Phase8Paths:
    workspace_root: Path
    phase7_root: Path
    output_root: Path
    phase6_exports: Path
    phase5_exports: Path
    phase4_context: Path

    @property
    def validated_hypotheses_path(self) -> Path:
        return self.phase7_root / "validated" / "validated_hypotheses.jsonl"


@dataclass
class GraphValidationOutput:
    paths: Phase8Paths
    build_result: GraphBuildResult
    phase7_records: list[dict[str, Any]]
    claims: list[HypothesisGraphClaim]
    resolutions: list[ClaimEntityResolution]
    path_validations: list[ClaimPathValidation]
    validation_results: list[GraphValidationResult]
    missing_graph_evidence: list[MissingGraphEvidence]
    hypothesis_rollups: list[dict[str, Any]]
    case_graph_exports: list[dict[str, Any]]
    metrics: dict[str, Any]
    leakage_findings: list[dict[str, Any]]


def default_paths(
    workspace_root: Path,
    *,
    phase7_root: Path | None = None,
    output_root: Path | None = None,
) -> Phase8Paths:
    return Phase8Paths(
        workspace_root=workspace_root,
        phase7_root=resolve_phase7_root(workspace_root, phase7_root),
        output_root=output_root or workspace_root / "06_data" / "Phase8" / "graph_validation",
        phase6_exports=workspace_root / "06_data" / "Phase6" / "timelines" / "exports",
        phase5_exports=workspace_root / "06_data" / "phase_05_case_builder_alert_compression" / "cases" / "exports",
        phase4_context=workspace_root / "06_data" / "Phase4" / "context",
    )


def resolve_phase7_root(workspace_root: Path, explicit_root: Path | None = None) -> Path:
    if explicit_root is not None:
        return explicit_root
    canonical = workspace_root / "06_data" / "Phase7" / "reason"
    if _validated_file(canonical).exists() and _validated_file(canonical).stat().st_size > 0:
        return canonical
    candidates = []
    phase7_root = workspace_root / "06_data" / "Phase7"
    for path in phase7_root.glob("*/validated/validated_hypotheses.jsonl"):
        if path.exists() and path.stat().st_size > 0:
            candidates.append(path)
    if not candidates:
        return canonical
    # Prefer the richest available run over tiny smoke folders when canonical output is absent.
    candidates.sort(key=lambda item: (item.stat().st_size, item.stat().st_mtime), reverse=True)
    return candidates[0].parents[1]


def build_graph_validation_outputs(
    *,
    workspace_root: Path,
    phase7_root: Path | None = None,
    output_root: Path | None = None,
    export_case_graphs: bool = True,
    include_context_nodes: bool = False,
    max_case_graph_exports: int | None = None,
    verbose: bool = False,
) -> GraphValidationOutput:
    paths = default_paths(workspace_root, phase7_root=phase7_root, output_root=output_root)
    if verbose:
        print(f"[INFO] Phase 7 root: {paths.phase7_root}")
        print(f"[INFO] Phase 8 output root: {paths.output_root}")

    build_result = build_enterprise_graph(
        graph_nodes_path=paths.phase4_context / "graph_seed" / "graph_nodes.csv",
        graph_edges_path=paths.phase4_context / "graph_seed" / "graph_edges.csv",
        enriched_alerts_path=paths.phase4_context / "exports" / "context_enriched_alerts_with_risk.jsonl",
        asset_inventory_path=paths.phase4_context / "seed" / "asset_inventory.csv",
        identity_inventory_path=paths.phase4_context / "seed" / "identity_inventory.csv",
        network_zones_path=paths.phase4_context / "seed" / "network_zones.csv",
        generated_cases_path=paths.phase5_exports / "generated_cases.jsonl",
        case_timelines_path=paths.phase6_exports / "case_timelines.jsonl",
        validated_hypotheses_path=paths.validated_hypotheses_path,
    )
    phase7_records = read_jsonl(paths.validated_hypotheses_path)
    passed_records = [row for row in phase7_records if row.get("validation_status") == "passed"]
    claims = extract_claims_from_records(passed_records)
    if verbose:
        print(f"[INFO] Phase 7 records seen: {len(phase7_records)}")
        print(f"[INFO] Passed Phase 7 records consumed: {len(passed_records)}")
        print(f"[INFO] Graph nodes: {len(build_result.graph.nodes)}")
        print(f"[INFO] Graph edges: {len(build_result.graph.edges)}")
        print(f"[INFO] Claims extracted: {len(claims)}")

    hypotheses = _hypothesis_lookup(passed_records)
    resolutions: list[ClaimEntityResolution] = []
    path_validations: list[ClaimPathValidation] = []
    validation_results: list[GraphValidationResult] = []
    for claim in claims:
        resolution = resolve_claim_entities(claim, build_result)
        path_validation = validate_claim_path(claim, resolution, build_result)
        result = classify_claim(claim, resolution, path_validation)
        resolutions.append(resolution)
        path_validations.append(path_validation)
        validation_results.append(result)

    hypothesis_rollups = roll_up_hypotheses(validation_results, hypotheses)
    missing_graph_evidence = build_missing_graph_evidence(validation_results)
    _enrich_graph_with_validation_context(
        build_result=build_result,
        claim_results=validation_results,
        hypothesis_rollups=hypothesis_rollups,
        include_context_nodes=include_context_nodes,
    )

    _write_outputs(
        paths=paths,
        build_result=build_result,
        claims=claims,
        resolutions=resolutions,
        path_validations=path_validations,
        validation_results=validation_results,
        missing_graph_evidence=missing_graph_evidence,
        hypothesis_rollups=hypothesis_rollups,
    )
    case_graph_exports = []
    if export_case_graphs:
        case_graph_exports = write_case_graph_exports(
            build_result.graph,
            hypothesis_rollups,
            paths.output_root,
            include_context_nodes=include_context_nodes,
            max_cases=max_case_graph_exports,
        )

    leakage_paths = list((paths.output_root / "exports").glob("*")) + [
        path for path in (paths.output_root / "qa").glob("*") if path.name != "graph_validation_leakage_audit.csv"
    ]
    leakage_findings = scan_forbidden_terms([path for path in leakage_paths if path.is_file()])
    write_csv(paths.output_root / "qa" / "graph_validation_leakage_audit.csv", leakage_findings, fieldnames=["path", "forbidden_term"])

    metrics = build_graph_validation_metrics(
        phase7_records=phase7_records,
        claims=claims,
        validation_results=validation_results,
        hypothesis_rollups=hypothesis_rollups,
        skipped_cases=[row["case_id"] for row in build_result.skipped_phase7_cases],
        leakage_count=len(leakage_findings),
    )
    write_metrics_files(paths.output_root, metrics)
    write_hallucination_report(paths.output_root / "reports" / "hallucination_rejection_report.md", metrics)
    _write_qa_report(paths.output_root / "reports" / "phase_08_qa_report.md", metrics)

    return GraphValidationOutput(
        paths=paths,
        build_result=build_result,
        phase7_records=phase7_records,
        claims=claims,
        resolutions=resolutions,
        path_validations=path_validations,
        validation_results=validation_results,
        missing_graph_evidence=missing_graph_evidence,
        hypothesis_rollups=hypothesis_rollups,
        case_graph_exports=case_graph_exports,
        metrics=metrics,
        leakage_findings=leakage_findings,
    )


def _write_outputs(
    *,
    paths: Phase8Paths,
    build_result: GraphBuildResult,
    claims: list[HypothesisGraphClaim],
    resolutions: list[ClaimEntityResolution],
    path_validations: list[ClaimPathValidation],
    validation_results: list[GraphValidationResult],
    missing_graph_evidence: list[MissingGraphEvidence],
    hypothesis_rollups: list[dict[str, Any]],
) -> None:
    output_root = paths.output_root
    write_enterprise_graph(build_result.graph, output_root)
    write_jsonl(output_root / "exports" / "hypothesis_claims.jsonl", claims)
    write_jsonl(output_root / "exports" / "claim_entity_resolution.jsonl", resolutions)
    write_jsonl(output_root / "exports" / "claim_path_validation.jsonl", path_validations)
    write_jsonl(output_root / "exports" / "graph_validation_results.jsonl", validation_results)
    write_jsonl(output_root / "exports" / "missing_graph_evidence.jsonl", missing_graph_evidence)
    write_jsonl(output_root / "exports" / "phase_09_graph_handoff.jsonl", hypothesis_rollups)
    write_jsonl(output_root / "exports" / "retry_required_cases.jsonl", build_result.skipped_phase7_cases)

    write_csv(output_root / "qa" / "claim_extraction_report.csv", claims)
    write_csv(output_root / "qa" / "entity_resolution_report.csv", [resolution_to_dict(item) for item in resolutions])
    write_csv(output_root / "qa" / "path_validation_report.csv", [path_validation_to_dict(item) for item in path_validations])
    write_csv(output_root / "qa" / "graph_validation_results.csv", [validation_result_to_dict(item) for item in validation_results])
    write_csv(output_root / "qa" / "missing_graph_evidence_report.csv", [missing_graph_evidence_to_dict(item) for item in missing_graph_evidence])
    write_csv(output_root / "qa" / "phase_09_graph_handoff.csv", hypothesis_rollups)


def _hypothesis_lookup(records: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    lookup: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        case_id = record.get("case_id")
        for hypothesis in record.get("hypotheses") or []:
            hypothesis_id = str(hypothesis.get("hypothesis_id") or "hypothesis")
            lookup[(case_id, hypothesis_id)] = hypothesis
    return lookup


def _validated_file(root: Path) -> Path:
    return root / "validated" / "validated_hypotheses.jsonl"


def _write_qa_report(path: Path, metrics: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Phase 8 QA Report",
        "",
        "Phase 8 performs deterministic graph validation over accepted Phase 7 hypotheses. "
        "Failed Phase 7 records are surfaced as retry_required and are not graph-validated.",
        "",
        "## Runtime QA",
        "",
        f"- Accepted Phase 7 cases consumed: {metrics.get('total_validated_phase7_cases', 0)}",
        f"- Failed Phase 7 cases skipped: {metrics.get('total_skipped_failed_phase7_cases', 0)}",
        f"- Hypotheses graph-validated: {metrics.get('total_hypotheses_validated', 0)}",
        f"- Claims extracted: {metrics.get('total_claims_extracted', 0)}",
        f"- Claims graph-validated: {metrics.get('total_claims_validated', 0)}",
        f"- Average feasibility score: {metrics.get('average_feasibility_score', 0)}",
        f"- Explanation coverage: {metrics.get('graph_explanation_coverage', 0)}",
        f"- Runtime leakage count: {metrics.get('runtime_ground_truth_exposure_count', 0)}",
        "",
        "## Status Counts",
        "",
    ]
    for status, count in sorted((metrics.get("hypothesis_status_counts") or {}).items()):
        lines.append(f"- Hypotheses {status}: {count}")
    for status, count in sorted((metrics.get("claim_status_counts") or {}).items()):
        lines.append(f"- Claims {status}: {count}")
    lines.extend(
        [
            "",
            "## Safety Note",
            "",
            "A feasible graph result means the hypothesis is structurally possible in the modeled enterprise graph. "
            "It does not mean the activity is confirmed or that response action is authorized.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def _enrich_graph_with_validation_context(
    *,
    build_result: GraphBuildResult,
    claim_results: list[GraphValidationResult],
    hypothesis_rollups: list[dict[str, Any]],
    include_context_nodes: bool,
) -> None:
    if not include_context_nodes:
        return
    graph = build_result.graph
    for row in hypothesis_rollups:
        case_id = row["case_id"]
        hypothesis_id = row["hypothesis_id"]
        source_id = f"{case_id}|{hypothesis_id}"
        hyp_node_id = graph.source_index.get(("Hypothesis", source_id))
        if hyp_node_id:
            node = graph.nodes[hyp_node_id]
            props = dict(node.properties or {})
            props.update(
                {
                    "graph_validation_status": row.get("graph_validation_status"),
                    "feasibility_score": row.get("feasibility_score"),
                    "validated_claim_count": len(row.get("validated_claims") or []),
                    "conditional_claim_count": len(row.get("conditional_claims") or []),
                    "rejected_claim_count": len(row.get("rejected_claims") or []),
                    "missing_graph_evidence_count": len(row.get("missing_graph_evidence") or []),
                }
            )
            graph.nodes[hyp_node_id] = type(node)(
                node_id=node.node_id,
                node_type=node.node_type,
                source_id=node.source_id,
                label=node.label,
                properties=props,
            )
            validation_node = graph.node_for(
                "GraphValidationResult",
                f"{case_id}|{hypothesis_id}",
                row.get("graph_validation_status") or "unknown",
                case_id=case_id,
                hypothesis_id=hypothesis_id,
                graph_validation_status=row.get("graph_validation_status"),
                feasibility_score=row.get("feasibility_score"),
                validated_claim_count=len(row.get("validated_claims") or []),
                conditional_claim_count=len(row.get("conditional_claims") or []),
                rejected_claim_count=len(row.get("rejected_claims") or []),
            )
            graph.edge(hyp_node_id, validation_node, "HYPOTHESIS_HAS_GRAPH_VALIDATION")

            for technique_id in row.get("mitre_techniques") or []:
                graph.edge(graph.node_for("Case", case_id), graph.node_for("MITRETechnique", technique_id), "CASE_MAPS_TO_TECHNIQUE")
            for asset_id in build_result.case_assets.get(case_id, set()):
                graph.edge(graph.node_for("Case", case_id), graph.node_for("Asset", asset_id), "CASE_AFFECTS_ASSET")
            for identity_id in build_result.case_identities.get(case_id, set()):
                graph.edge(graph.node_for("Case", case_id), graph.node_for("Identity", identity_id), "CASE_INVOLVES_IDENTITY")
            for asset_id in build_result.case_assets.get(case_id, set()):
                asset_node = graph.node_for("Asset", asset_id)
                for edge in graph.out_edges.get(asset_node, []):
                    if edge.relationship == "ASSET_SUPPORTS_SERVICE":
                        graph.edge(graph.node_for("Case", case_id), edge.target, "CASE_SUPPORTS_SERVICE")
                    if edge.relationship == "ASSET_IN_NETWORK_ZONE":
                        graph.edge(graph.node_for("Case", case_id), edge.target, "CASE_IN_NETWORK_ZONE")

    for result in claim_results:
        claim_node = graph.node_for(
            "Claim",
            result.claim_id,
            result.claim_type,
            case_id=result.case_id,
            hypothesis_id=result.hypothesis_id,
            claim_type=result.claim_type,
            graph_validation_status=result.graph_validation_status,
            feasibility_score=result.feasibility_score,
        )
        hyp_node = graph.source_index.get(("Hypothesis", f"{result.case_id}|{result.hypothesis_id}"))
        if hyp_node:
            graph.edge(hyp_node, claim_node, "HYPOTHESIS_VALIDATED_BY_CLAIM")
        for requirement in result.supporting_graph_facts or []:
            fact_node = graph.node_for("GraphFact", f"{result.claim_id}|{requirement}", requirement)
            graph.edge(claim_node, fact_node, "CLAIM_SUPPORTED_BY_GRAPH_FACT")
