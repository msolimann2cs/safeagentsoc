from __future__ import annotations

import csv
from dataclasses import asdict, is_dataclass
import json
from pathlib import Path
from typing import Any, Iterable

from safeagentsoc.graph.graph_builder import EnterpriseGraph


def write_jsonl(path: Path, rows: Iterable[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(to_plain(row), sort_keys=True) + "\n")


def write_csv(path: Path, rows: Iterable[Any], fieldnames: list[str] | None = None) -> None:
    materialized = [to_plain(row) for row in rows]
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        keys: list[str] = []
        for row in materialized:
            for key in row:
                if key not in keys:
                    keys.append(key)
        fieldnames = keys
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in materialized:
            writer.writerow({key: serialize_cell(row.get(key)) for key in fieldnames})


def write_enterprise_graph(graph: EnterpriseGraph, output_root: Path) -> None:
    exports = output_root / "exports"
    node_rows = [
        {
            "node_id": node_id,
            "node_type": node.node_type,
            "label": node.label,
            "case_id": (node.properties or {}).get("case_id", ""),
            "properties": node.properties or {},
        }
        for node_id, node in sorted(graph.nodes.items())
    ]
    edge_rows = [
        {
            "edge_id": edge.edge_id,
            "source": edge.source,
            "target": edge.target,
            "relationship": edge.relationship,
            "weight": edge.weight,
            "properties": edge.properties,
        }
        for edge in graph.edges
    ]
    write_csv(exports / "enterprise_graph_nodes.csv", node_rows)
    write_csv(exports / "enterprise_graph_edges.csv", edge_rows)
    manifest = {
        "node_count": len(node_rows),
        "edge_count": len(edge_rows),
        "networkx_available": graph.networkx_available,
        "adapter": "networkx" if graph.networkx_available else "stdlib_fallback",
    }
    (exports / "enterprise_graph_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def write_case_graph_exports(
    graph: EnterpriseGraph,
    hypothesis_rollups: list[dict[str, Any]],
    output_root: Path,
    *,
    include_context_nodes: bool = False,
    max_cases: int | None = None,
) -> list[dict[str, Any]]:
    visualization_root = output_root / "visualizations" / "case_graphs"
    exports: list[dict[str, Any]] = []
    case_ids = sorted({row["case_id"] for row in hypothesis_rollups})
    if max_cases is not None:
        case_ids = case_ids[:max_cases]
    for case_id in case_ids:
        nodes, edges = _case_subgraph(graph, case_id, include_context_nodes=include_context_nodes)
        case_dir = visualization_root / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        write_csv(case_dir / "case_graph_nodes.csv", nodes)
        write_csv(case_dir / "case_graph_edges.csv", edges)
        graph_json = {"case_id": case_id, "nodes": nodes, "edges": edges}
        (case_dir / "case_graph.json").write_text(json.dumps(graph_json, indent=2, sort_keys=True), encoding="utf-8")
        html_path = case_dir / f"{case_id}_graph.html"
        html_path.write_text(_simple_html(case_id, nodes, edges), encoding="utf-8")
        exports.append(
            {
                "case_id": case_id,
                "include_context_nodes": include_context_nodes,
                "node_count": len(nodes),
                "edge_count": len(edges),
                "case_graph_json": str(case_dir / "case_graph.json"),
                "case_graph_html": str(html_path),
            }
        )
    write_csv(output_root / "qa" / "case_graph_exports.csv", exports)
    return exports


def _case_subgraph(
    graph: EnterpriseGraph,
    case_id: str,
    *,
    include_context_nodes: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    start = f"Case:{case_id}"
    visited: set[str] = set()
    frontier = [start]
    for _ in range(4):
        next_frontier: list[str] = []
        for node_id in frontier:
            if node_id in visited:
                continue
            visited.add(node_id)
            for edge in graph.out_edges.get(node_id, []):
                base_relationships = {
                    "CASE_HAS_HYPOTHESIS",
                    "HYPOTHESIS_CITES_EVIDENCE",
                    "EVIDENCE_FROM_ALERT",
                    "ALERT_AFFECTS_ASSET",
                    "ALERT_ON_HOST",
                    "ALERT_INVOLVES_IDENTITY",
                    "ALERT_MAPS_TO_TECHNIQUE",
                    "ASSET_IN_NETWORK_ZONE",
                }
                context_relationships = {
                    "CASE_AFFECTS_ASSET",
                    "CASE_INVOLVES_IDENTITY",
                    "CASE_SUPPORTS_SERVICE",
                    "CASE_IN_NETWORK_ZONE",
                    "CASE_MAPS_TO_TECHNIQUE",
                    "HYPOTHESIS_HAS_GRAPH_VALIDATION",
                    "HYPOTHESIS_VALIDATED_BY_CLAIM",
                    "CLAIM_SUPPORTED_BY_GRAPH_FACT",
                }
                allowed_relationships = base_relationships | (context_relationships if include_context_nodes else set())
                if edge.relationship in allowed_relationships:
                    next_frontier.append(edge.target)
            for edge in graph.in_edges.get(node_id, []):
                if edge.relationship in {"EVIDENCE_FROM_ALERT"}:
                    next_frontier.append(edge.source)
        frontier = next_frontier

    nodes = []
    for node_id in sorted(visited):
        node = graph.nodes.get(node_id) or {}
        node_type = getattr(node, "node_type", None) if node else None
        label = getattr(node, "label", None) if node else None
        properties = getattr(node, "properties", {}) if node else {}
        nodes.append(
            {
                "node_id": node_id,
                "node_type": node_type,
                "label": label,
                "case_id": case_id,
                "properties": properties or {},
            }
        )
    edges = [
        {
            "edge_id": edge.edge_id,
            "source": edge.source,
            "target": edge.target,
            "relationship": edge.relationship,
            "weight": edge.weight,
            "validation_relevance": edge.source in visited and edge.target in visited,
        }
        for edge in graph.edges
        if edge.source in visited and edge.target in visited
    ]
    return nodes, edges


def _simple_html(case_id: str, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> str:
    rows = "\n".join(
        f"<li><strong>{node['node_type']}</strong>: {node['label']} <code>{node['node_id']}</code></li>"
        for node in nodes[:250]
    )
    return f"""<!doctype html>
<html lang=\"en\">
<head><meta charset=\"utf-8\"><title>{case_id} graph</title>
<style>body{{font-family:Georgia,serif;margin:2rem;background:#f7f3ec;color:#1f2933}}code{{color:#7c2d12}}.card{{background:white;border:1px solid #e5dccd;border-radius:14px;padding:1rem;}}</style></head>
<body><h1>{case_id} graph export</h1>
<p>This lightweight view lists the graph entities used for Phase 8 validation. It is a structural view, not a compromise conclusion.</p>
<div class=\"card\"><p><strong>Nodes:</strong> {len(nodes)} &nbsp; <strong>Edges:</strong> {len(edges)}</p><ul>{rows}</ul></div>
</body></html>"""


def serialize_cell(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(to_plain(value), sort_keys=True)
    return value


def to_plain(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, list):
        return [to_plain(item) for item in value]
    if isinstance(value, tuple):
        return [to_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: to_plain(item) for key, item in value.items()}
    return value
