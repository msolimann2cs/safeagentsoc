from __future__ import annotations

import csv
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any

from safeagentsoc.graph.schemas import GraphEdge, GraphNode


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def stable_id(*parts: Any, prefix: str = "id") -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}:{digest}"


class EnterpriseGraph:
    """Small graph adapter. Mirrors to NetworkX when present, otherwise uses stdlib indexes."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self.edge_ids: set[str] = set()
        self.out_edges: dict[str, list[GraphEdge]] = {}
        self.in_edges: dict[str, list[GraphEdge]] = {}
        self.source_index: dict[tuple[str, str], str] = {}
        self.nx_graph: Any | None = None
        try:
            import networkx as nx  # type: ignore

            self.nx_graph = nx.MultiDiGraph()
        except Exception:
            self.nx_graph = None

    def add_node(self, node: GraphNode) -> str:
        existing = self.source_index.get((node.node_type, node.source_id))
        if existing:
            current = self.nodes[existing]
            merged = {**current.properties, **node.properties}
            self.nodes[existing] = GraphNode(existing, current.node_type, current.source_id, node.label or current.label, merged)
            return existing
        self.nodes[node.node_id] = node
        self.source_index[(node.node_type, node.source_id)] = node.node_id
        if self.nx_graph is not None:
            self.nx_graph.add_node(node.node_id, **node.to_dict())
        return node.node_id

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.edge_id in self.edge_ids:
            return
        self.edge_ids.add(edge.edge_id)
        self.edges.append(edge)
        self.out_edges.setdefault(edge.source, []).append(edge)
        self.in_edges.setdefault(edge.target, []).append(edge)
        if self.nx_graph is not None:
            self.nx_graph.add_edge(edge.source, edge.target, key=edge.edge_id, **edge.to_dict())

    def node_for(self, node_type: str, source_id: str, label: str | None = None, **properties: Any) -> str:
        existing = self.source_index.get((node_type, source_id))
        if existing:
            if properties:
                current = self.nodes[existing]
                self.nodes[existing] = GraphNode(existing, current.node_type, current.source_id, current.label, {**current.properties, **properties})
            return existing
        safe_source = str(source_id).replace(" ", "_").replace("/", "_")
        node_id = f"{node_type}:{safe_source}"
        return self.add_node(GraphNode(node_id=node_id, node_type=node_type, source_id=str(source_id), label=label or str(source_id), properties=properties))

    @property
    def networkx_available(self) -> bool:
        return self.nx_graph is not None

    def edge(self, source: str, target: str, relationship: str, **properties: Any) -> GraphEdge:
        edge_id = stable_id(source, target, relationship, properties, prefix="Edge")
        edge = GraphEdge(edge_id=edge_id, source=source, target=target, relationship=relationship, properties=properties)
        self.add_edge(edge)
        return edge

    def has_edge(self, source: str, target: str, relationship: str | None = None) -> bool:
        for edge in self.out_edges.get(source, []):
            if edge.target != target:
                continue
            if relationship is None or edge.relationship == relationship:
                return True
        return False

    def has_typed_path(self, source: str, target: str, allowed_relationships: set[str] | None = None, max_depth: int = 6) -> bool:
        return bool(self.shortest_typed_path(source, target, allowed_relationships, max_depth))

    def shortest_typed_path(self, source: str, target: str, allowed_relationships: set[str] | None = None, max_depth: int = 6) -> list[str]:
        if source not in self.nodes or target not in self.nodes:
            return []
        queue: list[tuple[str, list[str]]] = [(source, [source])]
        seen = {source}
        while queue:
            current, path = queue.pop(0)
            if len(path) > max_depth + 1:
                continue
            for edge in self.out_edges.get(current, []):
                if allowed_relationships and edge.relationship not in allowed_relationships:
                    continue
                if edge.target in seen:
                    continue
                next_path = path + [edge.target]
                if edge.target == target:
                    return next_path
                seen.add(edge.target)
                queue.append((edge.target, next_path))
        return []


@dataclass
class GraphBuildResult:
    graph: EnterpriseGraph
    alert_nodes: dict[str, str] = field(default_factory=dict)
    evidence_nodes: dict[str, str] = field(default_factory=dict)
    evidence_to_alert: dict[str, str] = field(default_factory=dict)
    alert_assets: dict[str, set[str]] = field(default_factory=dict)
    alert_hosts: dict[str, set[str]] = field(default_factory=dict)
    alert_identities: dict[str, set[str]] = field(default_factory=dict)
    alert_techniques: dict[str, set[str]] = field(default_factory=dict)
    asset_zones: dict[str, str] = field(default_factory=dict)
    identity_assets: dict[str, set[str]] = field(default_factory=dict)
    case_assets: dict[str, set[str]] = field(default_factory=dict)
    case_identities: dict[str, set[str]] = field(default_factory=dict)
    case_hypotheses: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    skipped_phase7_cases: list[dict[str, Any]] = field(default_factory=list)


def build_enterprise_graph(
    *,
    graph_nodes_path: Path,
    graph_edges_path: Path,
    enriched_alerts_path: Path,
    asset_inventory_path: Path,
    identity_inventory_path: Path,
    network_zones_path: Path,
    generated_cases_path: Path,
    case_timelines_path: Path,
    validated_hypotheses_path: Path,
) -> GraphBuildResult:
    result = GraphBuildResult(graph=EnterpriseGraph())
    load_graph_seed(result, graph_nodes_path, graph_edges_path)
    load_context_seed(result, asset_inventory_path, identity_inventory_path, network_zones_path)
    load_enriched_alerts(result, enriched_alerts_path)
    load_cases(result, generated_cases_path)
    load_timelines(result, case_timelines_path)
    load_validated_hypotheses(result, validated_hypotheses_path)
    return result


def load_graph_seed(result: GraphBuildResult, nodes_path: Path, edges_path: Path) -> None:
    for row in read_csv(nodes_path):
        props = parse_json(row.get("properties_json"))
        result.graph.add_node(
            GraphNode(
                node_id=row["node_id"],
                node_type=row["node_type"],
                source_id=row["source_id"],
                label=row.get("display_name") or row["source_id"],
                properties=props,
            )
        )
    for row in read_csv(edges_path):
        result.graph.add_edge(
            GraphEdge(
                edge_id=row["edge_id"],
                source=row["source_node_id"],
                target=row["target_node_id"],
                relationship=row["relationship_type"],
                properties=parse_json(row.get("properties_json")),
            )
        )


def load_context_seed(result: GraphBuildResult, asset_path: Path, identity_path: Path, zones_path: Path) -> None:
    asset_by_name: dict[str, str] = {}
    for row in read_csv(asset_path):
        asset_id = row.get("asset_id")
        if not asset_id:
            continue
        asset_node = result.graph.node_for("Asset", asset_id, row.get("logical_asset_name") or asset_id, **row)
        host = row.get("logical_asset_name") or row.get("observed_hostname") or row.get("observed_agent_name")
        if host:
            host_node = result.graph.node_for("Host", host, host, asset_id=asset_id)
            result.graph.edge(host_node, asset_node, "HOST_REPRESENTS_ASSET")
            asset_by_name[host] = asset_id
        zone_id = row.get("network_zone_id")
        if zone_id:
            zone_node = result.graph.node_for("NetworkZone", zone_id, row.get("network_zone") or zone_id, **row)
            result.graph.edge(asset_node, zone_node, "ASSET_IN_NETWORK_ZONE")
            result.asset_zones[asset_id] = zone_id
        service = row.get("business_service")
        if service:
            service_node = result.graph.node_for("BusinessService", service, service, business_unit=row.get("business_unit"))
            result.graph.edge(asset_node, service_node, "ASSET_SUPPORTS_SERVICE")
        unit = row.get("business_unit")
        if unit:
            unit_node = result.graph.node_for("BusinessUnit", unit, unit)
            result.graph.edge(asset_node, unit_node, "ASSET_BELONGS_TO_BUSINESS_UNIT")
    for row in read_csv(identity_path):
        identity_id = row.get("identity_id")
        if not identity_id:
            continue
        identity_node = result.graph.node_for("Identity", identity_id, row.get("logical_username") or identity_id, **row)
        normal_assets = [item.strip() for item in (row.get("normal_assets") or "").split(";") if item.strip()]
        for asset_name in normal_assets:
            asset_id = asset_by_name.get(asset_name)
            if not asset_id:
                continue
            asset_node = result.graph.node_for("Asset", asset_id)
            result.graph.edge(identity_node, asset_node, "IDENTITY_NORMALLY_USES_ASSET")
            result.graph.edge(identity_node, asset_node, "IDENTITY_CAN_LOGIN_TO_ASSET")
            if truthy(row.get("privileged_account")):
                result.graph.edge(identity_node, asset_node, "IDENTITY_HAS_PRIVILEGE_ON_ASSET")
            result.identity_assets.setdefault(identity_id, set()).add(asset_id)
    zones = read_csv(zones_path)
    for row in zones:
        zone_id = row.get("network_zone_id")
        if zone_id:
            result.graph.node_for("NetworkZone", zone_id, row.get("network_zone") or zone_id, **row)
    add_synthetic_reachability(result, zones)


def add_synthetic_reachability(result: GraphBuildResult, zones: list[dict[str, str]]) -> None:
    zone_names = {row.get("network_zone_id"): row.get("network_zone", "") for row in zones if row.get("network_zone_id")}
    all_zones = set(zone_names)
    privileged_keywords = ("admin", "security", "identity", "operations", "infrastructure")
    for source_id, source_name in zone_names.items():
        allowed = {source_id}
        if any(keyword in source_name for keyword in privileged_keywords):
            allowed |= all_zones
        elif "workstations" in source_name:
            allowed |= {zone_id for zone_id, name in zone_names.items() if any(token in name for token in ("application", "identity", "security"))}
        elif "application" in source_name or "linux" in source_name:
            allowed |= {zone_id for zone_id, name in zone_names.items() if "identity" in name or "security" in name}
        for target_id in sorted(allowed):
            result.graph.edge(
                result.graph.node_for("NetworkZone", source_id),
                result.graph.node_for("NetworkZone", target_id),
                "NETWORK_ZONE_CAN_REACH_ZONE",
                synthetic=True,
            )


def load_enriched_alerts(result: GraphBuildResult, enriched_alerts_path: Path) -> None:
    for alert in read_jsonl(enriched_alerts_path):
        alert_uid = alert.get("alert_uid")
        if not alert_uid:
            continue
        summary = alert.get("original_alert_summary") or {}
        asset = alert.get("asset_context") or {}
        identity = alert.get("identity_context") or {}
        network = alert.get("network_context") or {}
        evidence_id = alert.get("evidence_id")
        alert_node = result.graph.node_for(
            "Alert",
            alert_uid,
            alert_uid,
            event_time_utc=alert.get("event_time_utc"),
            rule_id=summary.get("rule_id"),
            rule_description=summary.get("rule_description"),
            event_category=summary.get("event_category"),
            event_action=summary.get("event_action"),
        )
        result.alert_nodes[alert_uid] = alert_node
        if evidence_id:
            evidence_node = result.graph.node_for("Evidence", evidence_id, evidence_id)
            result.evidence_nodes[evidence_id] = evidence_node
            result.evidence_to_alert[evidence_id] = alert_uid
            result.graph.edge(evidence_node, alert_node, "EVIDENCE_FROM_ALERT")
        asset_id = asset.get("asset_id")
        if asset_id:
            result.alert_assets.setdefault(alert_uid, set()).add(asset_id)
            asset_node = result.graph.node_for("Asset", asset_id, asset.get("logical_asset_name") or asset_id, **asset)
            result.graph.edge(alert_node, asset_node, "ALERT_AFFECTS_ASSET")
            hostname = summary.get("hostname") or asset.get("logical_asset_name")
            if hostname:
                host_node = result.graph.node_for("Host", hostname, hostname)
                result.alert_hosts.setdefault(alert_uid, set()).add(hostname)
                result.graph.edge(alert_node, host_node, "ALERT_ON_HOST")
        identity_id = identity.get("identity_id")
        if identity_id:
            result.alert_identities.setdefault(alert_uid, set()).add(identity_id)
            identity_node = result.graph.node_for("Identity", identity_id, identity.get("logical_username") or identity_id, **identity)
            result.graph.edge(alert_node, identity_node, "ALERT_INVOLVES_IDENTITY")
        for technique_id in summary.get("mitre_technique_ids") or []:
            technique_node = result.graph.node_for("MITRETechnique", technique_id, technique_id)
            result.alert_techniques.setdefault(alert_uid, set()).add(technique_id)
            result.graph.edge(alert_node, technique_node, "ALERT_MAPS_TO_TECHNIQUE")
        process = summary.get("process") or {}
        if process.get("name") or process.get("command_line"):
            process_id = process.get("command_line") or process.get("name")
            process_node = result.graph.node_for("Process", process_id, process.get("name") or process_id, **process)
            result.graph.edge(alert_node, process_node, "ALERT_INVOLVES_PROCESS")
        file_info = summary.get("file") or {}
        if file_info.get("path") or file_info.get("name"):
            file_id = file_info.get("path") or file_info.get("name")
            file_node = result.graph.node_for("File", file_id, file_info.get("name") or file_id, **file_info)
            result.graph.edge(alert_node, file_node, "ALERT_TOUCHES_FILE")
        net = summary.get("network") or {}
        for ip_key in ("src_ip", "dst_ip"):
            if net.get(ip_key):
                ip_node = result.graph.node_for("IPAddress", net[ip_key], net[ip_key], role=ip_key)
                result.graph.edge(alert_node, ip_node, "ALERT_CONNECTS_TO_IP", ip_role=ip_key)
        if network.get("network_zone_id") and asset_id:
            result.asset_zones.setdefault(asset_id, network["network_zone_id"])


def load_cases(result: GraphBuildResult, generated_cases_path: Path) -> None:
    for case in read_jsonl(generated_cases_path):
        case_id = case.get("case_id")
        if not case_id:
            continue
        case_node = result.graph.node_for("Case", case_id, case.get("case_title") or case_id, **case)
        for asset_id in [case.get("primary_asset_id")] + [alert.get("asset_id") for alert in case.get("case_alerts") or []]:
            if asset_id:
                result.case_assets.setdefault(case_id, set()).add(asset_id)
                result.graph.edge(case_node, result.graph.node_for("Asset", asset_id), "CASE_INVOLVES_ASSET")
        for identity_id in [case.get("primary_identity_id")] + [alert.get("identity_id") for alert in case.get("case_alerts") or []]:
            if identity_id:
                result.case_identities.setdefault(case_id, set()).add(identity_id)
                result.graph.edge(case_node, result.graph.node_for("Identity", identity_id), "CASE_INVOLVES_IDENTITY")
        for alert in case.get("case_alerts") or []:
            alert_uid = alert.get("alert_uid")
            if alert_uid:
                result.graph.edge(case_node, result.graph.node_for("Alert", alert_uid), "CASE_HAS_ALERT")


def load_timelines(result: GraphBuildResult, case_timelines_path: Path) -> None:
    for timeline in read_jsonl(case_timelines_path):
        case_id = timeline.get("case_id")
        if not case_id:
            continue
        case_node = result.graph.node_for("Case", case_id)
        for step in timeline.get("timeline_steps") or []:
            technique_id = step.get("technique_id")
            if technique_id:
                technique_node = result.graph.node_for("MITRETechnique", technique_id, step.get("technique_name") or technique_id)
                result.graph.edge(case_node, technique_node, "CASE_HAS_TECHNIQUE", tactic=step.get("tactic"))


def load_validated_hypotheses(result: GraphBuildResult, validated_hypotheses_path: Path) -> None:
    for record in read_jsonl(validated_hypotheses_path):
        case_id = record.get("case_id")
        if not case_id:
            continue
        if record.get("validation_status") != "passed":
            result.skipped_phase7_cases.append({"case_id": case_id, "status": "retry_required", "reason": "phase7_validation_failed"})
            continue
        case_node = result.graph.node_for("Case", case_id)
        result.case_hypotheses.setdefault(case_id, [])
        for hypothesis in record.get("hypotheses") or []:
            hypothesis_id = str(hypothesis.get("hypothesis_id") or "hypothesis")
            source_id = f"{case_id}|{hypothesis_id}"
            hyp_node = result.graph.node_for(
                "Hypothesis",
                source_id,
                hypothesis.get("title") or hypothesis_id,
                case_id=case_id,
                hypothesis_id=hypothesis_id,
                confidence_score=hypothesis.get("confidence_score"),
                validation_status="passed",
            )
            result.graph.edge(case_node, hyp_node, "CASE_HAS_HYPOTHESIS")
            result.case_hypotheses[case_id].append(hypothesis)
            for evidence_id in hypothesis.get("supporting_evidence_ids") or []:
                result.graph.edge(hyp_node, result.graph.node_for("Evidence", evidence_id), "HYPOTHESIS_CITES_EVIDENCE")
            for technique_id in hypothesis.get("mitre_techniques") or []:
                result.graph.edge(hyp_node, result.graph.node_for("MITRETechnique", technique_id), "HYPOTHESIS_MAPS_TO_TECHNIQUE")


def parse_json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}
