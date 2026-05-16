from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from safeagentsoc.storage.db import DatabaseConfig, connect, execute_sql_file


RUNTIME_SCHEMA = "safeagentsoc_runtime"


@dataclass(frozen=True)
class GraphProjectionResult:
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    metrics: dict[str, Any]


def stable_hash(value: str, length: int = 24) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def stable_node_id(node_type: str, source_id: str) -> str:
    return f"{node_type}:{stable_hash(source_id)}"


def stable_edge_id(source_node_id: str, relationship_type: str, target_node_id: str) -> str:
    return f"Edge:{stable_hash(f'{source_node_id}|{relationship_type}|{target_node_id}', 32)}"


def non_empty(value: Any) -> bool:
    return value not in (None, "", [], {})


def json_value(value: Any) -> str:
    return json.dumps(value or {}, sort_keys=True, ensure_ascii=False)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def add_node(
    nodes: dict[str, dict[str, Any]],
    *,
    node_type: str,
    source_id: str,
    display_name: str | None = None,
    properties: dict[str, Any] | None = None,
) -> str:
    node_id = stable_node_id(node_type, source_id)
    if node_id not in nodes:
        nodes[node_id] = {
            "node_id": node_id,
            "node_type": node_type,
            "source_id": source_id,
            "display_name": display_name or source_id,
            "properties": properties or {},
        }
    return node_id


def add_edge(
    edges: dict[str, dict[str, Any]],
    *,
    source_node_id: str | None,
    target_node_id: str | None,
    relationship_type: str,
    properties: dict[str, Any] | None = None,
) -> None:
    if not source_node_id or not target_node_id:
        return
    edge_id = stable_edge_id(source_node_id, relationship_type, target_node_id)
    if edge_id not in edges:
        edges[edge_id] = {
            "edge_id": edge_id,
            "source_node_id": source_node_id,
            "target_node_id": target_node_id,
            "relationship_type": relationship_type,
            "properties": properties or {},
        }


def source_entity_id(prefix: str, values: list[Any]) -> str | None:
    cleaned = [str(value) for value in values if non_empty(value)]
    if not cleaned:
        return None
    return f"{prefix}:{'|'.join(cleaned)}"


def extract_ips(summary: dict[str, Any]) -> list[tuple[str, str]]:
    network = summary.get("network") or {}
    candidates = [
        ("agent_ip", summary.get("agent_ip")),
        ("src_ip", network.get("src_ip") or network.get("source_ip")),
        ("dst_ip", network.get("dst_ip") or network.get("destination_ip")),
    ]
    return [(role, str(value)) for role, value in candidates if non_empty(value)]


def project_alert(alert: dict[str, Any], nodes: dict[str, dict[str, Any]], edges: dict[str, dict[str, Any]]) -> None:
    summary = alert.get("original_alert_summary") or {}
    asset = alert.get("asset_context") or {}
    identity = alert.get("identity_context") or {}
    network = alert.get("network_context") or {}
    policy = alert.get("policy_context") or {}
    business_risk = alert.get("business_risk") or {}
    analyst_priority = alert.get("analyst_priority") or {}
    metadata = alert.get("context_metadata") or {}
    identity_applicability = alert.get("identity_applicability") or {}

    alert_uid = str(alert.get("alert_uid"))
    alert_node = add_node(
        nodes,
        node_type="Alert",
        source_id=alert_uid,
        display_name=alert_uid,
        properties={
            "evidence_id": alert.get("evidence_id"),
            "event_time_utc": alert.get("event_time_utc"),
            "source_system": alert.get("source_system"),
            "source_adapter": alert.get("source_adapter"),
            "agent_name": summary.get("agent_name"),
            "platform": summary.get("platform"),
            "rule_id": summary.get("rule_id"),
            "rule_level": summary.get("rule_level"),
            "rule_description": summary.get("rule_description"),
            "event_category": summary.get("event_category"),
            "event_action": summary.get("event_action"),
            "event_outcome": summary.get("event_outcome"),
            "severity_normalized": summary.get("severity_normalized"),
            "business_risk_score": business_risk.get("business_risk_score"),
            "business_risk_label": business_risk.get("business_risk_label"),
            "analyst_priority_score": analyst_priority.get("analyst_priority_score"),
            "analyst_priority_label": analyst_priority.get("analyst_priority_label"),
            "urgent_priority_gate_passed": analyst_priority.get("urgent_priority_gate_passed"),
            "identity_applicability_status": identity_applicability.get("status"),
            "context_confidence": metadata.get("context_confidence"),
            "mapping_rule_id": metadata.get("mapping_rule_id"),
            "mapping_rule_type": metadata.get("mapping_rule_type"),
            "missing_context_fields": metadata.get("missing_context_fields") or [],
        },
    )

    evidence_id = alert.get("evidence_id")
    evidence_node = None
    if non_empty(evidence_id):
        evidence_node = add_node(nodes, node_type="Evidence", source_id=str(evidence_id), display_name=str(evidence_id))
    add_edge(edges, source_node_id=alert_node, target_node_id=evidence_node, relationship_type="ALERT_HAS_EVIDENCE")

    host_source = summary.get("agent_name") or summary.get("hostname")
    host_node = None
    if non_empty(host_source):
        host_node = add_node(
            nodes,
            node_type="Host",
            source_id=str(host_source),
            display_name=str(host_source),
            properties={
                "hostname": summary.get("hostname"),
                "agent_name": summary.get("agent_name"),
                "agent_ip": summary.get("agent_ip"),
                "platform": summary.get("platform"),
            },
        )
    add_edge(edges, source_node_id=alert_node, target_node_id=host_node, relationship_type="ALERT_ON_HOST")

    asset_id = asset.get("asset_id")
    asset_node = None
    if non_empty(asset_id):
        asset_node = add_node(
            nodes,
            node_type="Asset",
            source_id=str(asset_id),
            display_name=asset.get("logical_asset_name") or str(asset_id),
            properties={
                "logical_asset_name": asset.get("logical_asset_name"),
                "business_unit": asset.get("business_unit"),
                "business_service": asset.get("business_service"),
                "asset_criticality": asset.get("asset_criticality"),
                "asset_role": asset.get("asset_role"),
                "data_classification": asset.get("data_classification"),
                "crown_jewel": asset.get("crown_jewel"),
                "context_source": asset.get("context_source"),
            },
        )
    add_edge(edges, source_node_id=host_node, target_node_id=asset_node, relationship_type="HOST_REPRESENTS_ASSET")
    add_edge(edges, source_node_id=alert_node, target_node_id=asset_node, relationship_type="ALERT_AFFECTS_ASSET")

    service_name = asset.get("business_service")
    service_node = None
    if non_empty(service_name):
        service_node = add_node(nodes, node_type="BusinessService", source_id=str(service_name), display_name=str(service_name))
    add_edge(edges, source_node_id=asset_node, target_node_id=service_node, relationship_type="ASSET_SUPPORTS_SERVICE")

    business_unit = asset.get("business_unit")
    if non_empty(business_unit):
        unit_node = add_node(nodes, node_type="BusinessUnit", source_id=str(business_unit), display_name=str(business_unit))
        add_edge(edges, source_node_id=asset_node, target_node_id=unit_node, relationship_type="ASSET_BELONGS_TO_BUSINESS_UNIT")

    data_classification = asset.get("data_classification")
    if non_empty(data_classification):
        data_node = add_node(
            nodes,
            node_type="DataClassification",
            source_id=str(data_classification),
            display_name=str(data_classification),
        )
        add_edge(edges, source_node_id=asset_node, target_node_id=data_node, relationship_type="ASSET_HAS_DATA_CLASSIFICATION")

    network_zone_id = network.get("network_zone_id") or asset.get("network_zone_id") or network.get("network_zone")
    zone_node = None
    if non_empty(network_zone_id):
        zone_node = add_node(
            nodes,
            node_type="NetworkZone",
            source_id=str(network_zone_id),
            display_name=network.get("network_zone") or str(network_zone_id),
            properties={
                "network_zone": network.get("network_zone"),
                "subnet": network.get("subnet"),
                "site": network.get("site"),
                "trust_level": network.get("trust_level"),
                "known_admin_network": network.get("known_admin_network"),
                "known_scanner_network": network.get("known_scanner_network"),
            },
        )
    add_edge(edges, source_node_id=asset_node, target_node_id=zone_node, relationship_type="ASSET_IN_NETWORK_ZONE")

    observed_user = (summary.get("user") or {}).get("username")
    user_node = None
    if non_empty(observed_user):
        user_node = add_node(nodes, node_type="User", source_id=str(observed_user), display_name=str(observed_user))
        add_edge(edges, source_node_id=alert_node, target_node_id=user_node, relationship_type="ALERT_INVOLVES_USER")

    identity_id = identity.get("identity_id")
    identity_node = None
    if non_empty(identity_id):
        identity_node = add_node(
            nodes,
            node_type="Identity",
            source_id=str(identity_id),
            display_name=identity.get("logical_username") or str(identity_id),
            properties={
                "logical_username": identity.get("logical_username"),
                "observed_username": identity.get("observed_username"),
                "privileged_account": identity.get("privileged_account"),
                "service_account": identity.get("service_account"),
                "identity_risk_score": identity.get("identity_risk_score"),
                "mfa_status": identity.get("mfa_status"),
            },
        )
        add_edge(edges, source_node_id=alert_node, target_node_id=identity_node, relationship_type="ALERT_INVOLVES_IDENTITY")
        add_edge(edges, source_node_id=identity_node, target_node_id=asset_node, relationship_type="IDENTITY_NORMALLY_USES_ASSET")
    add_edge(edges, source_node_id=user_node, target_node_id=identity_node, relationship_type="USER_HAS_IDENTITY_CONTEXT")

    process = summary.get("process") or {}
    process_source = source_entity_id("process", [process.get("name"), process.get("command_line"), process.get("path")])
    if process_source:
        process_node = add_node(
            nodes,
            node_type="Process",
            source_id=process_source,
            display_name=process.get("name") or process.get("command_line") or process_source,
            properties={
                "name": process.get("name"),
                "command_line": process.get("command_line"),
                "path": process.get("path"),
                "parent_name": process.get("parent_name"),
                "pid": process.get("pid"),
            },
        )
        add_edge(edges, source_node_id=alert_node, target_node_id=process_node, relationship_type="ALERT_INVOLVES_PROCESS")

    file_entity = summary.get("file") or {}
    file_source = source_entity_id("file", [file_entity.get("path"), file_entity.get("name"), file_entity.get("hash_sha256")])
    if file_source:
        file_node = add_node(
            nodes,
            node_type="File",
            source_id=file_source,
            display_name=file_entity.get("path") or file_entity.get("name") or file_source,
            properties={
                "path": file_entity.get("path"),
                "name": file_entity.get("name"),
                "extension": file_entity.get("extension"),
                "hash_sha256": file_entity.get("hash_sha256"),
            },
        )
        add_edge(edges, source_node_id=alert_node, target_node_id=file_node, relationship_type="ALERT_TOUCHES_FILE")

    for ip_role, ip_value in extract_ips(summary):
        ip_node = add_node(nodes, node_type="IPAddress", source_id=ip_value, display_name=ip_value)
        add_edge(
            edges,
            source_node_id=alert_node,
            target_node_id=ip_node,
            relationship_type="ALERT_CONNECTS_TO_IP",
            properties={"ip_role": ip_role},
        )

    rule_id = summary.get("rule_id")
    if non_empty(rule_id):
        rule_node = add_node(
            nodes,
            node_type="Rule",
            source_id=str(rule_id),
            display_name=str(rule_id),
            properties={
                "rule_id": rule_id,
                "rule_level": summary.get("rule_level"),
                "rule_description": summary.get("rule_description"),
            },
        )
        add_edge(edges, source_node_id=alert_node, target_node_id=rule_node, relationship_type="ALERT_TRIGGERED_RULE")

    for technique_id in summary.get("mitre_technique_ids") or []:
        if non_empty(technique_id):
            technique_node = add_node(
                nodes,
                node_type="MITRETechnique",
                source_id=str(technique_id),
                display_name=str(technique_id),
                properties={"tactics": summary.get("mitre_tactics") or []},
            )
            add_edge(edges, source_node_id=alert_node, target_node_id=technique_node, relationship_type="ALERT_MAPS_TO_TECHNIQUE")

    for policy_id in policy.get("relevant_policy_ids") or []:
        policy_node = add_node(nodes, node_type="Policy", source_id=str(policy_id), display_name=str(policy_id))
        add_edge(edges, source_node_id=policy_node, target_node_id=alert_node, relationship_type="POLICY_RELEVANT_TO_ALERT")
        add_edge(edges, source_node_id=policy_node, target_node_id=service_node, relationship_type="POLICY_PROTECTS_SERVICE")

    risk_label = business_risk.get("business_risk_label")
    if non_empty(risk_label):
        risk_node = add_node(nodes, node_type="BusinessRiskLabel", source_id=str(risk_label), display_name=str(risk_label))
        add_edge(edges, source_node_id=alert_node, target_node_id=risk_node, relationship_type="ALERT_HAS_BUSINESS_RISK_LABEL")

    priority_label = analyst_priority.get("analyst_priority_label")
    if non_empty(priority_label):
        priority_node = add_node(
            nodes,
            node_type="AnalystPriorityLabel",
            source_id=str(priority_label),
            display_name=str(priority_label),
            properties={"urgent_priority_gate_passed": analyst_priority.get("urgent_priority_gate_passed")},
        )
        add_edge(edges, source_node_id=alert_node, target_node_id=priority_node, relationship_type="ALERT_HAS_ANALYST_PRIORITY_LABEL")

    mapping_rule_id = metadata.get("mapping_rule_id")
    if non_empty(mapping_rule_id):
        mapping_node = add_node(
            nodes,
            node_type="ContextMappingRule",
            source_id=str(mapping_rule_id),
            display_name=str(mapping_rule_id),
            properties={
                "mapping_rule_type": metadata.get("mapping_rule_type"),
                "mapping_confidence": metadata.get("mapping_confidence"),
                "mapping_reason": metadata.get("mapping_reason"),
            },
        )
        add_edge(edges, source_node_id=alert_node, target_node_id=mapping_node, relationship_type="ALERT_SELECTED_MAPPING_RULE")

    for suppressor in analyst_priority.get("suppressors") or []:
        suppressor_node = add_node(nodes, node_type="AnalystPrioritySuppressor", source_id=str(suppressor), display_name=str(suppressor))
        add_edge(edges, source_node_id=alert_node, target_node_id=suppressor_node, relationship_type="ALERT_HAS_PRIORITY_SUPPRESSOR")


def build_graph_projection(enriched_alerts: list[dict[str, Any]]) -> GraphProjectionResult:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    for alert in enriched_alerts:
        project_alert(alert, nodes, edges)

    node_rows = sorted(nodes.values(), key=lambda row: (row["node_type"], row["node_id"]))
    edge_rows = sorted(edges.values(), key=lambda row: (row["relationship_type"], row["edge_id"]))
    node_type_counts: dict[str, int] = {}
    relationship_counts: dict[str, int] = {}
    for node in node_rows:
        node_type_counts[node["node_type"]] = node_type_counts.get(node["node_type"], 0) + 1
    for edge in edge_rows:
        relationship_counts[edge["relationship_type"]] = relationship_counts.get(edge["relationship_type"], 0) + 1

    return GraphProjectionResult(
        nodes=node_rows,
        edges=edge_rows,
        metrics={
            "total_enriched_alerts": len(enriched_alerts),
            "total_graph_nodes": len(node_rows),
            "total_graph_edges": len(edge_rows),
            "alert_nodes": node_type_counts.get("Alert", 0),
            "evidence_nodes": node_type_counts.get("Evidence", 0),
            "asset_nodes": node_type_counts.get("Asset", 0),
            "identity_nodes": node_type_counts.get("Identity", 0),
            "policy_nodes": node_type_counts.get("Policy", 0),
            "node_type_counts": node_type_counts,
            "relationship_counts": relationship_counts,
            "runtime_safety": "runtime_only_context_enriched_alerts_no_evaluation_artifacts",
        },
    )


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_manifest(path: Path, result: GraphProjectionResult, graph_batch_id: str, source_path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"graph_batch_id: {graph_batch_id}",
        f"generated_at_utc: {datetime.now(UTC).isoformat()}",
        f"source_enriched_alerts: {source_path}",
        "runtime_safety: runtime_only_no_evaluation_artifacts",
        "counts:",
    ]
    for key, value in result.metrics.items():
        if isinstance(value, dict):
            lines.append(f"  {key}:")
            for nested_key, nested_value in sorted(value.items()):
                lines.append(f"    {nested_key}: {nested_value}")
        else:
            lines.append(f"  {key}: {value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_graph_seed(result: GraphProjectionResult, output_dir: Path, graph_batch_id: str, source_path: Path) -> None:
    node_rows = [
        {
            "node_id": node["node_id"],
            "node_type": node["node_type"],
            "source_id": node["source_id"],
            "display_name": node["display_name"],
            "properties_json": json_value(node.get("properties")),
            "graph_batch_id": graph_batch_id,
        }
        for node in result.nodes
    ]
    edge_rows = [
        {
            "edge_id": edge["edge_id"],
            "source_node_id": edge["source_node_id"],
            "target_node_id": edge["target_node_id"],
            "relationship_type": edge["relationship_type"],
            "properties_json": json_value(edge.get("properties")),
            "graph_batch_id": graph_batch_id,
        }
        for edge in result.edges
    ]
    write_csv(
        output_dir / "graph_nodes.csv",
        node_rows,
        ["node_id", "node_type", "source_id", "display_name", "properties_json", "graph_batch_id"],
    )
    write_csv(
        output_dir / "graph_edges.csv",
        edge_rows,
        ["edge_id", "source_node_id", "target_node_id", "relationship_type", "properties_json", "graph_batch_id"],
    )
    write_manifest(output_dir / "graph_seed_manifest.yaml", result, graph_batch_id, source_path)


def persist_graph_seed(connection: Any, result: GraphProjectionResult, graph_batch_id: str, replace: bool = True) -> None:
    if replace:
        connection.execute(f"TRUNCATE TABLE {RUNTIME_SCHEMA}.context_graph_edges")
        connection.execute(f"TRUNCATE TABLE {RUNTIME_SCHEMA}.context_graph_nodes")
    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.context_graph_nodes (
                node_id,
                node_type,
                source_id,
                display_name,
                properties,
                context_import_batch_id
            )
            VALUES (%s, %s, %s, %s, %s::jsonb, NULL)
            ON CONFLICT (node_id) DO UPDATE SET
                node_type = EXCLUDED.node_type,
                source_id = EXCLUDED.source_id,
                display_name = EXCLUDED.display_name,
                properties = EXCLUDED.properties
            """,
            [
                (
                    node["node_id"],
                    node["node_type"],
                    node["source_id"],
                    node["display_name"],
                    json_value({"graph_batch_id": graph_batch_id, **(node.get("properties") or {})}),
                )
                for node in result.nodes
            ],
        )
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.context_graph_edges (
                edge_id,
                source_node_id,
                target_node_id,
                relationship_type,
                properties,
                context_import_batch_id
            )
            VALUES (%s, %s, %s, %s, %s::jsonb, NULL)
            ON CONFLICT (edge_id) DO UPDATE SET
                source_node_id = EXCLUDED.source_node_id,
                target_node_id = EXCLUDED.target_node_id,
                relationship_type = EXCLUDED.relationship_type,
                properties = EXCLUDED.properties
            """,
            [
                (
                    edge["edge_id"],
                    edge["source_node_id"],
                    edge["target_node_id"],
                    edge["relationship_type"],
                    json_value({"graph_batch_id": graph_batch_id, **(edge.get("properties") or {})}),
                )
                for edge in result.edges
            ],
        )
    connection.commit()


def run_graph_projection(
    *,
    enriched_alerts_path: Path,
    output_dir: Path,
    graph_batch_id: str,
    database_url: str | None = None,
    schema_file: Path | None = None,
    apply_schema: bool = False,
    persist: bool = False,
    replace: bool = True,
) -> GraphProjectionResult:
    enriched_alerts = read_jsonl(enriched_alerts_path)
    result = build_graph_projection(enriched_alerts)
    write_graph_seed(result, output_dir, graph_batch_id, enriched_alerts_path)

    if persist:
        config = DatabaseConfig(database_url) if database_url else DatabaseConfig.from_env()
        with connect(config) as connection:
            if apply_schema and schema_file:
                execute_sql_file(connection, schema_file)
            persist_graph_seed(connection, result, graph_batch_id=graph_batch_id, replace=replace)
    return result
