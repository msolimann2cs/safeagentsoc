from __future__ import annotations

import json
from typing import Any

from safeagentsoc.graph.graph_export import to_plain
from safeagentsoc.storage.repository import ensure_runtime_query


RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(connection: Any, query: str, params: object | None = None) -> Any:
    ensure_runtime_query(query)
    return connection.execute(query, params)


def persist_graph_validation_result(connection: Any, result: Any, *, replace: bool = True) -> None:
    if replace:
        runtime_query(
            connection,
            f"""
            TRUNCATE TABLE
                {RUNTIME_SCHEMA}.case_graph_exports,
                {RUNTIME_SCHEMA}.missing_graph_evidence,
                {RUNTIME_SCHEMA}.graph_validation_results,
                {RUNTIME_SCHEMA}.claim_path_validation,
                {RUNTIME_SCHEMA}.claim_entity_resolution,
                {RUNTIME_SCHEMA}.hypothesis_graph_claims,
                {RUNTIME_SCHEMA}.enterprise_graph_edges,
                {RUNTIME_SCHEMA}.enterprise_graph_nodes,
                {RUNTIME_SCHEMA}.graph_validation_runs
            CASCADE
            """,
        )

    run_id = str(result.metrics.get("graph_validation_run_id") or "phase8_latest")
    runtime_query(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.graph_validation_runs(graph_validation_run_id, metrics)
        VALUES (%(run_id)s, %(metrics)s::jsonb)
        ON CONFLICT (graph_validation_run_id) DO UPDATE SET metrics = EXCLUDED.metrics
        """,
        {"run_id": run_id, "metrics": json.dumps(result.metrics, sort_keys=True)},
    )

    for node_id, node in result.build_result.graph.nodes.items():
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.enterprise_graph_nodes(node_id, node_type, label, properties, graph_validation_run_id)
            VALUES (%(node_id)s, %(node_type)s, %(label)s, %(properties)s::jsonb, %(run_id)s)
            ON CONFLICT (node_id) DO UPDATE SET
                node_type = EXCLUDED.node_type,
                label = EXCLUDED.label,
                properties = EXCLUDED.properties,
                graph_validation_run_id = EXCLUDED.graph_validation_run_id
            """,
            {
                "node_id": node_id,
                "node_type": node.node_type,
                "label": node.label,
                "properties": json.dumps(node.properties, sort_keys=True),
                "run_id": run_id,
            },
        )

    for edge in result.build_result.graph.edges:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.enterprise_graph_edges(edge_id, source_node_id, target_node_id, relationship, weight, properties, graph_validation_run_id)
            VALUES (%(edge_id)s, %(source)s, %(target)s, %(relationship)s, %(weight)s, %(properties)s::jsonb, %(run_id)s)
            ON CONFLICT (edge_id) DO UPDATE SET
                source_node_id = EXCLUDED.source_node_id,
                target_node_id = EXCLUDED.target_node_id,
                relationship = EXCLUDED.relationship,
                weight = EXCLUDED.weight,
                properties = EXCLUDED.properties,
                graph_validation_run_id = EXCLUDED.graph_validation_run_id
            """,
            {
                "edge_id": edge.edge_id,
                "source": edge.source,
                "target": edge.target,
                "relationship": edge.relationship,
                "weight": edge.weight,
                "properties": json.dumps(edge.properties, sort_keys=True),
                "run_id": run_id,
            },
        )

    for claim in result.claims:
        record = to_plain(claim)
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.hypothesis_graph_claims(claim_id, case_id, hypothesis_id, claim_type, claim_record, graph_validation_run_id)
            VALUES (%(claim_id)s, %(case_id)s, %(hypothesis_id)s, %(claim_type)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (claim_id) DO UPDATE SET
                claim_record = EXCLUDED.claim_record,
                graph_validation_run_id = EXCLUDED.graph_validation_run_id
            """,
            {
                "claim_id": claim.claim_id,
                "case_id": claim.case_id,
                "hypothesis_id": claim.hypothesis_id,
                "claim_type": claim.claim_type,
                "record": json.dumps(record, sort_keys=True),
                "run_id": run_id,
            },
        )

    _persist_records(connection, run_id, "claim_entity_resolution", "resolution_id", result.resolutions, _resolution_id)
    _persist_records(connection, run_id, "claim_path_validation", "path_validation_id", result.path_validations, _path_id)
    _persist_records(connection, run_id, "graph_validation_results", "validation_id", result.validation_results, _validation_id)
    _persist_records(connection, run_id, "missing_graph_evidence", "missing_graph_evidence_id", result.missing_graph_evidence, _missing_id)

    for row in result.case_graph_exports:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_graph_exports(case_id, export_record, graph_validation_run_id)
            VALUES (%(case_id)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id) DO UPDATE SET
                export_record = EXCLUDED.export_record,
                graph_validation_run_id = EXCLUDED.graph_validation_run_id
            """,
            {
                "case_id": row["case_id"],
                "record": json.dumps(row, sort_keys=True),
                "run_id": run_id,
            },
        )
    connection.commit()


def _persist_records(connection: Any, run_id: str, table: str, id_column: str, rows: list[Any], id_builder: Any) -> None:
    for row in rows:
        record = to_plain(row)
        record_id = id_builder(record)
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.{table}({id_column}, case_id, hypothesis_id, claim_id, result_record, graph_validation_run_id)
            VALUES (%(record_id)s, %(case_id)s, %(hypothesis_id)s, %(claim_id)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT ({id_column}) DO UPDATE SET
                result_record = EXCLUDED.result_record,
                graph_validation_run_id = EXCLUDED.graph_validation_run_id
            """,
            {
                "record_id": record_id,
                "case_id": record.get("case_id"),
                "hypothesis_id": record.get("hypothesis_id"),
                "claim_id": record.get("claim_id"),
                "record": json.dumps(record, sort_keys=True),
                "run_id": run_id,
            },
        )


def _resolution_id(record: dict[str, Any]) -> str:
    return f"{record.get('claim_id')}|resolution"


def _path_id(record: dict[str, Any]) -> str:
    return f"{record.get('claim_id')}|path"


def _validation_id(record: dict[str, Any]) -> str:
    return f"{record.get('claim_id')}|graph_validation"


def _missing_id(record: dict[str, Any]) -> str:
    return f"{record.get('claim_id')}|{record.get('missing_type')}|missing_graph_context"
