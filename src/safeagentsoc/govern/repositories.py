from __future__ import annotations

import json
from typing import Any

from safeagentsoc.govern.action_catalog import load_action_catalog
from safeagentsoc.govern.io_utils import to_plain
from safeagentsoc.storage.repository import ensure_runtime_query


RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(connection: Any, query: str, params: object | None = None) -> Any:
    ensure_runtime_query(query)
    return connection.execute(query, params)


def persist_phase9_result(connection: Any, result: Any, *, replace: bool = True) -> None:
    if replace:
        runtime_query(
            connection,
            f"""
            TRUNCATE TABLE
                {RUNTIME_SCHEMA}.phase9_decision_ledger,
                {RUNTIME_SCHEMA}.framework_mappings,
                {RUNTIME_SCHEMA}.csirt_coordination_packs,
                {RUNTIME_SCHEMA}.ciso_decision_briefs,
                {RUNTIME_SCHEMA}.stakeholder_messages,
                {RUNTIME_SCHEMA}.approval_workflows,
                {RUNTIME_SCHEMA}.soar_dry_runs,
                {RUNTIME_SCHEMA}.safe_recommendations,
                {RUNTIME_SCHEMA}.policy_decisions,
                {RUNTIME_SCHEMA}.action_catalog,
                {RUNTIME_SCHEMA}.business_impact_assessments,
                {RUNTIME_SCHEMA}.uncertainty_assessments,
                {RUNTIME_SCHEMA}.incident_risk_scores,
                {RUNTIME_SCHEMA}.phase9_governance_runs
            CASCADE
            """,
        )

    run_id = str(result.metrics.get("phase9_governance_run_id") or "phase9_latest")
    runtime_query(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.phase9_governance_runs(phase9_governance_run_id, metrics)
        VALUES (%(run_id)s, %(metrics)s::jsonb)
        ON CONFLICT (phase9_governance_run_id) DO UPDATE SET metrics = EXCLUDED.metrics
        """,
        {"run_id": run_id, "metrics": json.dumps(result.metrics, sort_keys=True)},
    )

    catalog = load_action_catalog(result.paths.config_root / "action_catalog.yaml")
    for action_id, action in catalog.items():
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.action_catalog(action_id, action_record, phase9_governance_run_id)
            VALUES (%(action_id)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (action_id) DO UPDATE SET
                action_record = EXCLUDED.action_record,
                phase9_governance_run_id = EXCLUDED.phase9_governance_run_id
            """,
            {"action_id": action_id, "record": json.dumps(action.to_dict(), sort_keys=True), "run_id": run_id},
        )

    _persist_case_records(connection, run_id, "incident_risk_scores", "risk_id", result.risks, lambda row: f"{row['case_id']}|risk")
    _persist_case_records(connection, run_id, "uncertainty_assessments", "uncertainty_id", result.uncertainties, lambda row: f"{row['case_id']}|uncertainty")
    _persist_case_records(connection, run_id, "business_impact_assessments", "business_impact_id", result.business_impacts, lambda row: f"{row['case_id']}|business_impact")
    _persist_case_records(connection, run_id, "policy_decisions", "decision_id", result.policy_decisions, lambda row: row["decision_id"])
    _persist_case_records(connection, run_id, "safe_recommendations", "recommendation_id", result.recommendations, lambda row: row["recommendation_id"])
    _persist_case_records(connection, run_id, "soar_dry_runs", "dry_run_id", result.dry_runs, lambda row: row["dry_run_id"])
    _persist_case_records(connection, run_id, "approval_workflows", "approval_id", result.approval_decisions, lambda row: row["approval_id"])
    _persist_case_records(connection, run_id, "stakeholder_messages", "message_id", result.stakeholder_messages, lambda row: row["message_id"])
    _persist_case_records(connection, run_id, "ciso_decision_briefs", "brief_id", result.ciso_briefs, lambda row: f"{row['case_id']}|ciso_brief")
    _persist_case_records(connection, run_id, "csirt_coordination_packs", "pack_id", result.csirt_packs, lambda row: f"{row['case_id']}|csirt_pack")
    _persist_case_records(connection, run_id, "framework_mappings", "mapping_id", result.framework_mappings, lambda row: row["mapping_id"])
    _persist_case_records(connection, run_id, "phase9_decision_ledger", "decision_id", result.ledger_entries, lambda row: row["decision_id"])
    connection.commit()


def _persist_case_records(connection: Any, run_id: str, table: str, id_column: str, rows: list[Any], id_builder: Any) -> None:
    for row in rows:
        record = to_plain(row)
        record_id = id_builder(record)
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.{table}({id_column}, case_id, result_record, phase9_governance_run_id)
            VALUES (%(record_id)s, %(case_id)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT ({id_column}) DO UPDATE SET
                result_record = EXCLUDED.result_record,
                phase9_governance_run_id = EXCLUDED.phase9_governance_run_id
            """,
            {
                "record_id": record_id,
                "case_id": record.get("case_id"),
                "record": json.dumps(record, sort_keys=True),
                "run_id": run_id,
            },
        )
