from __future__ import annotations

import json
from typing import Any

from safeagentsoc.storage.repository import ensure_runtime_query


RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(connection: Any, query: str, params: object | None = None) -> Any:
    ensure_runtime_query(query)
    return connection.execute(query, params)


def persist_hypothesis_result(connection: Any, result: Any, *, run_id: str, replace: bool = True) -> None:
    if replace:
        runtime_query(
            connection,
            f"""
            TRUNCATE TABLE
                {RUNTIME_SCHEMA}.ai_decision_ledger,
                {RUNTIME_SCHEMA}.agent_firewall_results,
                {RUNTIME_SCHEMA}.evidence_support_results,
                {RUNTIME_SCHEMA}.hypothesis_validation_results,
                {RUNTIME_SCHEMA}.case_hypotheses_validated,
                {RUNTIME_SCHEMA}.case_hypotheses_raw,
                {RUNTIME_SCHEMA}.hypothesis_runs
            CASCADE
            """,
        )

    runtime_query(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.hypothesis_runs(hypothesis_run_id, case_count, validated_case_count, metrics)
        VALUES (%(run_id)s, %(case_count)s, %(validated_case_count)s, %(metrics)s::jsonb)
        ON CONFLICT (hypothesis_run_id) DO UPDATE SET
            case_count = EXCLUDED.case_count,
            validated_case_count = EXCLUDED.validated_case_count,
            metrics = EXCLUDED.metrics
        """,
        {
            "run_id": run_id,
            "case_count": result.metrics["total_cases"],
            "validated_case_count": result.metrics["validated_case_count"],
            "metrics": json.dumps(result.metrics, sort_keys=True),
        },
    )

    for raw in result.raw_outputs:
        case_id = raw.get("case_id")
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_hypotheses_raw(case_id, provider, raw_record, hypothesis_run_id)
            VALUES (%(case_id)s, %(provider)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id) DO UPDATE SET
                provider = EXCLUDED.provider,
                raw_record = EXCLUDED.raw_record,
                hypothesis_run_id = EXCLUDED.hypothesis_run_id
            """,
            {
                "case_id": case_id,
                "provider": raw.get("provider") or "unknown",
                "record": json.dumps(raw, sort_keys=True),
                "run_id": run_id,
            },
        )

    combined_validated_records = list(result.validated_outputs)
    combined_validated_records.extend(
        item.get("validated_record")
        for item in result.invalid_outputs
        if isinstance(item, dict) and isinstance(item.get("validated_record"), dict)
    )

    for record in combined_validated_records:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_hypotheses_validated(case_id, validation_status, validated_record, hypothesis_run_id)
            VALUES (%(case_id)s, %(status)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id) DO UPDATE SET
                validation_status = EXCLUDED.validation_status,
                validated_record = EXCLUDED.validated_record,
                hypothesis_run_id = EXCLUDED.hypothesis_run_id
            """,
            {
                "case_id": record["case_id"],
                "status": record["validation_status"],
                "record": json.dumps(record, sort_keys=True),
                "run_id": run_id,
            },
        )

    for row in result.validation_rows:
        validation_id = f"{row.get('case_id')}|schema"
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.hypothesis_validation_results(validation_id, case_id, validation_type, status, result_record, hypothesis_run_id)
            VALUES (%(validation_id)s, %(case_id)s, 'schema', %(status)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (validation_id) DO UPDATE SET
                status = EXCLUDED.status,
                result_record = EXCLUDED.result_record,
                hypothesis_run_id = EXCLUDED.hypothesis_run_id
            """,
            {
                "validation_id": validation_id,
                "case_id": row.get("case_id"),
                "status": row.get("schema_validation_status"),
                "record": json.dumps(row, sort_keys=True),
                "run_id": run_id,
            },
        )

    for row in result.evidence_rows:
        validation_id = f"{row.get('case_id')}|{row.get('hypothesis_id') or 'unknown'}|evidence"
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.evidence_support_results(validation_id, case_id, hypothesis_id, evidence_supported, support_rate, result_record, hypothesis_run_id)
            VALUES (%(validation_id)s, %(case_id)s, %(hypothesis_id)s, %(supported)s, %(support_rate)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (validation_id) DO UPDATE SET
                evidence_supported = EXCLUDED.evidence_supported,
                support_rate = EXCLUDED.support_rate,
                result_record = EXCLUDED.result_record,
                hypothesis_run_id = EXCLUDED.hypothesis_run_id
            """,
            {
                "validation_id": validation_id,
                "case_id": row.get("case_id"),
                "hypothesis_id": row.get("hypothesis_id") or "",
                "supported": bool(row.get("evidence_supported")),
                "support_rate": row.get("evidence_support_rate") or 0,
                "record": json.dumps(row, sort_keys=True),
                "run_id": run_id,
            },
        )

    for index, row in enumerate(result.agent_firewall_rows, start=1):
        result_id = f"{run_id}|agent_firewall|{index:05d}"
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.agent_firewall_results(result_id, check_type, agent_id, blocked, result_record, hypothesis_run_id)
            VALUES (%(result_id)s, %(check_type)s, %(agent_id)s, %(blocked)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (result_id) DO UPDATE SET
                blocked = EXCLUDED.blocked,
                result_record = EXCLUDED.result_record,
                hypothesis_run_id = EXCLUDED.hypothesis_run_id
            """,
            {
                "result_id": result_id,
                "check_type": row.get("check_type"),
                "agent_id": row.get("agent_id"),
                "blocked": bool(row.get("blocked")),
                "record": json.dumps(row, sort_keys=True),
                "run_id": run_id,
            },
        )

    for row in result.ledger_rows:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.ai_decision_ledger(decision_id, case_id, agent_id, ledger_record, hypothesis_run_id)
            VALUES (%(decision_id)s, %(case_id)s, %(agent_id)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (decision_id) DO UPDATE SET
                ledger_record = EXCLUDED.ledger_record,
                hypothesis_run_id = EXCLUDED.hypothesis_run_id
            """,
            {
                "decision_id": row["decision_id"],
                "case_id": row["case_id"],
                "agent_id": row["agent_id"],
                "record": json.dumps(row, sort_keys=True),
                "run_id": run_id,
            },
        )

    connection.commit()
