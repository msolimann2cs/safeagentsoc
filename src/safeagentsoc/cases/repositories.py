from __future__ import annotations

import json
from typing import Any

from safeagentsoc.storage.repository import ensure_runtime_query


RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(connection: Any, query: str, params: object | None = None) -> Any:
    ensure_runtime_query(query)
    return connection.execute(query, params)


def persist_case_builder_result(connection: Any, result: Any, *, run_id: str, replace: bool = True) -> None:
    if replace:
        runtime_query(
            connection,
            f"""
            TRUNCATE TABLE
                {RUNTIME_SCHEMA}.case_evidence_summary,
                {RUNTIME_SCHEMA}.case_alert_roles,
                {RUNTIME_SCHEMA}.alert_case_links,
                {RUNTIME_SCHEMA}.case_builder_metrics,
                {RUNTIME_SCHEMA}.generated_cases,
                {RUNTIME_SCHEMA}.case_builder_runs
            CASCADE
            """,
        )

    runtime_query(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.case_builder_runs(case_builder_run_id, input_alert_count, generated_case_count, metrics)
        VALUES (%(run_id)s, %(input_alert_count)s, %(generated_case_count)s, %(metrics)s::jsonb)
        ON CONFLICT (case_builder_run_id) DO UPDATE SET
            input_alert_count = EXCLUDED.input_alert_count,
            generated_case_count = EXCLUDED.generated_case_count,
            metrics = EXCLUDED.metrics
        """,
        {
            "run_id": run_id,
            "input_alert_count": result.metrics["total_input_alerts"],
            "generated_case_count": result.metrics["total_generated_cases"],
            "metrics": json.dumps(result.metrics, sort_keys=True),
        },
    )
    for case in result.cases:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.generated_cases(case_id, case_priority_label, case_priority_score, case_record, case_builder_run_id)
            VALUES (%(case_id)s, %(case_priority_label)s, %(case_priority_score)s, %(case_record)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id) DO UPDATE SET
                case_priority_label = EXCLUDED.case_priority_label,
                case_priority_score = EXCLUDED.case_priority_score,
                case_record = EXCLUDED.case_record,
                case_builder_run_id = EXCLUDED.case_builder_run_id
            """,
            {
                "case_id": case["case_id"],
                "case_priority_label": case["case_priority_label"],
                "case_priority_score": case["case_priority_score"],
                "case_record": json.dumps(case, sort_keys=True),
                "run_id": run_id,
            },
        )
    for link in result.alert_case_links:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.alert_case_links(case_id, alert_uid, evidence_id, runtime_alert_role, visibility_level, link_record, case_builder_run_id)
            VALUES (%(case_id)s, %(alert_uid)s, %(evidence_id)s, %(runtime_alert_role)s, %(visibility_level)s, %(link_record)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id, alert_uid) DO UPDATE SET
                evidence_id = EXCLUDED.evidence_id,
                runtime_alert_role = EXCLUDED.runtime_alert_role,
                visibility_level = EXCLUDED.visibility_level,
                link_record = EXCLUDED.link_record,
                case_builder_run_id = EXCLUDED.case_builder_run_id
            """,
            {
                "case_id": link["case_id"],
                "alert_uid": link["alert_uid"],
                "evidence_id": link["evidence_id"],
                "runtime_alert_role": link["runtime_alert_role"],
                "visibility_level": link["visibility_level"],
                "link_record": json.dumps(link, sort_keys=True),
                "run_id": run_id,
            },
        )
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_alert_roles(case_id, alert_uid, runtime_alert_role, role_confidence, role_reason, role_record, case_builder_run_id)
            VALUES (%(case_id)s, %(alert_uid)s, %(runtime_alert_role)s, %(role_confidence)s, %(role_reason)s, %(role_record)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id, alert_uid) DO UPDATE SET
                runtime_alert_role = EXCLUDED.runtime_alert_role,
                role_confidence = EXCLUDED.role_confidence,
                role_reason = EXCLUDED.role_reason,
                role_record = EXCLUDED.role_record,
                case_builder_run_id = EXCLUDED.case_builder_run_id
            """,
            {
                "case_id": link["case_id"],
                "alert_uid": link["alert_uid"],
                "runtime_alert_role": link["runtime_alert_role"],
                "role_confidence": link["role_confidence"],
                "role_reason": link["role_reason"],
                "role_record": json.dumps(link, sort_keys=True),
                "run_id": run_id,
            },
        )
    for summary in result.evidence_summary:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_evidence_summary(case_id, evidence_summary, case_builder_run_id)
            VALUES (%(case_id)s, %(evidence_summary)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id) DO UPDATE SET
                evidence_summary = EXCLUDED.evidence_summary,
                case_builder_run_id = EXCLUDED.case_builder_run_id
            """,
            {
                "case_id": summary["case_id"],
                "evidence_summary": json.dumps(summary, sort_keys=True),
                "run_id": run_id,
            },
        )
    for key, value in result.metrics.items():
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_builder_metrics(metric, value, case_builder_run_id)
            VALUES (%(metric)s, %(value)s, %(run_id)s)
            ON CONFLICT (metric) DO UPDATE SET
                value = EXCLUDED.value,
                case_builder_run_id = EXCLUDED.case_builder_run_id
            """,
            {"metric": key, "value": str(value), "run_id": run_id},
        )
    connection.commit()
