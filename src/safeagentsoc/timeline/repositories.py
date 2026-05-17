from __future__ import annotations

import json
from typing import Any

from safeagentsoc.storage.repository import ensure_runtime_query


RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(connection: Any, query: str, params: object | None = None) -> Any:
    ensure_runtime_query(query)
    return connection.execute(query, params)


def persist_timeline_result(connection: Any, result: Any, *, run_id: str, replace: bool = True) -> None:
    if replace:
        runtime_query(
            connection,
            f"""
            TRUNCATE TABLE
                {RUNTIME_SCHEMA}.timeline_quality_metrics,
                {RUNTIME_SCHEMA}.case_kill_chain_progression,
                {RUNTIME_SCHEMA}.case_attack_stories,
                {RUNTIME_SCHEMA}.case_missing_evidence,
                {RUNTIME_SCHEMA}.case_technique_claims,
                {RUNTIME_SCHEMA}.case_timeline_steps,
                {RUNTIME_SCHEMA}.case_timelines,
                {RUNTIME_SCHEMA}.timeline_builder_runs
            CASCADE
            """,
        )

    runtime_query(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.timeline_builder_runs(timeline_builder_run_id, case_count, metrics)
        VALUES (%(run_id)s, %(case_count)s, %(metrics)s::jsonb)
        ON CONFLICT (timeline_builder_run_id) DO UPDATE SET
            case_count = EXCLUDED.case_count,
            metrics = EXCLUDED.metrics
        """,
        {
            "run_id": run_id,
            "case_count": result.quality_metrics["total_cases_processed"],
            "metrics": json.dumps(result.quality_metrics, sort_keys=True),
        },
    )
    for timeline in result.timelines:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_timelines(case_id, timeline_record, timeline_builder_run_id)
            VALUES (%(case_id)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id) DO UPDATE SET
                timeline_record = EXCLUDED.timeline_record,
                timeline_builder_run_id = EXCLUDED.timeline_builder_run_id
            """,
            {"case_id": timeline["case_id"], "record": json.dumps(timeline, sort_keys=True), "run_id": run_id},
        )
    for step in result.timeline_steps:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_timeline_steps(case_id, step_id, step_order, step_type, claim_type, confidence_score, step_record, timeline_builder_run_id)
            VALUES (%(case_id)s, %(step_id)s, %(step_order)s, %(step_type)s, %(claim_type)s, %(confidence_score)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id, step_id) DO UPDATE SET
                step_order = EXCLUDED.step_order,
                step_type = EXCLUDED.step_type,
                claim_type = EXCLUDED.claim_type,
                confidence_score = EXCLUDED.confidence_score,
                step_record = EXCLUDED.step_record,
                timeline_builder_run_id = EXCLUDED.timeline_builder_run_id
            """,
            {
                "case_id": step["case_id"],
                "step_id": step["step_id"],
                "step_order": step["step_order"],
                "step_type": step["step_type"],
                "claim_type": step["claim_type"],
                "confidence_score": step.get("confidence_score") or 0,
                "record": json.dumps(step, sort_keys=True),
                "run_id": run_id,
            },
        )
    for index, claim in enumerate(result.technique_claims, start=1):
        claim_id = f"{claim['case_id']}|{claim.get('technique_id') or 'unknown'}|{claim.get('tactic') or 'unknown'}|{index:04d}"
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_technique_claims(claim_id, case_id, technique_id, tactic, claim_type, confidence_score, claim_record, timeline_builder_run_id)
            VALUES (%(claim_id)s, %(case_id)s, %(technique_id)s, %(tactic)s, %(claim_type)s, %(confidence_score)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (claim_id) DO UPDATE SET
                claim_type = EXCLUDED.claim_type,
                confidence_score = EXCLUDED.confidence_score,
                claim_record = EXCLUDED.claim_record,
                timeline_builder_run_id = EXCLUDED.timeline_builder_run_id
            """,
            {
                "claim_id": claim_id,
                "case_id": claim["case_id"],
                "technique_id": claim.get("technique_id"),
                "tactic": claim.get("tactic"),
                "claim_type": claim.get("claim_type"),
                "confidence_score": claim.get("confidence_score") or 0,
                "record": json.dumps(claim, sort_keys=True),
                "run_id": run_id,
            },
        )
    for index, entry in enumerate(result.missing_evidence, start=1):
        missing_id = f"{entry['case_id']}|{entry['missing_evidence_type']}"
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_missing_evidence(missing_id, case_id, missing_evidence_type, status, missing_record, timeline_builder_run_id)
            VALUES (%(missing_id)s, %(case_id)s, %(missing_type)s, %(status)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (missing_id) DO UPDATE SET
                status = EXCLUDED.status,
                missing_record = EXCLUDED.missing_record,
                timeline_builder_run_id = EXCLUDED.timeline_builder_run_id
            """,
            {
                "missing_id": missing_id,
                "case_id": entry["case_id"],
                "missing_type": entry["missing_evidence_type"],
                "status": entry["status"],
                "record": json.dumps(entry, sort_keys=True),
                "run_id": run_id,
            },
        )
    for story in result.attack_stories:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_attack_stories(case_id, story_record, timeline_builder_run_id)
            VALUES (%(case_id)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id) DO UPDATE SET
                story_record = EXCLUDED.story_record,
                timeline_builder_run_id = EXCLUDED.timeline_builder_run_id
            """,
            {"case_id": story["case_id"], "record": json.dumps(story, sort_keys=True), "run_id": run_id},
        )
    for row in result.kill_chain_progression:
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.case_kill_chain_progression(case_id, progression_depth, progression_record, timeline_builder_run_id)
            VALUES (%(case_id)s, %(depth)s, %(record)s::jsonb, %(run_id)s)
            ON CONFLICT (case_id) DO UPDATE SET
                progression_depth = EXCLUDED.progression_depth,
                progression_record = EXCLUDED.progression_record,
                timeline_builder_run_id = EXCLUDED.timeline_builder_run_id
            """,
            {
                "case_id": row["case_id"],
                "depth": row["progression_depth"],
                "record": json.dumps(row, sort_keys=True),
                "run_id": run_id,
            },
        )
    for key, value in result.quality_metrics.items():
        runtime_query(
            connection,
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.timeline_quality_metrics(metric, value, timeline_builder_run_id)
            VALUES (%(metric)s, %(value)s, %(run_id)s)
            ON CONFLICT (metric) DO UPDATE SET
                value = EXCLUDED.value,
                timeline_builder_run_id = EXCLUDED.timeline_builder_run_id
            """,
            {"metric": key, "value": str(value), "run_id": run_id},
        )
    connection.commit()

