from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from safeagentsoc.api.dependencies import get_db
from safeagentsoc.api.utils import cursor_all, cursor_one
from safeagentsoc.storage.repository import ensure_runtime_query


router = APIRouter(tags=["runtime-cases"])
RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(db: Any, query: str, params: dict[str, Any] | None = None) -> Any:
    ensure_runtime_query(query)
    return db.execute(query, params)


@router.get("/cases")
def list_cases(
    case_priority_label: str | None = None,
    business_unit: str | None = None,
    business_service: str | None = None,
    asset_id: str | None = None,
    identity_id: str | None = None,
    mitre_technique_id: str | None = None,
    has_suppressed_alerts: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Any = Depends(get_db),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if case_priority_label:
        clauses.append("case_priority_label = %(case_priority_label)s")
        params["case_priority_label"] = case_priority_label
    if business_unit:
        clauses.append("case_record->>'business_unit' = %(business_unit)s")
        params["business_unit"] = business_unit
    if business_service:
        clauses.append("case_record->>'business_service' = %(business_service)s")
        params["business_service"] = business_service
    if asset_id:
        clauses.append("case_record->>'primary_asset_id' = %(asset_id)s")
        params["asset_id"] = asset_id
    if identity_id:
        clauses.append("case_record->>'primary_identity_id' = %(identity_id)s")
        params["identity_id"] = identity_id
    if mitre_technique_id:
        clauses.append("case_record->'mitre_technique_ids' ? %(mitre_technique_id)s")
        params["mitre_technique_id"] = mitre_technique_id
    if has_suppressed_alerts is not None:
        clauses.append("((case_record->>'suppressed_alert_count')::int > 0) = %(has_suppressed_alerts)s")
        params["has_suppressed_alerts"] = has_suppressed_alerts
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT case_id, case_priority_label, case_priority_score, case_record
            FROM {RUNTIME_SCHEMA}.generated_cases
            {where_sql}
            ORDER BY case_priority_score DESC, case_id
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            params,
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/cases/{case_id}")
def get_case(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"SELECT case_id, case_priority_label, case_priority_score, case_record FROM {RUNTIME_SCHEMA}.generated_cases WHERE case_id = %(case_id)s",
            {"case_id": case_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Generated case not found")
    return row


@router.get("/cases/{case_id}/alerts")
def get_case_alerts(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.alert_case_links
            WHERE case_id = %(case_id)s
            ORDER BY link_record->>'event_time_utc', alert_uid
            """,
            {"case_id": case_id},
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/cases/{case_id}/suppressed-alerts")
def get_case_suppressed_alerts(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.alert_case_links
            WHERE case_id = %(case_id)s
              AND visibility_level IN ('collapsed_duplicate', 'collapsed_noise')
            ORDER BY link_record->>'event_time_utc', alert_uid
            """,
            {"case_id": case_id},
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/cases/{case_id}/evidence")
def get_case_evidence(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"SELECT * FROM {RUNTIME_SCHEMA}.case_evidence_summary WHERE case_id = %(case_id)s",
            {"case_id": case_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Case evidence summary not found")
    return row


@router.get("/cases/{case_id}/timeline")
def get_case_timeline(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT alert_uid, evidence_id, runtime_alert_role, visibility_level, link_record
            FROM {RUNTIME_SCHEMA}.alert_case_links
            WHERE case_id = %(case_id)s
            ORDER BY link_record->>'event_time_utc', alert_uid
            """,
            {"case_id": case_id},
        )
    )
    return {"case_id": case_id, "count": len(rows), "timeline": rows}


@router.get("/metrics/case-builder")
def get_case_builder_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT metrics
            FROM {RUNTIME_SCHEMA}.case_builder_runs
            ORDER BY generated_at_utc DESC
            LIMIT 1
            """,
        )
    )
    return row or {"metrics": {}}


@router.get("/metrics/alert-compression")
def get_alert_compression_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT
                COUNT(*) AS linked_alert_count,
                COUNT(*) FILTER (WHERE visibility_level IN ('visible_primary', 'visible_supporting')) AS visible_alert_count,
                COUNT(*) FILTER (WHERE visibility_level IN ('collapsed_duplicate', 'collapsed_noise')) AS suppressed_alert_count,
                COUNT(*) FILTER (WHERE runtime_alert_role = 'trigger') AS trigger_alert_count,
                COUNT(*) FILTER (WHERE runtime_alert_role = 'duplicate') AS duplicate_alert_count,
                COUNT(*) FILTER (WHERE runtime_alert_role = 'noise') AS noise_alert_count
            FROM {RUNTIME_SCHEMA}.alert_case_links
            """,
        )
    )
    return row or {}

