from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from safeagentsoc.api.dependencies import get_db
from safeagentsoc.api.utils import cursor_all, cursor_one
from safeagentsoc.storage.repository import ensure_runtime_query


router = APIRouter(tags=["runtime-context"])
RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(db: Any, query: str, params: dict[str, Any] | None = None) -> Any:
    ensure_runtime_query(query)
    return db.execute(query, params)


@router.get("/context/assets")
def list_assets(
    business_unit: str | None = None,
    business_service: str | None = None,
    asset_criticality: str | None = None,
    data_classification: str | None = None,
    network_zone: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Any = Depends(get_db),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if business_unit:
        clauses.append("business_unit = %(business_unit)s")
        params["business_unit"] = business_unit
    if business_service:
        clauses.append("business_service = %(business_service)s")
        params["business_service"] = business_service
    if asset_criticality:
        clauses.append("asset_criticality = %(asset_criticality)s")
        params["asset_criticality"] = asset_criticality
    if data_classification:
        clauses.append("data_classification = %(data_classification)s")
        params["data_classification"] = data_classification
    if network_zone:
        clauses.append("network_zone = %(network_zone)s")
        params["network_zone"] = network_zone
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.context_assets
            {where_sql}
            ORDER BY asset_id
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            params,
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/context/assets/{asset_id}")
def get_asset(asset_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(db, f"SELECT * FROM {RUNTIME_SCHEMA}.context_assets WHERE asset_id = %(asset_id)s", {"asset_id": asset_id})
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Context asset not found")
    return row


@router.get("/context/identities")
def list_identities(
    privileged_account: bool | None = None,
    service_account: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Any = Depends(get_db),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if privileged_account is not None:
        clauses.append("privileged_account = %(privileged_account)s")
        params["privileged_account"] = privileged_account
    if service_account is not None:
        clauses.append("service_account = %(service_account)s")
        params["service_account"] = service_account
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.context_identities
            {where_sql}
            ORDER BY identity_id
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            params,
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/context/identities/{identity_id}")
def get_identity(identity_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"SELECT * FROM {RUNTIME_SCHEMA}.context_identities WHERE identity_id = %(identity_id)s",
            {"identity_id": identity_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Context identity not found")
    return row


@router.get("/context/network-zones")
def list_network_zones(db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(runtime_query(db, f"SELECT * FROM {RUNTIME_SCHEMA}.context_network_zones ORDER BY network_zone_id"))
    return {"count": len(rows), "items": rows}


@router.get("/context/business-services")
def list_business_services(db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(runtime_query(db, f"SELECT * FROM {RUNTIME_SCHEMA}.context_business_services ORDER BY business_service_id"))
    return {"count": len(rows), "items": rows}


@router.get("/context/policies")
def list_policies(db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(runtime_query(db, f"SELECT * FROM {RUNTIME_SCHEMA}.context_policy_catalog ORDER BY policy_id"))
    return {"count": len(rows), "items": rows}


@router.get("/alerts/enriched")
def list_enriched_alerts(
    business_unit: str | None = None,
    business_service: str | None = None,
    asset_criticality: str | None = None,
    data_classification: str | None = None,
    network_zone: str | None = None,
    business_risk_label: str | None = None,
    analyst_priority_label: str | None = None,
    context_confidence_min: float | None = Query(default=None, ge=0, le=1),
    missing_context: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Any = Depends(get_db),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if business_unit:
        clauses.append("business_unit = %(business_unit)s")
        params["business_unit"] = business_unit
    if business_service:
        clauses.append("business_service = %(business_service)s")
        params["business_service"] = business_service
    if business_risk_label:
        clauses.append("business_risk_label = %(business_risk_label)s")
        params["business_risk_label"] = business_risk_label
    if analyst_priority_label:
        clauses.append("analyst_priority_label = %(analyst_priority_label)s")
        params["analyst_priority_label"] = analyst_priority_label
    if context_confidence_min is not None:
        clauses.append("context_confidence >= %(context_confidence_min)s")
        params["context_confidence_min"] = context_confidence_min
    if missing_context is not None:
        clauses.append("(cardinality(missing_context_fields) > 0) = %(missing_context)s")
        params["missing_context"] = missing_context
    if asset_criticality:
        clauses.append("(context_enriched_alert->'asset_context'->>'asset_criticality') = %(asset_criticality)s")
        params["asset_criticality"] = asset_criticality
    if data_classification:
        clauses.append("(context_enriched_alert->'asset_context'->>'data_classification') = %(data_classification)s")
        params["data_classification"] = data_classification
    if network_zone:
        clauses.append("(context_enriched_alert->'network_context'->>'network_zone') = %(network_zone)s")
        params["network_zone"] = network_zone
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT
                alert_uid,
                evidence_id,
                mapping_id,
                asset_id,
                identity_id,
                network_zone_id,
                business_unit,
                business_service,
                business_risk_score,
                business_risk_label,
                analyst_priority_score,
                analyst_priority_label,
                urgent_priority_gate_passed,
                risk_confidence,
                context_confidence,
                missing_context_fields,
                context_enriched_alert
            FROM {RUNTIME_SCHEMA}.context_enriched_alerts
            {where_sql}
            ORDER BY analyst_priority_score DESC NULLS LAST, business_risk_score DESC NULLS LAST, context_confidence DESC NULLS LAST, alert_uid
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            params,
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/alerts/enriched/high-risk")
def list_high_risk_enriched_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Any = Depends(get_db),
) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.context_enriched_alerts
            WHERE business_risk_label IN ('high', 'critical')
            ORDER BY business_risk_score DESC NULLS LAST, alert_uid
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            {"limit": limit, "offset": offset},
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/alerts/enriched/high-priority")
def list_high_priority_enriched_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Any = Depends(get_db),
) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.context_enriched_alerts
            WHERE analyst_priority_label IN ('high', 'critical')
            ORDER BY analyst_priority_score DESC NULLS LAST, business_risk_score DESC NULLS LAST, alert_uid
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            {"limit": limit, "offset": offset},
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/alerts/{alert_uid}/context")
def get_alert_context(alert_uid: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.context_enriched_alerts
            WHERE alert_uid = %(alert_uid)s
            """,
            {"alert_uid": alert_uid},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Context-enriched alert not found")
    return row


@router.get("/metrics/context-coverage")
def context_coverage_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT
                (SELECT COUNT(*) FROM {RUNTIME_SCHEMA}.normalized_alerts) AS total_normalized_alerts,
                COUNT(*) AS total_context_enriched_alerts,
                ROUND((COUNT(*) FILTER (WHERE asset_id IS NOT NULL))::numeric / NULLIF(COUNT(*), 0), 4) AS asset_context_coverage_rate,
                ROUND((COUNT(*) FILTER (WHERE identity_id IS NOT NULL))::numeric / NULLIF(COUNT(*), 0), 4) AS identity_context_coverage_rate,
                ROUND((COUNT(*) FILTER (WHERE identity_id IS NOT NULL))::numeric / NULLIF(COUNT(*), 0), 4) AS identity_context_coverage_all_alerts,
                ROUND((COUNT(*) FILTER (WHERE identity_applicability_status = 'resolved'))::numeric
                    / NULLIF(COUNT(*) FILTER (WHERE identity_applicability_status IN ('resolved', 'missing')), 0), 4)
                    AS identity_context_coverage_identity_applicable_alerts,
                COUNT(*) FILTER (WHERE identity_applicability_status IN ('resolved', 'missing')) AS identity_applicable_alert_count,
                COUNT(*) FILTER (WHERE identity_applicability_status = 'resolved') AS identity_resolved_alert_count,
                COUNT(*) FILTER (WHERE identity_applicability_status = 'not_applicable') AS identity_not_applicable_alert_count,
                COUNT(*) FILTER (WHERE identity_applicability_status = 'missing') AS identity_missing_alert_count,
                COUNT(*) FILTER (WHERE identity_applicability_status = 'unknown') AS identity_unknown_applicability_alert_count,
                ROUND((COUNT(*) FILTER (WHERE network_zone_id IS NOT NULL))::numeric / NULLIF(COUNT(*), 0), 4) AS network_context_coverage_rate,
                ROUND((COUNT(*) FILTER (WHERE business_service IS NOT NULL))::numeric / NULLIF(COUNT(*), 0), 4) AS business_service_coverage_rate,
                ROUND((COUNT(*) FILTER (
                    WHERE jsonb_array_length(COALESCE(context_enriched_alert->'policy_context'->'relevant_policy_ids', '[]'::jsonb)) > 0
                ))::numeric / NULLIF(COUNT(*), 0), 4) AS policy_context_coverage_rate,
                ROUND(AVG(context_confidence), 4) AS context_confidence_average,
                ROUND((COUNT(*) FILTER (WHERE analyst_priority_score IS NOT NULL))::numeric / NULLIF(COUNT(*), 0), 4)
                    AS analyst_priority_score_coverage_rate,
                COUNT(*) FILTER (WHERE analyst_priority_label IN ('high', 'critical')) AS urgent_analyst_priority_count,
                COUNT(*) FILTER (WHERE cardinality(missing_context_fields) > 0) AS missing_context_alert_count
            FROM {RUNTIME_SCHEMA}.context_enriched_alerts
            """,
        )
    )
    return row or {}


@router.get("/metrics/business-risk")
def business_risk_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    by_label = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT
                business_risk_label,
                COUNT(*) AS alert_count,
                ROUND(AVG(business_risk_score), 2) AS average_business_risk_score,
                MAX(business_risk_score) AS max_business_risk_score
            FROM {RUNTIME_SCHEMA}.context_enriched_alerts
            GROUP BY business_risk_label
            ORDER BY average_business_risk_score DESC NULLS LAST
            """,
        )
    )
    high_risk_by_mapping_rule_type = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT
                COALESCE(context_enriched_alert->'context_metadata'->>'mapping_rule_type', 'unknown') AS mapping_rule_type,
                COALESCE(context_enriched_alert->'context_metadata'->>'mapping_rule_id', 'unknown') AS mapping_rule_id,
                COUNT(*) AS high_risk_alert_count,
                ROUND(
                    COUNT(*)::numeric / NULLIF(
                        SUM(COUNT(*)) OVER (),
                        0
                    ),
                    4
                ) AS high_risk_alert_rate
            FROM {RUNTIME_SCHEMA}.context_enriched_alerts
            WHERE business_risk_label IN ('high', 'critical')
            GROUP BY mapping_rule_type, mapping_rule_id
            ORDER BY high_risk_alert_count DESC, mapping_rule_type, mapping_rule_id
            """,
        )
    )
    return {
        "count": len(by_label),
        "items": by_label,
        "high_risk_by_mapping_rule_type": high_risk_by_mapping_rule_type,
    }


@router.get("/metrics/analyst-priority")
def analyst_priority_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    by_label = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT
                analyst_priority_label,
                COUNT(*) AS alert_count,
                ROUND(AVG(analyst_priority_score), 2) AS average_analyst_priority_score,
                MAX(analyst_priority_score) AS max_analyst_priority_score
            FROM {RUNTIME_SCHEMA}.context_enriched_alerts
            GROUP BY analyst_priority_label
            ORDER BY average_analyst_priority_score DESC NULLS LAST
            """,
        )
    )
    urgent_by_mapping_rule_type = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT
                COALESCE(context_enriched_alert->'context_metadata'->>'mapping_rule_type', 'unknown') AS mapping_rule_type,
                COALESCE(context_enriched_alert->'context_metadata'->>'mapping_rule_id', 'unknown') AS mapping_rule_id,
                COUNT(*) AS urgent_alert_count,
                ROUND(COUNT(*)::numeric / NULLIF(SUM(COUNT(*)) OVER (), 0), 4) AS urgent_alert_rate
            FROM {RUNTIME_SCHEMA}.context_enriched_alerts
            WHERE analyst_priority_label IN ('high', 'critical')
            GROUP BY mapping_rule_type, mapping_rule_id
            ORDER BY urgent_alert_count DESC, mapping_rule_type, mapping_rule_id
            """,
        )
    )
    suppressor_rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT
                suppressor,
                COUNT(*) AS alert_count
            FROM (
                SELECT jsonb_array_elements_text(
                    COALESCE(context_enriched_alert->'analyst_priority'->'suppressors', '[]'::jsonb)
                ) AS suppressor
                FROM {RUNTIME_SCHEMA}.context_enriched_alerts
            ) AS expanded
            GROUP BY suppressor
            ORDER BY alert_count DESC, suppressor
            LIMIT 20
            """,
        )
    )
    return {
        "count": len(by_label),
        "items": by_label,
        "urgent_by_mapping_rule_type": urgent_by_mapping_rule_type,
        "top_suppressors": suppressor_rows,
    }
