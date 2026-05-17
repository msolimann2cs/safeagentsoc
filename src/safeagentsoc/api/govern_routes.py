from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from safeagentsoc.api.dependencies import get_db
from safeagentsoc.api.utils import cursor_all, cursor_one
from safeagentsoc.storage.repository import ensure_runtime_query


router = APIRouter(tags=["runtime-governance"])
RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(db: Any, query: str, params: dict[str, Any] | None = None) -> Any:
    ensure_runtime_query(query)
    return db.execute(query, params)


def _case_records(db: Any, table: str, case_id: str, order_by: str = "case_id") -> list[dict[str, Any]]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT result_record
            FROM {RUNTIME_SCHEMA}.{table}
            WHERE case_id = %(case_id)s
            ORDER BY {order_by}
            """,
            {"case_id": case_id},
        )
    )
    return [row["result_record"] for row in rows]


def _case_record(db: Any, table: str, case_id: str) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT result_record
            FROM {RUNTIME_SCHEMA}.{table}
            WHERE case_id = %(case_id)s
            LIMIT 1
            """,
            {"case_id": case_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Phase 9 governance object not found")
    return row["result_record"]


@router.get("/cases/{case_id}/risk")
def get_case_risk(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    return _case_record(db, "incident_risk_scores", case_id)


@router.get("/cases/{case_id}/uncertainty")
def get_case_uncertainty(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    return _case_record(db, "uncertainty_assessments", case_id)


@router.get("/cases/{case_id}/recommendations")
def get_case_recommendations(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    items = _case_records(db, "safe_recommendations", case_id, "result_record->>'recommendation_rank'")
    return {"case_id": case_id, "count": len(items), "items": items}


@router.get("/cases/{case_id}/policy-decisions")
def get_case_policy_decisions(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    items = _case_records(db, "policy_decisions", case_id, "result_record->>'action_id'")
    return {"case_id": case_id, "count": len(items), "items": items}


@router.get("/cases/{case_id}/soar-dry-run")
def get_case_soar_dry_run(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    items = _case_records(db, "soar_dry_runs", case_id, "result_record->>'action_id'")
    return {"case_id": case_id, "count": len(items), "items": items}


@router.get("/cases/{case_id}/csirt-pack")
def get_case_csirt_pack(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    return _case_record(db, "csirt_coordination_packs", case_id)


@router.get("/cases/{case_id}/ciso-brief")
def get_case_ciso_brief(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    return _case_record(db, "ciso_decision_briefs", case_id)


@router.get("/cases/{case_id}/stakeholder-messages")
def get_case_stakeholder_messages(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    items = _case_records(db, "stakeholder_messages", case_id, "result_record->>'audience'")
    return {"case_id": case_id, "count": len(items), "items": items}


@router.get("/metrics/grc-policy")
def get_grc_policy_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    metrics = _latest_metrics(db)
    return {
        "policy_decision_count": metrics.get("policy_decision_count", 0),
        "blocked_action_count": metrics.get("blocked_action_count", 0),
        "approval_required_count": metrics.get("approval_required_count", 0),
        "framework_mapping_count": metrics.get("framework_mapping_count", 0),
        "metrics": metrics,
    }


@router.get("/metrics/ciso-value")
def get_ciso_value_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    metrics = _latest_metrics(db)
    return {
        "case_count": metrics.get("case_count", 0),
        "high_or_critical_case_count": metrics.get("high_or_critical_case_count", 0),
        "ciso_brief_count": metrics.get("ciso_brief_count", 0),
        "csirt_pack_count": metrics.get("csirt_pack_count", 0),
        "decision_traceability_score": metrics.get("decision_traceability_score", 0),
        "metrics": metrics,
    }


@router.get("/metrics/unsafe-action-blocking")
def get_unsafe_action_blocking_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    metrics = _latest_metrics(db)
    return {
        "unsafe_action_block_rate": metrics.get("unsafe_action_block_rate", 0),
        "action_catalog_violation_rate": metrics.get("action_catalog_violation_rate", 0),
        "public_message_overclaim_rate": metrics.get("public_message_overclaim_rate", 0),
        "runtime_leakage_count": metrics.get("runtime_leakage_count", 0),
        "metrics": metrics,
    }


def _latest_metrics(db: Any) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT metrics
            FROM {RUNTIME_SCHEMA}.phase9_governance_runs
            ORDER BY generated_at_utc DESC
            LIMIT 1
            """,
        )
    )
    return (row or {}).get("metrics") or {}
