from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from safeagentsoc.api.dependencies import get_db
from safeagentsoc.api.utils import cursor_all, cursor_one
from safeagentsoc.storage.repository import ensure_runtime_query


router = APIRouter(tags=["runtime-graph-validation"])
RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(db: Any, query: str, params: dict[str, Any] | None = None) -> Any:
    ensure_runtime_query(query)
    return db.execute(query, params)


@router.get("/cases/{case_id}/graph-validation")
def get_case_graph_validation(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT result_record
            FROM {RUNTIME_SCHEMA}.graph_validation_results
            WHERE case_id = %(case_id)s
            ORDER BY hypothesis_id, claim_id
            """,
            {"case_id": case_id},
        )
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Graph validation not found")
    return {"case_id": case_id, "count": len(rows), "items": [row["result_record"] for row in rows]}


@router.get("/cases/{case_id}/graph-claims")
def get_case_graph_claims(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT claim_record
            FROM {RUNTIME_SCHEMA}.hypothesis_graph_claims
            WHERE case_id = %(case_id)s
            ORDER BY hypothesis_id, claim_id
            """,
            {"case_id": case_id},
        )
    )
    return {"case_id": case_id, "count": len(rows), "items": [row["claim_record"] for row in rows]}


@router.get("/cases/{case_id}/graph-evidence")
def get_case_graph_evidence(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    resolutions = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT result_record
            FROM {RUNTIME_SCHEMA}.claim_entity_resolution
            WHERE case_id = %(case_id)s
            ORDER BY hypothesis_id, claim_id
            """,
            {"case_id": case_id},
        )
    )
    missing = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT result_record
            FROM {RUNTIME_SCHEMA}.missing_graph_evidence
            WHERE case_id = %(case_id)s
            ORDER BY hypothesis_id, claim_id
            """,
            {"case_id": case_id},
        )
    )
    return {
        "case_id": case_id,
        "entity_resolution_count": len(resolutions),
        "missing_graph_evidence_count": len(missing),
        "entity_resolution": [row["result_record"] for row in resolutions],
        "missing_graph_evidence": [row["result_record"] for row in missing],
    }


@router.get("/cases/{case_id}/graph-visualization")
def get_case_graph_visualization(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT export_record
            FROM {RUNTIME_SCHEMA}.case_graph_exports
            WHERE case_id = %(case_id)s
            """,
            {"case_id": case_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Case graph visualization not found")
    return row["export_record"]


@router.get("/hypotheses/{hypothesis_id}/graph-validation")
def get_hypothesis_graph_validation(hypothesis_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT result_record
            FROM {RUNTIME_SCHEMA}.graph_validation_results
            WHERE hypothesis_id = %(hypothesis_id)s
            ORDER BY case_id, claim_id
            """,
            {"hypothesis_id": hypothesis_id},
        )
    )
    return {"hypothesis_id": hypothesis_id, "count": len(rows), "items": [row["result_record"] for row in rows]}


@router.get("/metrics/graph-validation")
def get_graph_validation_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT metrics
            FROM {RUNTIME_SCHEMA}.graph_validation_runs
            ORDER BY generated_at_utc DESC
            LIMIT 1
            """,
        )
    )
    return row or {"metrics": {}}


@router.get("/metrics/hallucination-rejection")
def get_hallucination_rejection_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT metrics
            FROM {RUNTIME_SCHEMA}.graph_validation_runs
            ORDER BY generated_at_utc DESC
            LIMIT 1
            """,
        )
    )
    metrics = (row or {}).get("metrics") or {}
    return {
        "hallucination_reduction_rate": metrics.get("hallucination_reduction_rate", 0),
        "infeasible_path_rejection_rate": metrics.get("infeasible_path_rejection_rate", 0),
        "conditional_path_detection_rate": metrics.get("conditional_path_detection_rate", 0),
        "runtime_ground_truth_exposure_count": metrics.get("runtime_ground_truth_exposure_count", 0),
        "metrics": metrics,
    }
