from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from safeagentsoc.api.dependencies import get_db
from safeagentsoc.api.utils import cursor_all, cursor_one
from safeagentsoc.storage.repository import ensure_runtime_query


router = APIRouter(tags=["runtime-timelines"])
RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(db: Any, query: str, params: dict[str, Any] | None = None) -> Any:
    ensure_runtime_query(query)
    return db.execute(query, params)


@router.get("/cases/{case_id}/timeline")
def get_phase6_timeline(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"SELECT case_id, timeline_record FROM {RUNTIME_SCHEMA}.case_timelines WHERE case_id = %(case_id)s",
            {"case_id": case_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Phase 6 timeline not found")
    return row


@router.get("/cases/{case_id}/attack-story")
def get_attack_story(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"SELECT case_id, story_record FROM {RUNTIME_SCHEMA}.case_attack_stories WHERE case_id = %(case_id)s",
            {"case_id": case_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Attack story not found")
    return row


@router.get("/cases/{case_id}/mitre-chain")
def get_mitre_chain(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT technique_id, tactic, claim_type, confidence_score, claim_record
            FROM {RUNTIME_SCHEMA}.case_technique_claims
            WHERE case_id = %(case_id)s
            ORDER BY confidence_score DESC, tactic, technique_id
            """,
            {"case_id": case_id},
        )
    )
    return {"case_id": case_id, "count": len(rows), "items": rows}


@router.get("/cases/{case_id}/missing-evidence")
def get_missing_evidence(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT missing_evidence_type, status, missing_record
            FROM {RUNTIME_SCHEMA}.case_missing_evidence
            WHERE case_id = %(case_id)s
            ORDER BY missing_evidence_type
            """,
            {"case_id": case_id},
        )
    )
    return {"case_id": case_id, "count": len(rows), "items": rows}


@router.get("/cases/{case_id}/kill-chain")
def get_kill_chain(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"SELECT case_id, progression_depth, progression_record FROM {RUNTIME_SCHEMA}.case_kill_chain_progression WHERE case_id = %(case_id)s",
            {"case_id": case_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Kill-chain progression not found")
    return row


@router.get("/metrics/mitre-coverage")
def get_mitre_coverage(db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT tactic, technique_id, COUNT(DISTINCT case_id) AS case_count,
                   AVG(confidence_score) AS avg_confidence,
                   COUNT(*) FILTER (WHERE claim_type = 'observed') AS observed_count,
                   COUNT(*) FILTER (WHERE claim_type = 'inferred') AS inferred_count
            FROM {RUNTIME_SCHEMA}.case_technique_claims
            GROUP BY tactic, technique_id
            ORDER BY case_count DESC, avg_confidence DESC
            """,
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/metrics/timeline-quality")
def get_timeline_quality(db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"SELECT metric, value FROM {RUNTIME_SCHEMA}.timeline_quality_metrics ORDER BY metric",
        )
    )
    return {"metrics": {row["metric"]: row["value"] for row in rows}}


@router.get("/metrics/missing-evidence")
def get_missing_evidence_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT missing_evidence_type, status, COUNT(*) AS case_count
            FROM {RUNTIME_SCHEMA}.case_missing_evidence
            GROUP BY missing_evidence_type, status
            ORDER BY missing_evidence_type, status
            """,
        )
    )
    return {"count": len(rows), "items": rows}

