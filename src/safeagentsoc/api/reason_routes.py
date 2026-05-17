from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from safeagentsoc.api.dependencies import get_db
from safeagentsoc.api.utils import cursor_all, cursor_one
from safeagentsoc.storage.repository import ensure_runtime_query


router = APIRouter(tags=["runtime-reasoning"])
RUNTIME_SCHEMA = "safeagentsoc_runtime"


def runtime_query(db: Any, query: str, params: dict[str, Any] | None = None) -> Any:
    ensure_runtime_query(query)
    return db.execute(query, params)


@router.get("/cases/{case_id}/hypotheses")
def get_case_hypotheses(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT case_id, provider, raw_record
            FROM {RUNTIME_SCHEMA}.case_hypotheses_raw
            WHERE case_id = %(case_id)s
            """,
            {"case_id": case_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Raw hypotheses not found")
    return row


@router.get("/cases/{case_id}/hypotheses/validated")
def get_validated_case_hypotheses(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT case_id, validation_status, validated_record
            FROM {RUNTIME_SCHEMA}.case_hypotheses_validated
            WHERE case_id = %(case_id)s
            """,
            {"case_id": case_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Validated hypotheses not found")
    return row


@router.get("/cases/hypotheses/failed")
def list_failed_case_hypotheses(limit: int = 100, db: Any = Depends(get_db)) -> dict[str, Any]:
    safe_limit = max(1, min(limit, 1000))
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT case_id, validation_status, validated_record
            FROM {RUNTIME_SCHEMA}.case_hypotheses_validated
            WHERE validation_status = 'failed'
            ORDER BY case_id
            LIMIT %(limit)s
            """,
            {"limit": safe_limit},
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/cases/{case_id}/recommended-checks")
def get_case_recommended_checks(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT validated_record
            FROM {RUNTIME_SCHEMA}.case_hypotheses_validated
            WHERE case_id = %(case_id)s
            """,
            {"case_id": case_id},
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Validated hypotheses not found")
    checks = []
    for hypothesis in row["validated_record"].get("hypotheses") or []:
        checks.append(
            {
                "case_id": case_id,
                "hypothesis_id": hypothesis.get("hypothesis_id"),
                "recommended_checks": hypothesis.get("recommended_checks") or [],
            }
        )
    return {"case_id": case_id, "count": len(checks), "items": checks}


@router.get("/cases/{case_id}/ai-decision-ledger")
def get_case_ai_decision_ledger(case_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT decision_id, case_id, agent_id, ledger_record
            FROM {RUNTIME_SCHEMA}.ai_decision_ledger
            WHERE case_id = %(case_id)s
            ORDER BY created_at_utc, decision_id
            """,
            {"case_id": case_id},
        )
    )
    return {"case_id": case_id, "count": len(rows), "items": rows}


@router.get("/metrics/llm-grounding")
def get_llm_grounding_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    row = cursor_one(
        runtime_query(
            db,
            f"""
            SELECT metrics
            FROM {RUNTIME_SCHEMA}.hypothesis_runs
            ORDER BY generated_at_utc DESC
            LIMIT 1
            """,
        )
    )
    return row or {"metrics": {}}


@router.get("/metrics/agent-firewall")
def get_agent_firewall_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT check_type, agent_id, blocked, COUNT(*) AS result_count
            FROM {RUNTIME_SCHEMA}.agent_firewall_results
            GROUP BY check_type, agent_id, blocked
            ORDER BY check_type, agent_id, blocked DESC
            """,
        )
    )
    return {"count": len(rows), "items": rows}


@router.get("/metrics/prompt-injection")
def get_prompt_injection_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    rows = cursor_all(
        runtime_query(
            db,
            f"""
            SELECT result_record
            FROM {RUNTIME_SCHEMA}.agent_firewall_results
            WHERE check_type = 'prompt_injection'
            ORDER BY result_id
            """,
        )
    )
    blocked = sum(1 for row in rows if row["result_record"].get("blocked") is True)
    return {
        "test_count": len(rows),
        "blocked_count": blocked,
        "prompt_injection_rejection_rate": round(blocked / max(len(rows), 1), 4),
        "items": rows,
    }
