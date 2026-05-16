from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException

from safeagentsoc.api.dependencies import eval_api_enabled, eval_api_token, get_db
from safeagentsoc.api.utils import cursor_all
from safeagentsoc.storage.repository import EvaluationRepository


router = APIRouter(prefix="/eval", tags=["evaluation-only"])


def require_eval_access(x_eval_token: str | None = Header(default=None)) -> None:
    if not eval_api_enabled():
        raise HTTPException(status_code=404, detail="Evaluation API is disabled")

    expected_token = eval_api_token()
    if expected_token and x_eval_token != expected_token:
        raise HTTPException(status_code=403, detail="Invalid evaluation API token")


@router.get("/labels/{alert_uid}", dependencies=[Depends(require_eval_access)])
def eval_labels(alert_uid: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    cursor = db.execute(
        """
        SELECT *
        FROM safeagentsoc_eval.ground_truth_labels
        WHERE alert_uid = %(alert_uid)s
        ORDER BY label_id
        """,
        {"alert_uid": alert_uid},
    )
    rows = cursor_all(cursor)
    return {"count": len(rows), "items": rows}


@router.get("/casebook", dependencies=[Depends(require_eval_access)])
def eval_casebook(db: Any = Depends(get_db)) -> dict[str, Any]:
    cursor = db.execute(
        """
        SELECT case_id, scenario_id, campaign_id, run_id, execution_mode, evaluation_source, loaded_batch_id, created_at_utc
        FROM safeagentsoc_eval.casebook_cases
        ORDER BY case_id
        LIMIT 500
        """
    )
    rows = cursor_all(cursor)
    return {"count": len(rows), "items": rows}


@router.get("/fatigue-baseline", dependencies=[Depends(require_eval_access)])
def eval_fatigue_baseline(db: Any = Depends(get_db)) -> dict[str, Any]:
    cursor = db.execute(
        """
        SELECT baseline_id, alert_uid, rule_id, rule_description, agent_name, event_time_utc, baseline_bucket, evaluation_source, loaded_batch_id
        FROM safeagentsoc_eval.alert_fatigue_baseline
        ORDER BY baseline_id
        LIMIT 1000
        """
    )
    rows = cursor_all(cursor)
    return {"count": len(rows), "items": rows}


@router.get("/linkage-metrics", dependencies=[Depends(require_eval_access)])
def eval_linkage_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    repo = EvaluationRepository(db)
    label_rows = cursor_all(repo.label_linkage_metrics())
    casebook_rows = cursor_all(repo.casebook_linkage_metrics())
    return {
        "labels": label_rows,
        "casebook": casebook_rows,
        "note": "Evaluation endpoints are disabled by default and must not be used by runtime or AI modules.",
    }
