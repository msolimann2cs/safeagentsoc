from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from safeagentsoc.api.dependencies import get_db
from safeagentsoc.api.utils import cursor_all, cursor_one
from safeagentsoc.storage.repository import RuntimeAlertRepository


router = APIRouter(tags=["runtime-metrics"])


@router.get("/metrics/normalization")
def normalization_metrics(db: Any = Depends(get_db)) -> dict[str, Any]:
    repo = RuntimeAlertRepository(db)
    rows = cursor_all(repo.normalization_metrics())
    return {"count": len(rows), "items": rows}


@router.get("/metrics/runtime-summary")
def runtime_summary(db: Any = Depends(get_db)) -> dict[str, Any]:
    repo = RuntimeAlertRepository(db)
    row = cursor_one(repo.runtime_summary())
    return row or {}
