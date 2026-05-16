from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from safeagentsoc.api.dependencies import get_db
from safeagentsoc.api.utils import cursor_one
from safeagentsoc.storage.repository import RuntimeAlertRepository


router = APIRouter(tags=["runtime-evidence"])


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    repo = RuntimeAlertRepository(db)
    row = cursor_one(repo.get_evidence(evidence_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence reference not found")
    return row


@router.get("/rules/{rule_id}")
def get_rule(rule_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    repo = RuntimeAlertRepository(db)
    row = cursor_one(repo.get_rule(rule_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return row


@router.get("/mitre/{technique_id}")
def get_mitre(technique_id: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    repo = RuntimeAlertRepository(db)
    row = cursor_one(repo.get_mitre(technique_id))
    if row is None:
        raise HTTPException(status_code=404, detail="MITRE technique not found")
    return row
