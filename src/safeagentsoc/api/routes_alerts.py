from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from safeagentsoc.api.dependencies import get_db
from safeagentsoc.api.utils import cursor_all, cursor_one
from safeagentsoc.storage.repository import RuntimeAlertRepository


router = APIRouter(tags=["runtime-alerts"])


@router.get("/alerts")
def list_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    agent_name: str | None = None,
    platform: str | None = None,
    rule_id: str | None = None,
    rule_level: int | None = None,
    decoder_name: str | None = None,
    event_category: str | None = None,
    event_action: str | None = None,
    event_outcome: str | None = None,
    normalized_severity: str | None = None,
    mitre_technique_id: str | None = None,
    timestamp_from: str | None = None,
    timestamp_to: str | None = None,
    source: str | None = None,
    normalization_status: str | None = None,
    db: Any = Depends(get_db),
) -> dict[str, Any]:
    repo = RuntimeAlertRepository(db)
    cursor = repo.list_alerts(
        limit=limit,
        offset=offset,
        agent_name=agent_name,
        platform=platform,
        rule_id=rule_id,
        rule_level=rule_level,
        decoder_name=decoder_name,
        event_category=event_category,
        event_action=event_action,
        event_outcome=event_outcome,
        severity=normalized_severity,
        mitre_technique_id=mitre_technique_id,
        timestamp_from=timestamp_from,
        timestamp_to=timestamp_to,
        source=source,
        normalization_status=normalization_status,
    )
    rows = cursor_all(cursor)
    return {"count": len(rows), "items": rows}


@router.get("/alerts/{alert_uid}")
def get_alert(alert_uid: str, db: Any = Depends(get_db)) -> dict[str, Any]:
    repo = RuntimeAlertRepository(db)
    row = cursor_one(repo.get_alert(alert_uid))
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row
