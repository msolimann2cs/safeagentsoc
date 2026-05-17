from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from safeagentsoc.govern.io_utils import to_plain
from safeagentsoc.govern.schemas import Phase9LedgerEntry


def ledger_entry(case_id: str, object_type: str, object_id: str, decision: str, reason: str, evidence_ids: list[str], source: Any, output: Any) -> Phase9LedgerEntry:
    created = datetime.now(timezone.utc).isoformat()
    return Phase9LedgerEntry(
        decision_id=f"{case_id}|{object_type}|{object_id}|ledger",
        case_id=case_id,
        object_type=object_type,
        object_id=object_id,
        decision=decision,
        reason=reason,
        evidence_ids=evidence_ids[:10],
        input_hash=sha256_json(source),
        output_hash=sha256_json(output),
        created_at_utc=created,
    )


def sha256_json(value: Any) -> str:
    encoded = json.dumps(to_plain(value), sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
