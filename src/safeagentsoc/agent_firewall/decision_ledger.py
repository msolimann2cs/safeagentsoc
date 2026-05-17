from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from typing import Any


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def ledger_entry(
    *,
    case_id: str,
    agent_id: str,
    input_record: Any,
    raw_output: Any,
    validated_output: Any,
    schema_validation_status: str,
    evidence_validation_status: str,
    unsupported_claim_count: int,
) -> dict[str, Any]:
    decision_seed = f"{case_id}|{agent_id}|{stable_hash(input_record)[:16]}|{stable_hash(raw_output)[:16]}"
    return {
        "decision_id": "ai_decision_" + hashlib.sha256(decision_seed.encode("utf-8")).hexdigest()[:24],
        "case_id": case_id,
        "agent_id": agent_id,
        "input_hash": stable_hash(input_record),
        "output_hash": stable_hash(raw_output),
        "validated_output_hash": stable_hash(validated_output),
        "schema_validation_status": schema_validation_status,
        "evidence_validation_status": evidence_validation_status,
        "unsupported_claim_count": unsupported_claim_count,
        "created_at_utc": datetime.now(UTC).isoformat(),
    }

