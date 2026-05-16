from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from safeagentsoc.adapters.wazuh.jsonl_parser import get_nested


UID_STRATEGY_VERSION = "alert_uid_v1"
EVIDENCE_ID_VERSION = "evidence_id_v1"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def normalize_component(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list)):
        return canonical_json(value)
    return str(value)


def stable_uid_components(raw_alert: dict[str, Any]) -> dict[str, str | None]:
    full_log = normalize_component(get_nested(raw_alert, "full_log"))
    return {
        "timestamp": normalize_component(get_nested(raw_alert, "timestamp")),
        "agent_name": normalize_component(get_nested(raw_alert, "agent.name")),
        "rule_id": normalize_component(get_nested(raw_alert, "rule.id")),
        "decoder_name": normalize_component(get_nested(raw_alert, "decoder.name")),
        "location": normalize_component(get_nested(raw_alert, "location")),
        "full_log_sha256": sha256_text(full_log) if full_log else None,
    }


def natural_alert_fingerprint(raw_alert: dict[str, Any]) -> str:
    payload = {
        "strategy": UID_STRATEGY_VERSION,
        "components": stable_uid_components(raw_alert),
    }
    return sha256_text(canonical_json(payload))


def build_alert_uid(
    raw_alert: dict[str, Any],
    raw_line_number: int,
    use_line_disambiguator: bool = False,
) -> str:
    payload: dict[str, Any] = {
        "strategy": UID_STRATEGY_VERSION,
        "components": stable_uid_components(raw_alert),
    }
    if use_line_disambiguator:
        payload["raw_line_number"] = raw_line_number

    return "alert_" + sha256_text(canonical_json(payload))[:32]


def build_evidence_id(alert_uid: str, raw_alert_sha256: str, ingestion_batch_id: str) -> str:
    payload = {
        "strategy": EVIDENCE_ID_VERSION,
        "alert_uid": alert_uid,
        "raw_alert_sha256": raw_alert_sha256,
        "ingestion_batch_id": ingestion_batch_id,
    }
    return "evidence_" + sha256_text(canonical_json(payload))[:32]
