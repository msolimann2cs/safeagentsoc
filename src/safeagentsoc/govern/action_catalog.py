from __future__ import annotations

from pathlib import Path
from typing import Any

from safeagentsoc.govern.io_utils import load_config
from safeagentsoc.govern.schemas import ResponseAction


def load_action_catalog(path: Path) -> dict[str, ResponseAction]:
    raw = load_config(path)
    actions = raw.get("actions", raw if isinstance(raw, dict) else {})
    return {action_id: ResponseAction(action_id=action_id, **data) for action_id, data in actions.items()}


def validate_action_id(action_id: str, catalog: dict[str, ResponseAction]) -> bool:
    return action_id in catalog


def candidate_actions_for_case(risk_label: str, has_identity: bool, graph_status: str) -> list[str]:
    actions = [
        "add_case_note",
        "continue_monitoring",
        "review_logs",
        "inspect_endpoint_telemetry",
        "check_related_alerts",
    ]
    if risk_label in {"medium", "high", "critical"}:
        actions.extend(["create_analyst_task", "escalate_to_tier2", "request_edr_scan", "open_it_ticket"])
    if has_identity and risk_label in {"high", "critical"}:
        actions.extend(["verify_user_activity", "force_mfa_reauth", "disable_active_sessions", "disable_user_account"])
    if risk_label == "critical" or graph_status == "feasible":
        actions.extend(["isolate_endpoint", "notify_legal", "notify_executive_team"])
    actions.extend(["generate_ciso_brief", "prepare_holding_statement", "public_customer_communication"])
    return list(dict.fromkeys(actions))


def action_to_dict(action: ResponseAction) -> dict[str, Any]:
    return action.to_dict()
