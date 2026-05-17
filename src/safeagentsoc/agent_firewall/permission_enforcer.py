from __future__ import annotations

from dataclasses import asdict
from typing import Any

from safeagentsoc.agent_firewall.agent_identity import AGENT_PERMISSIONS, get_agent_permission


def enforce_permission(agent_id: str, operation: str, resource: str) -> dict[str, Any]:
    permission = get_agent_permission(agent_id)
    if operation not in {"read", "write"}:
        raise ValueError(f"Unsupported permission operation: {operation}")
    denied = resource in (permission.cannot_read if operation == "read" else permission.cannot_write)
    allowed = resource in (permission.can_read if operation == "read" else permission.can_write)
    return {
        "agent_id": agent_id,
        "operation": operation,
        "resource": resource,
        "allowed": bool(allowed and not denied),
        "reason": "allowed by explicit permission" if allowed and not denied else "blocked by Agent Firewall permission matrix",
    }


def permission_matrix_rows() -> list[dict[str, Any]]:
    return [asdict(permission) for permission in AGENT_PERMISSIONS.values()]


def run_unauthorized_permission_tests() -> list[dict[str, Any]]:
    tests = [
        ("hypothesis_generator", "read", "ground_truth"),
        ("hypothesis_generator", "write", "response_actions"),
        ("evidence_verifier", "read", "casebook"),
        ("decision_ledger_writer", "write", "response_actions"),
    ]
    return [enforce_permission(agent_id, operation, resource) for agent_id, operation, resource in tests]

