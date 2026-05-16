from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any


UNKNOWN_CONTEXT_ASSET_ID = "__UNKNOWN__"

FORBIDDEN_MAPPING_TERMS = {
    "ground_truth",
    "expected_conclusion",
    "casebook_answer",
    "true_positive",
    "false_positive",
    "event_role",
    "scenario_label",
    "gold_label",
    "answer_key",
    "case_id",
    "scenario_id",
    "manual_label",
}

ALLOWED_RUNTIME_MATCH_FIELDS = {
    "agent_name",
    "hostname",
    "agent_ip",
    "platform",
    "user",
    "process_name",
    "process_command_line",
    "source_ip",
    "destination_ip",
    "file_path",
    "rule_id",
    "rule_description",
    "decoder_name",
    "event_category",
    "event_action",
    "event_outcome",
    "mitre_technique_ids",
    "mitre_tactics",
    "severity_normalized",
}

MATCH_COLUMNS = {
    "match_agent_name": "agent_name",
    "match_hostname": "hostname",
    "match_agent_ip": "agent_ip",
    "match_user": "user",
    "match_platform": "platform",
    "match_rule_id": "rule_id",
    "match_rule_contains": "rule_description",
    "match_decoder_name": "decoder_name",
    "match_event_category": "event_category",
    "match_event_action": "event_action",
    "match_event_outcome": "event_outcome",
    "match_mitre_contains": "mitre_technique_ids",
    "match_process_name_contains": "process_name",
    "match_command_line_contains": "process_command_line",
    "match_file_path_contains": "file_path",
    "match_severity": "severity_normalized",
}

CONTAINS_COLUMNS = {
    "match_rule_contains",
    "match_mitre_contains",
    "match_process_name_contains",
    "match_command_line_contains",
    "match_file_path_contains",
}

CRITERIA_EXACT_FIELDS = {
    "agent_name": "match_agent_name",
    "hostname": "match_hostname",
    "agent_ip": "match_agent_ip",
    "user": "match_user",
    "platform": "match_platform",
    "rule_id": "match_rule_id",
    "decoder_name": "match_decoder_name",
    "event_category": "match_event_category",
    "event_action": "match_event_action",
    "event_outcome": "match_event_outcome",
    "severity_normalized": "match_severity",
}

CRITERIA_CONTAINS_FIELDS = {
    "rule_description": "match_rule_contains",
    "mitre_technique_ids": "match_mitre_contains",
    "process_name": "match_process_name_contains",
    "process_command_line": "match_command_line_contains",
    "file_path": "match_file_path_contains",
}

REQUIRED_MAPPING_COLUMNS = [
    "mapping_id",
    "priority",
    "mapping_type",
    "rule_scope",
    "asset_id",
    "confidence",
    "fallback_behavior",
    "reason",
    "runtime_allowed_fields",
    "runtime_safe",
    "context_source",
]


@dataclass(frozen=True)
class MappingRule:
    mapping_id: str
    priority: int
    mapping_type: str
    rule_scope: str
    criteria: dict[str, str]
    asset_id: str
    identity_id: str | None
    network_zone_id: str | None
    policy_ids: tuple[str, ...]
    confidence: float
    fallback_behavior: str
    reason: str
    runtime_allowed_fields: tuple[str, ...]
    runtime_safe: bool
    context_source: str


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def split_semicolon(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(";") if item.strip())


def normalize_bool(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"true", "1", "yes", "y"}


def parse_criteria_expression(criteria: str | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    if not criteria:
        return parsed
    for predicate in criteria.split(";"):
        predicate = predicate.strip()
        if not predicate:
            continue
        if "~=" in predicate:
            field, value = predicate.split("~=", 1)
            field = field.strip()
            column = CRITERIA_CONTAINS_FIELDS.get(field)
        elif "=" in predicate:
            field, value = predicate.split("=", 1)
            field = field.strip()
            column = CRITERIA_EXACT_FIELDS.get(field)
        else:
            raise ValueError(f"Invalid criteria predicate: {predicate}")
        if not column:
            raise ValueError(f"Criteria field is not runtime-safe or not supported: {field}")
        parsed[column] = value.strip()
    return parsed


def load_mapping_rules(path: Path) -> list[MappingRule]:
    rows = read_csv_rows(path)
    rules: list[MappingRule] = []
    for row in rows:
        criteria = parse_criteria_expression(row.get("criteria"))
        criteria.update({
            column: value.strip()
            for column, value in row.items()
            if column in MATCH_COLUMNS and value and value.strip()
        })
        rules.append(
            MappingRule(
                mapping_id=row["mapping_id"].strip(),
                priority=int(row["priority"]),
                mapping_type=row["mapping_type"].strip(),
                rule_scope=row["rule_scope"].strip(),
                criteria=criteria,
                asset_id=row["asset_id"].strip(),
                identity_id=row.get("identity_id", "").strip() or None,
                network_zone_id=row.get("network_zone_id", "").strip() or None,
                policy_ids=split_semicolon(row.get("policy_ids")),
                confidence=float(row["confidence"]),
                fallback_behavior=row["fallback_behavior"].strip(),
                reason=row["reason"].strip(),
                runtime_allowed_fields=split_semicolon(row.get("runtime_allowed_fields")),
                runtime_safe=normalize_bool(row["runtime_safe"]),
                context_source=row.get("context_source", "").strip(),
            )
        )
    return sorted(rules, key=lambda rule: (-rule.priority, rule.mapping_id))


def alert_lookup_values(alert: dict[str, Any]) -> dict[str, str]:
    """Flatten the allowed normalized-alert fields used by runtime-safe mapping."""
    host = alert.get("host") or {}
    agent = alert.get("agent") or {}
    rule = alert.get("rule") or {}
    decoder = alert.get("decoder") or {}
    event = alert.get("event") or {}
    entities = alert.get("entities") or {}
    user = entities.get("user") or {}
    process = entities.get("process") or {}
    source = entities.get("source") or {}
    destination = entities.get("destination") or {}
    file_obj = entities.get("file") or {}
    mitre = alert.get("mitre") or {}

    return {
        "agent_name": str(host.get("agent_name") or agent.get("name") or alert.get("agent_name") or ""),
        "hostname": str(host.get("hostname") or alert.get("hostname") or ""),
        "agent_ip": str(host.get("agent_ip") or agent.get("ip") or alert.get("agent_ip") or ""),
        "platform": str(host.get("platform") or alert.get("platform") or ""),
        "user": str(user.get("name") or user.get("username") or alert.get("user") or ""),
        "process_name": str(process.get("name") or alert.get("process_name") or ""),
        "process_command_line": str(process.get("command_line") or alert.get("process_command_line") or ""),
        "source_ip": str(source.get("ip") or alert.get("source_ip") or ""),
        "destination_ip": str(destination.get("ip") or alert.get("destination_ip") or ""),
        "file_path": str(file_obj.get("path") or alert.get("file_path") or ""),
        "rule_id": str(rule.get("id") or alert.get("rule_id") or ""),
        "rule_description": str(rule.get("description") or alert.get("rule_description") or ""),
        "decoder_name": str(decoder.get("name") or alert.get("decoder_name") or ""),
        "event_category": str(event.get("category") or alert.get("event_category") or ""),
        "event_action": str(event.get("action") or alert.get("event_action") or ""),
        "event_outcome": str(event.get("outcome") or alert.get("event_outcome") or ""),
        "mitre_technique_ids": " ".join(str(item) for item in mitre.get("technique_ids") or alert.get("mitre_technique_ids") or []),
        "mitre_tactics": " ".join(str(item) for item in mitre.get("tactics") or alert.get("mitre_tactics") or []),
        "severity_normalized": str(alert.get("severity_normalized") or alert.get("normalized_severity") or ""),
    }


def rule_matches_alert(rule: MappingRule, alert: dict[str, Any]) -> bool:
    values = alert_lookup_values(alert)
    for column, expected in rule.criteria.items():
        actual = values[MATCH_COLUMNS[column]]
        if column in CONTAINS_COLUMNS:
            if expected.lower() not in actual.lower():
                return False
        elif expected.lower() != actual.lower():
            return False
    return True


def select_mapping_rule(alert: dict[str, Any], rules: list[MappingRule]) -> MappingRule | None:
    for rule in sorted(rules, key=lambda item: (-item.priority, item.mapping_id)):
        if rule_matches_alert(rule, alert):
            return rule
    return None


def validate_mapping_rules(
    mapping_rules_path: Path,
    seed_dir: Path,
) -> tuple[list[str], dict[str, int | float]]:
    errors: list[str] = []
    rows = read_csv_rows(mapping_rules_path)
    if not rows:
        return ["context_mapping_rules.csv must contain at least one mapping rule"], {}

    fieldnames = set(rows[0].keys())
    missing_columns = [column for column in REQUIRED_MAPPING_COLUMNS if column not in fieldnames]
    if missing_columns:
        errors.append(f"context_mapping_rules.csv missing columns: {', '.join(missing_columns)}")

    lower_header_text = " ".join(fieldnames).lower()
    for term in FORBIDDEN_MAPPING_TERMS:
        if term in lower_header_text:
            errors.append(f"context_mapping_rules.csv header contains forbidden runtime field or term: {term}")

    assets = {row.get("asset_id") for row in read_csv_rows(seed_dir / "asset_inventory.csv")}
    identities = {row.get("identity_id") for row in read_csv_rows(seed_dir / "identity_inventory.csv")}
    zones = {row.get("network_zone_id") for row in read_csv_rows(seed_dir / "network_zones.csv")}
    policies = {row.get("policy_id") for row in read_csv_rows(seed_dir / "policy_catalog_seed.csv")}

    seen_ids: set[str] = set()
    fallback_count = 0
    exact_identity_count = 0
    behavioral_count = 0
    agent_fallback_count = 0

    for index, row in enumerate(rows, start=2):
        row_text = " ".join(str(value).lower() for value in row.values())
        for term in FORBIDDEN_MAPPING_TERMS:
            if term in row_text:
                errors.append(f"context_mapping_rules.csv row {index} contains forbidden runtime term: {term}")

        mapping_id = row.get("mapping_id", "")
        if not mapping_id:
            errors.append(f"context_mapping_rules.csv row {index} missing mapping_id")
        elif mapping_id in seen_ids:
            errors.append(f"context_mapping_rules.csv duplicate mapping_id: {mapping_id}")
        seen_ids.add(mapping_id)

        try:
            int(row.get("priority", ""))
        except ValueError:
            errors.append(f"context_mapping_rules.csv row {index} priority must be an integer")

        try:
            confidence = float(row.get("confidence", ""))
            if confidence < 0 or confidence > 1:
                errors.append(f"context_mapping_rules.csv row {index} confidence must be 0-1")
        except ValueError:
            errors.append(f"context_mapping_rules.csv row {index} confidence must be numeric")

        if row.get("asset_id") not in assets and row.get("asset_id") != UNKNOWN_CONTEXT_ASSET_ID:
            errors.append(f"context_mapping_rules.csv row {index} references unknown asset_id: {row.get('asset_id')}")
        if row.get("identity_id") and row.get("identity_id") not in identities:
            errors.append(f"context_mapping_rules.csv row {index} references unknown identity_id: {row.get('identity_id')}")
        if row.get("network_zone_id") and row.get("network_zone_id") not in zones:
            errors.append(f"context_mapping_rules.csv row {index} references unknown network_zone_id: {row.get('network_zone_id')}")

        for policy_id in split_semicolon(row.get("policy_ids")):
            if policy_id not in policies:
                errors.append(f"context_mapping_rules.csv row {index} references unknown policy_id: {policy_id}")

        declared_fields = set(split_semicolon(row.get("runtime_allowed_fields")))
        if not declared_fields and row.get("fallback_behavior") != "return_unknown_context":
            errors.append(f"context_mapping_rules.csv row {index} missing runtime_allowed_fields")
        illegal_declared = sorted(declared_fields - ALLOWED_RUNTIME_MATCH_FIELDS)
        if illegal_declared:
            errors.append(f"context_mapping_rules.csv row {index} uses non-runtime fields: {', '.join(illegal_declared)}")

        try:
            criteria_columns = parse_criteria_expression(row.get("criteria"))
        except ValueError as exc:
            errors.append(f"context_mapping_rules.csv row {index} has invalid criteria: {exc}")
            criteria_columns = {}
        used_fields = {MATCH_COLUMNS[column] for column in MATCH_COLUMNS if row.get(column)}
        used_fields.update(MATCH_COLUMNS[column] for column in criteria_columns)
        undeclared_used = sorted(used_fields - declared_fields)
        if undeclared_used:
            errors.append(f"context_mapping_rules.csv row {index} does not declare used runtime fields: {', '.join(undeclared_used)}")

        if not normalize_bool(row.get("runtime_safe")):
            errors.append(f"context_mapping_rules.csv row {index} runtime_safe must be true")
        if row.get("context_source") != "dataset_anchored_synthetic":
            errors.append(f"context_mapping_rules.csv row {index} context_source must be dataset_anchored_synthetic")

        if row.get("fallback_behavior") == "return_unknown_context":
            fallback_count += 1
        if row.get("mapping_type") == "exact_identity":
            exact_identity_count += 1
        if row.get("mapping_type") == "behavioral":
            behavioral_count += 1
        if row.get("mapping_type") == "agent_fallback":
            agent_fallback_count += 1

    if fallback_count == 0:
        errors.append("context_mapping_rules.csv must include an unknown-context fallback rule")
    if exact_identity_count == 0:
        errors.append("context_mapping_rules.csv must include at least one exact identity rule")
    if behavioral_count == 0:
        errors.append("context_mapping_rules.csv must include at least one behavioral rule")
    if agent_fallback_count < 3:
        errors.append("context_mapping_rules.csv should include agent fallback rules for all top observed agents")

    summary = {
        "mapping_rule_count": len(rows),
        "exact_identity_rules": exact_identity_count,
        "behavioral_rules": behavioral_count,
        "agent_fallback_rules": agent_fallback_count,
        "unknown_fallback_rules": fallback_count,
    }
    return errors, summary
