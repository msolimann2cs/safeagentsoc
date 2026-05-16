from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
import hashlib
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import json
from pathlib import Path
from typing import Any

from safeagentsoc.context.analyst_priority import calculate_analyst_priority
from safeagentsoc.context.business_risk import calculate_business_risk
from safeagentsoc.context.context_confidence import (
    calculate_context_confidence,
    unknown_asset_context,
    unknown_identity_context,
    unknown_network_context,
)
from safeagentsoc.context.mapping_rules import MappingRule, parse_criteria_expression, select_mapping_rule
from safeagentsoc.storage.db import DatabaseConfig, connect, execute_sql_file


RUNTIME_SCHEMA = "safeagentsoc_runtime"


@dataclass(frozen=True)
class ContextPackage:
    assets: dict[str, dict[str, Any]]
    identities: dict[str, dict[str, Any]]
    network_zones: dict[str, dict[str, Any]]
    business_services: dict[str, dict[str, Any]]
    policies: dict[str, dict[str, Any]]
    mapping_rules: list[MappingRule]
    latest_context_import_batch_id: str | None


@dataclass(frozen=True)
class EnrichmentResult:
    enriched_alerts: list[dict[str, Any]]
    qa_metrics: dict[str, Any]
    missing_context_rows: list[dict[str, Any]]
    business_risk_distribution: list[dict[str, Any]]
    context_confidence_distribution: list[dict[str, Any]]


def to_jsonable(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (IPv4Address, IPv6Address, IPv4Network, IPv6Network)):
        return str(value)
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    return value


def json_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return json.loads(value)
    return dict(value)


def rows_by_key(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {str(row[key]): to_jsonable(row) for row in rows if row.get(key) is not None}


def fetch_all(connection: Any, query: str, params: object | None = None) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        return [to_jsonable(dict(row)) for row in cursor.fetchall()]


def mapping_rule_from_row(row: dict[str, Any]) -> MappingRule:
    return MappingRule(
        mapping_id=row["mapping_id"],
        priority=int(row["priority"]),
        mapping_type=row["mapping_type"],
        rule_scope=row["rule_scope"],
        criteria=parse_criteria_expression(row.get("criteria")),
        asset_id=row["asset_id"],
        identity_id=row.get("identity_id"),
        network_zone_id=row.get("network_zone_id"),
        policy_ids=tuple(row.get("policy_ids") or []),
        confidence=float(row["confidence"]),
        fallback_behavior=row["fallback_behavior"],
        reason=row["reason"],
        runtime_allowed_fields=tuple(row.get("runtime_allowed_fields") or []),
        runtime_safe=bool(row["runtime_safe"]),
        context_source=row["context_source"],
    )


def load_context_package(connection: Any) -> ContextPackage:
    assets = rows_by_key(fetch_all(connection, f"SELECT * FROM {RUNTIME_SCHEMA}.context_assets"), "asset_id")
    identities = rows_by_key(fetch_all(connection, f"SELECT * FROM {RUNTIME_SCHEMA}.context_identities"), "identity_id")
    zones = rows_by_key(fetch_all(connection, f"SELECT * FROM {RUNTIME_SCHEMA}.context_network_zones"), "network_zone_id")
    services = rows_by_key(fetch_all(connection, f"SELECT * FROM {RUNTIME_SCHEMA}.context_business_services"), "business_service")
    policies = rows_by_key(fetch_all(connection, f"SELECT * FROM {RUNTIME_SCHEMA}.context_policy_catalog"), "policy_id")
    mapping_rows = fetch_all(
        connection,
        f"""
        SELECT *
        FROM {RUNTIME_SCHEMA}.context_mapping_rules
        ORDER BY priority DESC, mapping_id
        """,
    )
    batch_rows = fetch_all(
        connection,
        f"""
        SELECT context_import_batch_id
        FROM {RUNTIME_SCHEMA}.context_import_batches
        ORDER BY imported_at_utc DESC
        LIMIT 1
        """,
    )
    return ContextPackage(
        assets=assets,
        identities=identities,
        network_zones=zones,
        business_services=services,
        policies=policies,
        mapping_rules=[mapping_rule_from_row(row) for row in mapping_rows],
        latest_context_import_batch_id=batch_rows[0]["context_import_batch_id"] if batch_rows else None,
    )


def fetch_normalized_alerts(connection: Any, limit: int | None = None) -> list[dict[str, Any]]:
    limit_sql = "LIMIT %(limit)s" if limit else ""
    params = {"limit": limit} if limit else None
    return fetch_all(
        connection,
        f"""
        SELECT
            alert_uid,
            evidence_id,
            source_system,
            source_adapter,
            event_time_utc,
            hostname,
            agent_name,
            agent_ip::text AS agent_ip,
            platform,
            rule_id,
            rule_level,
            rule_description,
            decoder_name,
            event_category,
            event_action,
            event_outcome,
            severity_normalized,
            severity_score,
            mitre_technique_ids,
            mitre_tactics,
            normalized_alert
        FROM {RUNTIME_SCHEMA}.normalized_alerts
        ORDER BY event_time_utc, alert_uid
        {limit_sql}
        """,
        params,
    )


def normalized_json_from_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = json_dict(row.get("normalized_alert"))
    if normalized:
        return normalized
    return {
        "alert_uid": row.get("alert_uid"),
        "source": {"source_system": row.get("source_system"), "source_adapter": row.get("source_adapter")},
        "timestamps": {"event_time_utc": row.get("event_time_utc")},
        "host": {
            "hostname": row.get("hostname"),
            "agent_name": row.get("agent_name"),
            "agent_ip": row.get("agent_ip"),
            "platform": row.get("platform"),
        },
        "rule": {
            "rule_id": row.get("rule_id"),
            "rule_level": row.get("rule_level"),
            "rule_description": row.get("rule_description"),
        },
        "decoder": {"decoder_name": row.get("decoder_name")},
        "event": {
            "category": row.get("event_category"),
            "action": row.get("event_action"),
            "outcome": row.get("event_outcome"),
        },
        "severity": {"normalized": row.get("severity_normalized"), "normalized_score": row.get("severity_score")},
        "mitre": {"technique_ids": row.get("mitre_technique_ids") or [], "tactics": row.get("mitre_tactics") or []},
        "entities": {"user": {}, "process": {}, "network": {}, "file": {}},
        "evidence": {"evidence_id": row.get("evidence_id")},
    }


def original_summary(row: dict[str, Any], normalized: dict[str, Any]) -> dict[str, Any]:
    entities = normalized.get("entities") or {}
    return {
        "agent_name": row.get("agent_name"),
        "hostname": row.get("hostname"),
        "agent_ip": row.get("agent_ip"),
        "platform": row.get("platform"),
        "rule_id": row.get("rule_id"),
        "rule_level": row.get("rule_level"),
        "rule_description": row.get("rule_description"),
        "decoder_name": row.get("decoder_name"),
        "event_category": row.get("event_category"),
        "event_action": row.get("event_action"),
        "event_outcome": row.get("event_outcome"),
        "severity_normalized": row.get("severity_normalized"),
        "severity_score": row.get("severity_score"),
        "mitre_technique_ids": row.get("mitre_technique_ids") or [],
        "mitre_tactics": row.get("mitre_tactics") or [],
        "user": entities.get("user") or {},
        "process": entities.get("process") or {},
        "network": entities.get("network") or {},
        "file": entities.get("file") or {},
    }


def build_asset_context(asset: dict[str, Any] | None, service: dict[str, Any] | None) -> dict[str, Any]:
    if not asset:
        return unknown_asset_context()
    return {
        "status": "known",
        "asset_id": asset.get("asset_id"),
        "logical_asset_name": asset.get("logical_asset_name"),
        "asset_owner": asset.get("asset_owner"),
        "business_unit": asset.get("business_unit"),
        "business_service": asset.get("business_service"),
        "asset_criticality": asset.get("asset_criticality"),
        "environment": asset.get("environment"),
        "asset_role": asset.get("asset_role"),
        "exposure_level": asset.get("exposure_level"),
        "internet_facing": asset.get("internet_facing"),
        "crown_jewel": asset.get("crown_jewel"),
        "data_classification": asset.get("data_classification"),
        "site": asset.get("site"),
        "cloud_region": asset.get("cloud_region"),
        "network_zone_id": asset.get("network_zone_id"),
        "network_zone": asset.get("network_zone"),
        "service_tier": asset.get("service_tier"),
        "service_criticality": service.get("service_criticality") if service else asset.get("asset_criticality"),
        "regulatory_scope": asset.get("regulatory_scope") or [],
        "monitoring_priority": asset.get("monitoring_priority"),
        "context_source": asset.get("context_source"),
    }


def build_identity_context(identity: dict[str, Any] | None) -> dict[str, Any]:
    if not identity:
        return unknown_identity_context()
    return {
        "status": "known",
        "identity_id": identity.get("identity_id"),
        "logical_username": identity.get("logical_username"),
        "observed_username": identity.get("observed_username"),
        "user_department": identity.get("user_department"),
        "user_role": identity.get("user_role"),
        "identity_type": identity.get("identity_type"),
        "identity_status": identity.get("identity_status"),
        "privileged_account": identity.get("privileged_account"),
        "service_account": identity.get("service_account"),
        "privileged_scope": identity.get("privileged_scope"),
        "data_access_level": identity.get("data_access_level"),
        "identity_risk_score": identity.get("identity_risk_score"),
        "mfa_status": identity.get("mfa_status"),
        "manager_or_owner": identity.get("manager_or_owner"),
        "normal_assets": identity.get("normal_assets") or [],
        "normal_login_hours": identity.get("normal_login_hours"),
        "context_source": identity.get("context_source"),
    }


def build_network_context(zone: dict[str, Any] | None) -> dict[str, Any]:
    if not zone:
        return unknown_network_context()
    return {
        "status": "known",
        "network_zone_id": zone.get("network_zone_id"),
        "network_zone": zone.get("network_zone"),
        "subnet": zone.get("subnet"),
        "site": zone.get("site"),
        "environment": zone.get("environment"),
        "cloud_region": zone.get("cloud_region"),
        "vpc_or_vlan": zone.get("vpc_or_vlan"),
        "trust_level": zone.get("trust_level"),
        "trusted_boundary_crossing": zone.get("trusted_boundary_crossing"),
        "known_admin_network": zone.get("known_admin_network"),
        "known_scanner_network": zone.get("known_scanner_network"),
        "description": zone.get("description"),
    }


def build_policy_context(policy_ids: tuple[str, ...], policies: dict[str, dict[str, Any]]) -> dict[str, Any]:
    selected = [policies[policy_id] for policy_id in policy_ids if policy_id in policies]
    return {
        "relevant_policy_ids": [policy.get("policy_id") for policy in selected],
        "policy_names": [policy.get("policy_name") for policy in selected],
        "control_families": sorted({policy.get("control_family") for policy in selected if policy.get("control_family")}),
        "approval_requirements": [policy.get("approval_requirements") for policy in selected if policy.get("approval_requirements")],
        "response_constraints": [policy.get("response_constraints") for policy in selected if policy.get("response_constraints")],
        "audit_logging_requirements": [
            policy.get("audit_logging_requirements") for policy in selected if policy.get("audit_logging_requirements")
        ],
    }


def classify_identity_applicability(
    summary: dict[str, Any],
    selected_rule: MappingRule,
    identity_context: dict[str, Any],
) -> dict[str, Any]:
    if identity_context.get("status") == "known" and identity_context.get("identity_id"):
        return {
            "status": "resolved",
            "reason": "Mapping rule resolved an identity context.",
            "identity_applicable": True,
        }

    description = str(summary.get("rule_description") or "").lower()
    category = str(summary.get("event_category") or "").lower()
    user = summary.get("user") or {}
    process = summary.get("process") or {}
    process_name = str(process.get("name") or "").lower()

    identity_terms = [
        "sudo",
        "pam",
        "login",
        "logon",
        "authentication",
        "auth",
        "password",
        "session",
        "user",
        "account",
        "powershell",
        "cmd",
        "ssh",
    ]
    not_applicable_terms = [
        "dpkg",
        "package",
        "security configuration assessment",
        "sca",
        "syscheck",
        "integrity",
        "ossec",
        "windows defender",
        "defender",
        "potentially unwanted",
        "pua",
        "malware",
        "virus",
        "rootcheck",
        "vulnerability detector",
        "vulnerability",
        "policy monitoring",
        "sca scan",
    ]

    if user.get("username"):
        return {
            "status": "missing",
            "reason": "Alert contains an observed user but no identity inventory mapping resolved.",
            "identity_applicable": True,
        }
    if category in {"authentication", "privilege_activity", "process_execution"}:
        return {
            "status": "missing",
            "reason": f"Event category {category} is identity-applicable but no identity mapping resolved.",
            "identity_applicable": True,
        }
    if any(term in description for term in identity_terms) or process_name in {"powershell.exe", "cmd.exe", "net.exe", "ssh", "sshd"}:
        return {
            "status": "missing",
            "reason": "Rule or process semantics indicate identity should be reviewed.",
            "identity_applicable": True,
        }
    if category in {"monitoring_internal", "background", "system_activity"} or any(term in description for term in not_applicable_terms):
        return {
            "status": "not_applicable",
            "reason": "Alert appears to be system package compliance integrity or internal monitoring telemetry.",
            "identity_applicable": False,
        }
    if category in {"file_activity", "network_activity"}:
        return {
            "status": "not_applicable",
            "reason": f"Event category {category} can be investigated without requiring identity context.",
            "identity_applicable": False,
        }
    if selected_rule.mapping_type in {"agent_fallback", "generic_unknown_fallback"}:
        return {
            "status": "unknown",
            "reason": "Fallback mapping lacks enough runtime detail to decide identity applicability.",
            "identity_applicable": False,
        }
    return {
        "status": "unknown",
        "reason": "Runtime fields do not clearly indicate whether identity context should apply.",
        "identity_applicable": False,
    }


def enrich_alert(row: dict[str, Any], context: ContextPackage) -> dict[str, Any]:
    normalized = normalized_json_from_row(row)
    selected_rule = select_mapping_rule(normalized, context.mapping_rules)
    if selected_rule is None:
        raise RuntimeError("No context mapping rule selected. MAP-999 unknown fallback is required.")

    asset = None if selected_rule.asset_id == "__UNKNOWN__" else context.assets.get(selected_rule.asset_id)
    service = context.business_services.get(asset.get("business_service")) if asset else None
    identity = context.identities.get(selected_rule.identity_id) if selected_rule.identity_id else None
    zone_id = selected_rule.network_zone_id or (asset.get("network_zone_id") if asset else None)
    zone = context.network_zones.get(zone_id) if zone_id else None

    summary = original_summary(row, normalized)
    asset_context = build_asset_context(asset, service)
    identity_context = build_identity_context(identity)
    identity_applicability = classify_identity_applicability(summary, selected_rule, identity_context)
    network_context = build_network_context(zone)
    policy_context = build_policy_context(selected_rule.policy_ids, context.policies)
    confidence = calculate_context_confidence(
        mapping_confidence=selected_rule.confidence,
        asset_context=asset_context,
        identity_context=identity_context,
        network_context=network_context,
        policy_context=policy_context,
        evidence_id=row.get("evidence_id"),
        identity_applicability_status=identity_applicability["status"],
    )
    risk = calculate_business_risk(
        original_alert_summary=summary,
        asset_context=asset_context,
        identity_context=identity_context,
        policy_context=policy_context,
        context_confidence=confidence.context_confidence,
        mapping_rule_type=selected_rule.mapping_type,
        mapping_confidence=selected_rule.confidence,
    )

    business_risk_payload = {
        "business_risk_score": risk.business_risk_score,
        "business_risk_label": risk.business_risk_label,
        "risk_factors": risk.risk_factors,
        "risk_explanation": risk.risk_explanation,
        "risk_confidence": risk.risk_confidence,
        "score_components": risk.score_components,
    }
    context_metadata = {
        "mapping_rule_id": selected_rule.mapping_id,
        "mapping_rule_type": selected_rule.mapping_type,
        "mapping_confidence": round(selected_rule.confidence, 4),
        "mapping_reason": selected_rule.reason,
        "fallback_behavior": selected_rule.fallback_behavior,
        "context_confidence": confidence.context_confidence,
        "confidence_factors": confidence.confidence_factors,
        "missing_context_fields": confidence.missing_context_fields,
        "recommended_follow_up": confidence.recommended_follow_up,
        "context_source": selected_rule.context_source,
    }
    analyst_priority = calculate_analyst_priority(
        original_alert_summary=summary,
        asset_context=asset_context,
        identity_context=identity_context,
        identity_applicability=identity_applicability,
        policy_context=policy_context,
        business_risk=business_risk_payload,
        context_metadata=context_metadata,
    )
    analyst_priority_payload = {
        "analyst_priority_score": analyst_priority.analyst_priority_score,
        "analyst_priority_label": analyst_priority.analyst_priority_label,
        "urgent_priority_gate_passed": analyst_priority.urgent_priority_gate_passed,
        "gate_reasons": analyst_priority.gate_reasons,
        "priority_factors": analyst_priority.priority_factors,
        "suppressors": analyst_priority.suppressors,
        "priority_explanation": analyst_priority.explanation,
        "score_components": analyst_priority.score_components,
    }

    return {
        "alert_uid": row.get("alert_uid"),
        "evidence_id": row.get("evidence_id"),
        "event_time_utc": row.get("event_time_utc"),
        "source_system": row.get("source_system"),
        "source_adapter": row.get("source_adapter"),
        "original_alert_summary": summary,
        "asset_context": asset_context,
        "identity_context": identity_context,
        "identity_applicability": identity_applicability,
        "network_context": network_context,
        "policy_context": policy_context,
        "business_risk": business_risk_payload,
        "analyst_priority": analyst_priority_payload,
        "context_metadata": context_metadata,
    }


def distribution(rows: list[dict[str, Any]], path: list[str]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        value: Any = row
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        label = str(value if value not in (None, "") else "unknown")
        counts[label] = counts.get(label, 0) + 1
    return [{"value": key, "count": value} for key, value in sorted(counts.items())]


def build_missing_context_rows(enriched_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for alert in enriched_alerts:
        for field in alert["context_metadata"]["missing_context_fields"]:
            rows.append(
                {
                    "alert_uid": alert["alert_uid"],
                    "evidence_id": alert["evidence_id"],
                    "mapping_rule_id": alert["context_metadata"]["mapping_rule_id"],
                    "missing_context_field": field,
                    "recommended_follow_up": ";".join(alert["context_metadata"]["recommended_follow_up"]),
                }
            )
    return rows


def suppressor_distribution(enriched_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for alert in enriched_alerts:
        for suppressor in alert.get("analyst_priority", {}).get("suppressors") or []:
            label = str(suppressor if suppressor not in (None, "") else "unknown")
            counts[label] = counts.get(label, 0) + 1
    return [{"suppressor": key, "count": value} for key, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


def high_risk_mapping_distribution(enriched_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    high_risk_alerts = [
        alert for alert in enriched_alerts if alert["business_risk"]["business_risk_label"] in {"high", "critical"}
    ]
    counts: dict[tuple[str, str], int] = {}
    for alert in high_risk_alerts:
        key = (
            str(alert["context_metadata"].get("mapping_rule_type") or "unknown"),
            str(alert["context_metadata"].get("mapping_rule_id") or "unknown"),
        )
        counts[key] = counts.get(key, 0) + 1
    return [
        {
            "mapping_rule_type": mapping_type,
            "mapping_rule_id": mapping_id,
            "high_risk_alert_count": count,
            "high_risk_alert_rate": round(count / len(high_risk_alerts), 4) if high_risk_alerts else 0.0,
        }
        for (mapping_type, mapping_id), count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def build_qa_metrics(enriched_alerts: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(enriched_alerts)
    if total == 0:
        return {}
    asset_known = sum(1 for alert in enriched_alerts if alert["asset_context"].get("status") == "known")
    identity_known = sum(1 for alert in enriched_alerts if alert["identity_context"].get("status") == "known")
    identity_applicable = sum(1 for alert in enriched_alerts if alert["identity_applicability"]["status"] in {"resolved", "missing"})
    identity_resolved = sum(1 for alert in enriched_alerts if alert["identity_applicability"]["status"] == "resolved")
    identity_missing = sum(1 for alert in enriched_alerts if alert["identity_applicability"]["status"] == "missing")
    identity_not_applicable = sum(1 for alert in enriched_alerts if alert["identity_applicability"]["status"] == "not_applicable")
    identity_unknown = sum(1 for alert in enriched_alerts if alert["identity_applicability"]["status"] == "unknown")
    network_known = sum(1 for alert in enriched_alerts if alert["network_context"].get("status") == "known")
    service_known = sum(1 for alert in enriched_alerts if alert["asset_context"].get("business_service"))
    policy_known = sum(1 for alert in enriched_alerts if alert["policy_context"].get("relevant_policy_ids"))
    avg_confidence = sum(alert["context_metadata"]["context_confidence"] for alert in enriched_alerts) / total
    return {
        "total_context_enriched_alerts": total,
        "asset_context_coverage_rate": round(asset_known / total, 4),
        "identity_context_coverage_rate": round(identity_known / total, 4),
        "identity_context_coverage_all_alerts": round(identity_known / total, 4),
        "identity_context_coverage_identity_applicable_alerts": round(identity_resolved / identity_applicable, 4)
        if identity_applicable
        else 0.0,
        "identity_applicable_alert_count": identity_applicable,
        "identity_resolved_alert_count": identity_resolved,
        "identity_not_applicable_alert_count": identity_not_applicable,
        "identity_missing_alert_count": identity_missing,
        "identity_unknown_applicability_alert_count": identity_unknown,
        "network_context_coverage_rate": round(network_known / total, 4),
        "business_service_coverage_rate": round(service_known / total, 4),
        "policy_context_coverage_rate": round(policy_known / total, 4),
        "business_risk_score_coverage_rate": 1.0,
        "context_confidence_average": round(avg_confidence, 4),
        "missing_asset_context_count": total - asset_known,
        "missing_identity_context_count": total - identity_known,
        "high_risk_alert_count": sum(1 for alert in enriched_alerts if alert["business_risk"]["business_risk_label"] == "high"),
        "critical_risk_alert_count": sum(
            1 for alert in enriched_alerts if alert["business_risk"]["business_risk_label"] == "critical"
        ),
        "high_risk_agent_fallback_count": sum(
            1
            for alert in enriched_alerts
            if alert["business_risk"]["business_risk_label"] in {"high", "critical"}
            and alert["context_metadata"].get("mapping_rule_type") in {"agent_fallback", "generic_unknown_fallback"}
        ),
        "analyst_priority_score_coverage_rate": 1.0,
        "high_analyst_priority_count": sum(
            1 for alert in enriched_alerts if alert["analyst_priority"]["analyst_priority_label"] == "high"
        ),
        "critical_analyst_priority_count": sum(
            1 for alert in enriched_alerts if alert["analyst_priority"]["analyst_priority_label"] == "critical"
        ),
        "urgent_analyst_priority_count": sum(
            1 for alert in enriched_alerts if alert["analyst_priority"]["analyst_priority_label"] in {"high", "critical"}
        ),
    }


def enrich_alerts_from_connection(connection: Any, limit: int | None = None) -> EnrichmentResult:
    context = load_context_package(connection)
    if not context.mapping_rules:
        raise RuntimeError("No context mapping rules found. Run Phase 4 Sprint 5 import first.")
    alerts = fetch_normalized_alerts(connection, limit=limit)
    enriched = [enrich_alert(row, context) for row in alerts]
    return EnrichmentResult(
        enriched_alerts=enriched,
        qa_metrics=build_qa_metrics(enriched),
        missing_context_rows=build_missing_context_rows(enriched),
        business_risk_distribution=distribution(enriched, ["business_risk", "business_risk_label"]),
        context_confidence_distribution=confidence_buckets(enriched),
    )


def confidence_buckets(enriched_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets = {"0.00-0.49": 0, "0.50-0.69": 0, "0.70-0.84": 0, "0.85-1.00": 0}
    for alert in enriched_alerts:
        score = alert["context_metadata"]["context_confidence"]
        if score < 0.5:
            buckets["0.00-0.49"] += 1
        elif score < 0.7:
            buckets["0.50-0.69"] += 1
        elif score < 0.85:
            buckets["0.70-0.84"] += 1
        else:
            buckets["0.85-1.00"] += 1
    return [{"confidence_bucket": key, "count": value} for key, value in buckets.items()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(to_jsonable(row), sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def flatten_enriched_alert(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "alert_uid": alert["alert_uid"],
        "evidence_id": alert["evidence_id"],
        "event_time_utc": alert["event_time_utc"],
        "agent_name": alert["original_alert_summary"].get("agent_name"),
        "hostname": alert["original_alert_summary"].get("hostname"),
        "platform": alert["original_alert_summary"].get("platform"),
        "rule_id": alert["original_alert_summary"].get("rule_id"),
        "rule_level": alert["original_alert_summary"].get("rule_level"),
        "rule_description": alert["original_alert_summary"].get("rule_description"),
        "severity_normalized": alert["original_alert_summary"].get("severity_normalized"),
        "asset_id": alert["asset_context"].get("asset_id"),
        "logical_asset_name": alert["asset_context"].get("logical_asset_name"),
        "business_unit": alert["asset_context"].get("business_unit"),
        "business_service": alert["asset_context"].get("business_service"),
        "asset_criticality": alert["asset_context"].get("asset_criticality"),
        "data_classification": alert["asset_context"].get("data_classification"),
        "identity_id": alert["identity_context"].get("identity_id"),
        "identity_applicability_status": alert["identity_applicability"].get("status"),
        "identity_applicability_reason": alert["identity_applicability"].get("reason"),
        "logical_username": alert["identity_context"].get("logical_username"),
        "privileged_account": alert["identity_context"].get("privileged_account"),
        "network_zone": alert["network_context"].get("network_zone"),
        "mapping_rule_id": alert["context_metadata"].get("mapping_rule_id"),
        "context_confidence": alert["context_metadata"].get("context_confidence"),
        "business_risk_score": alert["business_risk"].get("business_risk_score"),
        "business_risk_label": alert["business_risk"].get("business_risk_label"),
        "analyst_priority_score": alert["analyst_priority"].get("analyst_priority_score"),
        "analyst_priority_label": alert["analyst_priority"].get("analyst_priority_label"),
        "urgent_priority_gate_passed": alert["analyst_priority"].get("urgent_priority_gate_passed"),
        "analyst_priority_suppressors": ";".join(alert["analyst_priority"].get("suppressors") or []),
        "missing_context_fields": ";".join(alert["context_metadata"].get("missing_context_fields") or []),
    }


def write_outputs(result: EnrichmentResult, output_dir: Path, qa_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    qa_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_dir / "context_enriched_alerts.jsonl", result.enriched_alerts)
    write_jsonl(output_dir / "context_enriched_alerts_with_risk.jsonl", result.enriched_alerts)
    write_csv(output_dir / "context_enriched_alerts.csv", [flatten_enriched_alert(alert) for alert in result.enriched_alerts])
    write_csv(qa_dir / "missing_context_report.csv", result.missing_context_rows)
    write_csv(qa_dir / "business_risk_distribution.csv", result.business_risk_distribution)
    write_csv(qa_dir / "analyst_priority_distribution.csv", distribution(result.enriched_alerts, ["analyst_priority", "analyst_priority_label"]))
    write_csv(qa_dir / "analyst_priority_suppressor_distribution.csv", suppressor_distribution(result.enriched_alerts))
    write_csv(qa_dir / "context_confidence_distribution.csv", result.context_confidence_distribution)
    write_csv(qa_dir / "identity_applicability_report.csv", distribution(result.enriched_alerts, ["identity_applicability", "status"]))
    write_csv(qa_dir / "high_risk_mapping_rule_type_distribution.csv", high_risk_mapping_distribution(result.enriched_alerts))
    write_csv(qa_dir / "context_coverage_report.csv", [{"metric": key, "value": value} for key, value in result.qa_metrics.items()])
    high_risk_rows = [
        flatten_enriched_alert(alert)
        for alert in result.enriched_alerts
        if alert["business_risk"]["business_risk_label"] in {"high", "critical"}
    ][:250]
    write_csv(qa_dir / "high_risk_alert_review_pack.csv", high_risk_rows)
    urgent_priority_rows = [
        flatten_enriched_alert(alert)
        for alert in result.enriched_alerts
        if alert["analyst_priority"]["analyst_priority_label"] in {"high", "critical"}
    ][:250]
    write_csv(qa_dir / "urgent_analyst_priority_review_pack.csv", urgent_priority_rows)


def persist_enriched_alerts(connection: Any, result: EnrichmentResult, batch_id: str | None = None, replace: bool = True) -> None:
    if replace:
        connection.execute(f"TRUNCATE TABLE {RUNTIME_SCHEMA}.context_missing_context_events")
        connection.execute(f"TRUNCATE TABLE {RUNTIME_SCHEMA}.context_enriched_alerts")
    with connection.cursor() as cursor:
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.context_enriched_alerts (
                alert_uid,
                evidence_id,
                mapping_id,
                asset_id,
                identity_id,
                identity_applicability_status,
                network_zone_id,
                business_unit,
                business_service,
                business_risk_score,
                business_risk_label,
                analyst_priority_score,
                analyst_priority_label,
                urgent_priority_gate_passed,
                risk_confidence,
                context_confidence,
                missing_context_fields,
                context_enriched_alert,
                context_import_batch_id
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
            ON CONFLICT (alert_uid) DO UPDATE SET
                evidence_id = EXCLUDED.evidence_id,
                mapping_id = EXCLUDED.mapping_id,
                asset_id = EXCLUDED.asset_id,
                identity_id = EXCLUDED.identity_id,
                identity_applicability_status = EXCLUDED.identity_applicability_status,
                network_zone_id = EXCLUDED.network_zone_id,
                business_unit = EXCLUDED.business_unit,
                business_service = EXCLUDED.business_service,
                business_risk_score = EXCLUDED.business_risk_score,
                business_risk_label = EXCLUDED.business_risk_label,
                analyst_priority_score = EXCLUDED.analyst_priority_score,
                analyst_priority_label = EXCLUDED.analyst_priority_label,
                urgent_priority_gate_passed = EXCLUDED.urgent_priority_gate_passed,
                risk_confidence = EXCLUDED.risk_confidence,
                context_confidence = EXCLUDED.context_confidence,
                missing_context_fields = EXCLUDED.missing_context_fields,
                context_enriched_alert = EXCLUDED.context_enriched_alert,
                context_import_batch_id = EXCLUDED.context_import_batch_id
            """,
            [
                (
                    alert["alert_uid"],
                    alert["evidence_id"],
                    alert["context_metadata"]["mapping_rule_id"],
                    alert["asset_context"].get("asset_id"),
                    alert["identity_context"].get("identity_id"),
                    alert["identity_applicability"].get("status"),
                    alert["network_context"].get("network_zone_id"),
                    alert["asset_context"].get("business_unit"),
                    alert["asset_context"].get("business_service"),
                    alert["business_risk"]["business_risk_score"],
                    alert["business_risk"]["business_risk_label"],
                    alert["analyst_priority"]["analyst_priority_score"],
                    alert["analyst_priority"]["analyst_priority_label"],
                    alert["analyst_priority"]["urgent_priority_gate_passed"],
                    alert["business_risk"]["risk_confidence"],
                    alert["context_metadata"]["context_confidence"],
                    alert["context_metadata"]["missing_context_fields"],
                    json.dumps(to_jsonable(alert), sort_keys=True),
                    batch_id,
                )
                for alert in result.enriched_alerts
            ],
        )
        cursor.executemany(
            f"""
            INSERT INTO {RUNTIME_SCHEMA}.context_missing_context_events (
                missing_context_event_id,
                alert_uid,
                missing_field,
                missing_reason,
                mapping_id
            )
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (missing_context_event_id) DO NOTHING
            """,
            [
                (
                    "missing_"
                    + hashlib.sha256(f"{row['alert_uid']}|{row['missing_context_field']}".encode("utf-8")).hexdigest()[:32],
                    row["alert_uid"],
                    row["missing_context_field"],
                    row["recommended_follow_up"],
                    row["mapping_rule_id"],
                )
                for row in result.missing_context_rows
            ],
        )
    connection.commit()


def run_enrichment(
    *,
    database_url: str | None,
    output_dir: Path,
    qa_dir: Path,
    schema_file: Path | None = None,
    apply_schema: bool = False,
    persist: bool = True,
    replace: bool = True,
    limit: int | None = None,
) -> EnrichmentResult:
    config = DatabaseConfig(database_url) if database_url else DatabaseConfig.from_env()
    with connect(config) as connection:
        if apply_schema and schema_file:
            execute_sql_file(connection, schema_file)
        result = enrich_alerts_from_connection(connection, limit=limit)
        if persist:
            context = load_context_package(connection)
            persist_enriched_alerts(connection, result, batch_id=context.latest_context_import_batch_id, replace=replace)
        write_outputs(result, output_dir=output_dir, qa_dir=qa_dir)
    return result
