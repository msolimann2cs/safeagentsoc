from __future__ import annotations

from collections.abc import Iterable, Mapping
import csv
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from safeagentsoc.context.context_validator import validate_mapping_rule_package, validate_seed_package
from safeagentsoc.storage.db import DatabaseConfig, connect, execute_sql_file


RUNTIME_SCHEMA = "safeagentsoc_runtime"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def split_semicolon(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(";") if item.strip()]


def parse_bool(value: str | bool | None) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def parse_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def first_present(row: Mapping[str, str], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def empty_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def raw_json(row: Mapping[str, Any]) -> str:
    return json.dumps(dict(row), sort_keys=True)


@dataclass(frozen=True)
class ContextImportPaths:
    seed_dir: Path
    mapping_rules: Path
    schema_file: Path | None = None
    manifest_output: Path | None = None
    report_output: Path | None = None


@dataclass(frozen=True)
class ContextImportResult:
    context_import_batch_id: str
    row_counts: dict[str, int]
    file_hashes: dict[str, str]
    validation_errors: list[str]


def required_context_files(paths: ContextImportPaths) -> dict[str, Path]:
    return {
        "asset_inventory": paths.seed_dir / "asset_inventory.csv",
        "identity_inventory": paths.seed_dir / "identity_inventory.csv",
        "network_zones": paths.seed_dir / "network_zones.csv",
        "business_units": paths.seed_dir / "business_units.csv",
        "business_services": paths.seed_dir / "business_services.csv",
        "data_classification": paths.seed_dir / "data_classification.csv",
        "policy_catalog": paths.seed_dir / "policy_catalog_seed.csv",
        "context_mapping_rules": paths.mapping_rules,
    }


def validate_context_import_inputs(paths: ContextImportPaths) -> list[str]:
    errors = validate_seed_package(paths.seed_dir)
    errors.extend(validate_mapping_rule_package(paths.mapping_rules, paths.seed_dir))
    return errors


def collect_import_metadata(paths: ContextImportPaths) -> tuple[dict[str, int], dict[str, str]]:
    files = required_context_files(paths)
    row_counts = {name: len(read_csv(path)) for name, path in files.items()}
    file_hashes = {name: sha256_file(path) for name, path in files.items()}
    return row_counts, file_hashes


def clear_context_tables(connection: Any) -> None:
    tables = [
        "context_graph_edges",
        "context_graph_nodes",
        "context_missing_context_events",
        "context_enriched_alerts",
        "context_mapping_rules",
        "context_policy_catalog",
        "context_identities",
        "context_assets",
        "context_network_zones",
        "context_data_classifications",
        "context_business_services",
        "context_business_units",
        "context_import_batches",
    ]
    for table in tables:
        connection.execute(f"TRUNCATE TABLE {RUNTIME_SCHEMA}.{table} CASCADE")


def insert_import_batch(
    connection: Any,
    batch_id: str,
    row_counts: dict[str, int],
    file_hashes: dict[str, str],
    replace_existing: bool,
    notes: str | None = None,
) -> None:
    connection.execute(
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.context_import_batches (
            context_import_batch_id,
            context_source,
            imported_by,
            replace_existing,
            source_manifest,
            row_counts,
            file_hashes,
            validation_status,
            notes
        )
        VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s)
        ON CONFLICT (context_import_batch_id) DO UPDATE SET
            imported_at_utc = now(),
            imported_by = EXCLUDED.imported_by,
            replace_existing = EXCLUDED.replace_existing,
            source_manifest = EXCLUDED.source_manifest,
            row_counts = EXCLUDED.row_counts,
            file_hashes = EXCLUDED.file_hashes,
            validation_status = EXCLUDED.validation_status,
            notes = EXCLUDED.notes
        """,
        (
            batch_id,
            "dataset_anchored_synthetic",
            "safeagentsoc_phase4_import_context",
            replace_existing,
            json.dumps({"phase": "phase_04_enterprise_context", "sprint": 5}, sort_keys=True),
            json.dumps(row_counts, sort_keys=True),
            json.dumps(file_hashes, sort_keys=True),
            "passed",
            notes,
        ),
    )


def executemany(connection: Any, sql: str, rows: Iterable[tuple[Any, ...]]) -> int:
    rows = list(rows)
    if not rows:
        return 0
    with connection.cursor() as cursor:
        cursor.executemany(sql, rows)
    return len(rows)


def insert_business_units(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    return executemany(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.context_business_units (
            business_unit_id, business_unit, executive_owner, business_unit_tier,
            regulatory_scope, description, context_source, raw_record, context_import_batch_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (business_unit_id) DO UPDATE SET
            business_unit = EXCLUDED.business_unit,
            executive_owner = EXCLUDED.executive_owner,
            business_unit_tier = EXCLUDED.business_unit_tier,
            regulatory_scope = EXCLUDED.regulatory_scope,
            description = EXCLUDED.description,
            context_source = EXCLUDED.context_source,
            raw_record = EXCLUDED.raw_record,
            context_import_batch_id = EXCLUDED.context_import_batch_id
        """,
        (
            (
                row["business_unit_id"],
                row["business_unit"],
                empty_to_none(row.get("executive_owner")),
                empty_to_none(row.get("business_unit_tier")),
                split_semicolon(row.get("regulatory_scope")),
                empty_to_none(row.get("description")),
                row["context_source"],
                raw_json(row),
                batch_id,
            )
            for row in rows
        ),
    )


def insert_business_services(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    return executemany(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.context_business_services (
            business_service_id, business_service, business_unit, service_owner,
            service_tier, service_criticality, data_classification,
            recovery_time_objective_hours, recovery_point_objective_hours,
            regulatory_scope, upstream_dependencies, downstream_dependencies,
            context_source, raw_record, context_import_batch_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (business_service_id) DO UPDATE SET
            business_service = EXCLUDED.business_service,
            business_unit = EXCLUDED.business_unit,
            service_owner = EXCLUDED.service_owner,
            service_tier = EXCLUDED.service_tier,
            service_criticality = EXCLUDED.service_criticality,
            data_classification = EXCLUDED.data_classification,
            recovery_time_objective_hours = EXCLUDED.recovery_time_objective_hours,
            recovery_point_objective_hours = EXCLUDED.recovery_point_objective_hours,
            regulatory_scope = EXCLUDED.regulatory_scope,
            upstream_dependencies = EXCLUDED.upstream_dependencies,
            downstream_dependencies = EXCLUDED.downstream_dependencies,
            context_source = EXCLUDED.context_source,
            raw_record = EXCLUDED.raw_record,
            context_import_batch_id = EXCLUDED.context_import_batch_id
        """,
        (
            (
                row["business_service_id"],
                row["business_service"],
                row["business_unit"],
                empty_to_none(row.get("service_owner")),
                empty_to_none(row.get("service_tier")),
                empty_to_none(row.get("service_criticality")),
                empty_to_none(row.get("data_classification")),
                parse_int(row.get("recovery_time_objective_hours")),
                parse_int(row.get("recovery_point_objective_hours")),
                split_semicolon(row.get("regulatory_scope")),
                split_semicolon(row.get("upstream_dependencies")),
                split_semicolon(row.get("downstream_dependencies")),
                row["context_source"],
                raw_json(row),
                batch_id,
            )
            for row in rows
        ),
    )


def insert_data_classifications(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    return executemany(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.context_data_classifications (
            classification_id, data_classification, sensitivity_rank,
            confidentiality_impact, integrity_impact, availability_impact,
            regulatory_scope, handling_requirements, context_source, raw_record, context_import_batch_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (classification_id) DO UPDATE SET
            data_classification = EXCLUDED.data_classification,
            sensitivity_rank = EXCLUDED.sensitivity_rank,
            confidentiality_impact = EXCLUDED.confidentiality_impact,
            integrity_impact = EXCLUDED.integrity_impact,
            availability_impact = EXCLUDED.availability_impact,
            regulatory_scope = EXCLUDED.regulatory_scope,
            handling_requirements = EXCLUDED.handling_requirements,
            context_source = EXCLUDED.context_source,
            raw_record = EXCLUDED.raw_record,
            context_import_batch_id = EXCLUDED.context_import_batch_id
        """,
        (
            (
                row["classification_id"],
                row["data_classification"],
                int(first_present(row, "sensitivity_rank", "risk_score") or 0),
                empty_to_none(row.get("confidentiality_impact")),
                empty_to_none(row.get("integrity_impact")),
                empty_to_none(row.get("availability_impact")),
                split_semicolon(row.get("regulatory_scope")),
                empty_to_none(row.get("handling_requirements")),
                row["context_source"],
                raw_json(row),
                batch_id,
            )
            for row in rows
        ),
    )


def insert_network_zones(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    return executemany(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.context_network_zones (
            network_zone_id, network_zone, subnet, site, environment, cloud_region,
            vpc_or_vlan, trust_level, ingress_egress_direction,
            trusted_boundary_crossing, known_admin_network, known_scanner_network,
            description, raw_record, context_import_batch_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (network_zone_id) DO UPDATE SET
            network_zone = EXCLUDED.network_zone,
            subnet = EXCLUDED.subnet,
            site = EXCLUDED.site,
            environment = EXCLUDED.environment,
            cloud_region = EXCLUDED.cloud_region,
            vpc_or_vlan = EXCLUDED.vpc_or_vlan,
            trust_level = EXCLUDED.trust_level,
            ingress_egress_direction = EXCLUDED.ingress_egress_direction,
            trusted_boundary_crossing = EXCLUDED.trusted_boundary_crossing,
            known_admin_network = EXCLUDED.known_admin_network,
            known_scanner_network = EXCLUDED.known_scanner_network,
            description = EXCLUDED.description,
            raw_record = EXCLUDED.raw_record,
            context_import_batch_id = EXCLUDED.context_import_batch_id
        """,
        (
            (
                row["network_zone_id"],
                row["network_zone"],
                empty_to_none(row.get("subnet")),
                empty_to_none(row.get("site")),
                empty_to_none(row.get("environment")),
                empty_to_none(row.get("cloud_region")),
                empty_to_none(row.get("vpc_or_vlan")),
                row["trust_level"],
                empty_to_none(row.get("ingress_egress_direction")),
                parse_bool(row.get("trusted_boundary_crossing")),
                parse_bool(row.get("known_admin_network")),
                parse_bool(row.get("known_scanner_network")),
                empty_to_none(row.get("description")),
                raw_json(row),
                batch_id,
            )
            for row in rows
        ),
    )


def insert_assets(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    return executemany(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.context_assets (
            asset_id, observed_hostname, observed_agent_name, observed_ip, logical_asset_name,
            asset_owner, business_unit, business_service, asset_criticality, environment,
            asset_role, exposure_level, internet_facing, crown_jewel, data_classification,
            site, cloud_region, network_zone_id, network_zone, service_tier,
            recovery_time_objective_hours, regulatory_scope, monitoring_priority,
            represented_by_observed_host, tags, observed_in_dataset, context_source,
            context_rationale, raw_record, context_import_batch_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (asset_id) DO UPDATE SET
            observed_hostname = EXCLUDED.observed_hostname,
            observed_agent_name = EXCLUDED.observed_agent_name,
            observed_ip = EXCLUDED.observed_ip,
            logical_asset_name = EXCLUDED.logical_asset_name,
            asset_owner = EXCLUDED.asset_owner,
            business_unit = EXCLUDED.business_unit,
            business_service = EXCLUDED.business_service,
            asset_criticality = EXCLUDED.asset_criticality,
            environment = EXCLUDED.environment,
            asset_role = EXCLUDED.asset_role,
            exposure_level = EXCLUDED.exposure_level,
            internet_facing = EXCLUDED.internet_facing,
            crown_jewel = EXCLUDED.crown_jewel,
            data_classification = EXCLUDED.data_classification,
            site = EXCLUDED.site,
            cloud_region = EXCLUDED.cloud_region,
            network_zone_id = EXCLUDED.network_zone_id,
            network_zone = EXCLUDED.network_zone,
            service_tier = EXCLUDED.service_tier,
            recovery_time_objective_hours = EXCLUDED.recovery_time_objective_hours,
            regulatory_scope = EXCLUDED.regulatory_scope,
            monitoring_priority = EXCLUDED.monitoring_priority,
            represented_by_observed_host = EXCLUDED.represented_by_observed_host,
            tags = EXCLUDED.tags,
            observed_in_dataset = EXCLUDED.observed_in_dataset,
            context_source = EXCLUDED.context_source,
            context_rationale = EXCLUDED.context_rationale,
            raw_record = EXCLUDED.raw_record,
            context_import_batch_id = EXCLUDED.context_import_batch_id
        """,
        (
            (
                row["asset_id"],
                empty_to_none(row.get("observed_hostname")),
                empty_to_none(row.get("observed_agent_name")),
                empty_to_none(row.get("observed_ip")),
                row["logical_asset_name"],
                empty_to_none(row.get("asset_owner")),
                row["business_unit"],
                row["business_service"],
                row["asset_criticality"],
                empty_to_none(row.get("environment")),
                row["asset_role"],
                empty_to_none(row.get("exposure_level")),
                parse_bool(row.get("internet_facing")),
                parse_bool(row.get("crown_jewel")),
                row["data_classification"],
                empty_to_none(row.get("site")),
                empty_to_none(row.get("cloud_region")),
                empty_to_none(row.get("network_zone_id")),
                empty_to_none(row.get("network_zone")),
                empty_to_none(row.get("service_tier")),
                parse_int(row.get("recovery_time_objective_hours")),
                split_semicolon(row.get("regulatory_scope")),
                empty_to_none(row.get("monitoring_priority")),
                empty_to_none(row.get("represented_by_observed_host")),
                split_semicolon(row.get("tags")),
                parse_bool(row.get("observed_in_dataset")) or False,
                row["context_source"],
                empty_to_none(row.get("context_rationale")),
                raw_json(row),
                batch_id,
            )
            for row in rows
        ),
    )


def insert_identities(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    return executemany(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.context_identities (
            identity_id, observed_username, logical_username, user_department, user_role,
            identity_type, identity_status, privileged_account, service_account,
            privileged_scope, data_access_level, identity_risk_score, mfa_status,
            recent_identity_alerts, account_age_days, manager_or_owner, normal_assets,
            normal_login_hours, tags, observed_in_dataset, context_source,
            context_rationale, raw_record, context_import_batch_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (identity_id) DO UPDATE SET
            observed_username = EXCLUDED.observed_username,
            logical_username = EXCLUDED.logical_username,
            user_department = EXCLUDED.user_department,
            user_role = EXCLUDED.user_role,
            identity_type = EXCLUDED.identity_type,
            identity_status = EXCLUDED.identity_status,
            privileged_account = EXCLUDED.privileged_account,
            service_account = EXCLUDED.service_account,
            privileged_scope = EXCLUDED.privileged_scope,
            data_access_level = EXCLUDED.data_access_level,
            identity_risk_score = EXCLUDED.identity_risk_score,
            mfa_status = EXCLUDED.mfa_status,
            recent_identity_alerts = EXCLUDED.recent_identity_alerts,
            account_age_days = EXCLUDED.account_age_days,
            manager_or_owner = EXCLUDED.manager_or_owner,
            normal_assets = EXCLUDED.normal_assets,
            normal_login_hours = EXCLUDED.normal_login_hours,
            tags = EXCLUDED.tags,
            observed_in_dataset = EXCLUDED.observed_in_dataset,
            context_source = EXCLUDED.context_source,
            context_rationale = EXCLUDED.context_rationale,
            raw_record = EXCLUDED.raw_record,
            context_import_batch_id = EXCLUDED.context_import_batch_id
        """,
        (
            (
                row["identity_id"],
                empty_to_none(row.get("observed_username")),
                row["logical_username"],
                empty_to_none(row.get("user_department")),
                empty_to_none(row.get("user_role")),
                empty_to_none(row.get("identity_type")),
                empty_to_none(row.get("identity_status")),
                parse_bool(row.get("privileged_account")),
                parse_bool(row.get("service_account")),
                empty_to_none(row.get("privileged_scope")),
                empty_to_none(row.get("data_access_level")),
                parse_int(row.get("identity_risk_score")),
                empty_to_none(row.get("mfa_status")),
                empty_to_none(row.get("recent_identity_alerts")),
                parse_int(row.get("account_age_days")),
                empty_to_none(row.get("manager_or_owner")),
                split_semicolon(row.get("normal_assets")),
                empty_to_none(row.get("normal_login_hours")),
                split_semicolon(row.get("tags")),
                parse_bool(row.get("observed_in_dataset")) or False,
                row["context_source"],
                empty_to_none(row.get("context_rationale")),
                raw_json(row),
                batch_id,
            )
            for row in rows
        ),
    )


def insert_policies(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    return executemany(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.context_policy_catalog (
            policy_id, policy_name, control_family, evidence_requirements,
            escalation_rules, response_constraints, approval_requirements,
            audit_logging_requirements, relevant_asset_roles, relevant_business_units,
            context_source, raw_record, context_import_batch_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (policy_id) DO UPDATE SET
            policy_name = EXCLUDED.policy_name,
            control_family = EXCLUDED.control_family,
            evidence_requirements = EXCLUDED.evidence_requirements,
            escalation_rules = EXCLUDED.escalation_rules,
            response_constraints = EXCLUDED.response_constraints,
            approval_requirements = EXCLUDED.approval_requirements,
            audit_logging_requirements = EXCLUDED.audit_logging_requirements,
            relevant_asset_roles = EXCLUDED.relevant_asset_roles,
            relevant_business_units = EXCLUDED.relevant_business_units,
            context_source = EXCLUDED.context_source,
            raw_record = EXCLUDED.raw_record,
            context_import_batch_id = EXCLUDED.context_import_batch_id
        """,
        (
            (
                row["policy_id"],
                row["policy_name"],
                empty_to_none(row.get("control_family")),
                split_semicolon(row.get("evidence_requirements")),
                empty_to_none(row.get("escalation_rules")),
                empty_to_none(row.get("response_constraints")),
                empty_to_none(row.get("approval_requirements")),
                empty_to_none(row.get("audit_logging_requirements")),
                split_semicolon(row.get("relevant_asset_roles")),
                split_semicolon(row.get("relevant_business_units")),
                row["context_source"],
                raw_json(row),
                batch_id,
            )
            for row in rows
        ),
    )


def insert_mapping_rules(connection: Any, path: Path, batch_id: str) -> int:
    rows = read_csv(path)
    return executemany(
        connection,
        f"""
        INSERT INTO {RUNTIME_SCHEMA}.context_mapping_rules (
            mapping_id, priority, mapping_type, rule_scope, criteria, asset_id,
            identity_id, network_zone_id, policy_ids, confidence, fallback_behavior,
            reason, runtime_allowed_fields, runtime_safe, context_source,
            raw_record, context_import_batch_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (mapping_id) DO UPDATE SET
            priority = EXCLUDED.priority,
            mapping_type = EXCLUDED.mapping_type,
            rule_scope = EXCLUDED.rule_scope,
            criteria = EXCLUDED.criteria,
            asset_id = EXCLUDED.asset_id,
            identity_id = EXCLUDED.identity_id,
            network_zone_id = EXCLUDED.network_zone_id,
            policy_ids = EXCLUDED.policy_ids,
            confidence = EXCLUDED.confidence,
            fallback_behavior = EXCLUDED.fallback_behavior,
            reason = EXCLUDED.reason,
            runtime_allowed_fields = EXCLUDED.runtime_allowed_fields,
            runtime_safe = EXCLUDED.runtime_safe,
            context_source = EXCLUDED.context_source,
            raw_record = EXCLUDED.raw_record,
            context_import_batch_id = EXCLUDED.context_import_batch_id
        """,
        (
            (
                row["mapping_id"],
                int(row["priority"]),
                row["mapping_type"],
                row["rule_scope"],
                empty_to_none(row.get("criteria")),
                row["asset_id"],
                empty_to_none(row.get("identity_id")),
                empty_to_none(row.get("network_zone_id")),
                split_semicolon(row.get("policy_ids")),
                float(row["confidence"]),
                row["fallback_behavior"],
                row["reason"],
                split_semicolon(row.get("runtime_allowed_fields")),
                parse_bool(row.get("runtime_safe")),
                row["context_source"],
                raw_json(row),
                batch_id,
            )
            for row in rows
        ),
    )


def import_context_package(
    paths: ContextImportPaths,
    batch_id: str,
    database_url: str | None = None,
    replace_existing: bool = False,
    apply_schema: bool = False,
) -> ContextImportResult:
    validation_errors = validate_context_import_inputs(paths)
    row_counts, file_hashes = collect_import_metadata(paths)
    if validation_errors:
        return ContextImportResult(batch_id, row_counts, file_hashes, validation_errors)

    config = DatabaseConfig(database_url) if database_url else DatabaseConfig.from_env()
    with connect(config) as connection:
        if apply_schema:
            if not paths.schema_file:
                raise ValueError("schema_file is required when apply_schema=True")
            execute_sql_file(connection, paths.schema_file)

        if replace_existing:
            clear_context_tables(connection)

        insert_import_batch(
            connection,
            batch_id=batch_id,
            row_counts=row_counts,
            file_hashes=file_hashes,
            replace_existing=replace_existing,
            notes="Phase 4 Sprint 5 context import",
        )
        files = required_context_files(paths)
        inserted_counts = {
            "business_units": insert_business_units(connection, files["business_units"], batch_id),
            "business_services": insert_business_services(connection, files["business_services"], batch_id),
            "data_classification": insert_data_classifications(connection, files["data_classification"], batch_id),
            "network_zones": insert_network_zones(connection, files["network_zones"], batch_id),
            "assets": insert_assets(connection, files["asset_inventory"], batch_id),
            "identities": insert_identities(connection, files["identity_inventory"], batch_id),
            "policy_catalog": insert_policies(connection, files["policy_catalog"], batch_id),
            "context_mapping_rules": insert_mapping_rules(connection, files["context_mapping_rules"], batch_id),
        }
        insert_import_batch(
            connection,
            batch_id=batch_id,
            row_counts=inserted_counts,
            file_hashes=file_hashes,
            replace_existing=replace_existing,
            notes="Phase 4 Sprint 5 context import completed",
        )
        connection.commit()

    return ContextImportResult(batch_id, row_counts, file_hashes, [])


def write_import_manifest(result: ContextImportResult, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "phase: phase_04_enterprise_context",
        "sprint: 5",
        "artifact: context_import_manifest",
        f"context_import_batch_id: {result.context_import_batch_id}",
        f"generated_at_utc: {datetime.now(UTC).isoformat()}",
        "validation_status: passed" if not result.validation_errors else "validation_status: failed",
        "row_counts:",
    ]
    lines.extend(f"  {key}: {value}" for key, value in sorted(result.row_counts.items()))
    lines.append("file_hashes:")
    lines.extend(f"  {key}: {value}" for key, value in sorted(result.file_hashes.items()))
    if result.validation_errors:
        lines.append("validation_errors:")
        lines.extend(f"  - {error}" for error in result.validation_errors)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_import_report(result: ContextImportResult, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    status = "passed" if not result.validation_errors else "failed"
    lines = [
        "# Phase 4 Context Import Report",
        "",
        f"Context import batch: `{result.context_import_batch_id}`",
        f"Validation status: `{status}`",
        "",
        "## Row Counts",
        "",
        "| Artifact | Rows |",
        "|---|---:|",
    ]
    lines.extend(f"| `{key}` | {value} |" for key, value in sorted(result.row_counts.items()))
    lines.extend(["", "## File Hashes", "", "| Artifact | SHA256 |", "|---|---|"])
    lines.extend(f"| `{key}` | `{value}` |" for key, value in sorted(result.file_hashes.items()))
    if result.validation_errors:
        lines.extend(["", "## Validation Errors", ""])
        lines.extend(f"- {error}" for error in result.validation_errors)
    else:
        lines.extend(
            [
                "",
                "## Runtime Safety",
                "",
                "The import pipeline validates and imports only Phase 4 context seed and mapping artifacts into `safeagentsoc_runtime` tables.",
                "It does not query or import `safeagentsoc_eval` data.",
            ]
        )
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
