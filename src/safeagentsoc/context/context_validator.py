from __future__ import annotations

import csv
from pathlib import Path

from safeagentsoc.context.context_loader import load_json_schema
from safeagentsoc.context.mapping_rules import validate_mapping_rules
from safeagentsoc.context.schemas import REQUIRED_CONTEXT_SCHEMA_FILES


REQUIRED_SEED_FILES = [
    "asset_inventory.csv",
    "identity_inventory.csv",
    "network_zones.csv",
    "business_units.csv",
    "business_services.csv",
    "data_classification.csv",
    "policy_catalog_seed.csv",
]

FORBIDDEN_RUNTIME_CONTEXT_TERMS = [
    "ground_truth",
    "expected_conclusion",
    "casebook_answer",
    "true_positive",
    "false_positive",
    "event_role",
    "scenario_label",
    "gold_label",
    "answer_key",
]


def validate_schema_package(schema_dir: Path) -> list[str]:
    errors: list[str] = []
    for filename in REQUIRED_CONTEXT_SCHEMA_FILES:
        path = schema_dir / filename
        if not path.exists():
            errors.append(f"Missing schema: {filename}")
            continue
        data = load_json_schema(path)
        for field in ["$schema", "$id", "title", "type", "properties"]:
            if field not in data:
                errors.append(f"{filename} missing top-level field: {field}")
    return errors


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def check_unique(rows: list[dict[str, str]], key: str, label: str) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for index, row in enumerate(rows, start=2):
        value = row.get(key, "")
        if not value:
            errors.append(f"{label} row {index} missing {key}")
            continue
        if value in seen:
            errors.append(f"{label} duplicate {key}: {value}")
        seen.add(value)
    return errors


def check_forbidden_terms(seed_dir: Path) -> list[str]:
    errors: list[str] = []
    for path in seed_dir.glob("*.csv"):
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        for term in FORBIDDEN_RUNTIME_CONTEXT_TERMS:
            if term in text:
                errors.append(f"{path.name} contains forbidden runtime context term: {term}")
    return errors


def validate_seed_package(seed_dir: Path, observed_hosts_path: Path | None = None) -> list[str]:
    errors: list[str] = []
    for filename in REQUIRED_SEED_FILES:
        if not (seed_dir / filename).exists():
            errors.append(f"Missing seed file: {filename}")

    if errors:
        return errors

    assets = read_csv(seed_dir / "asset_inventory.csv")
    identities = read_csv(seed_dir / "identity_inventory.csv")
    zones = read_csv(seed_dir / "network_zones.csv")
    business_units = read_csv(seed_dir / "business_units.csv")
    services = read_csv(seed_dir / "business_services.csv")
    classifications = read_csv(seed_dir / "data_classification.csv")
    policies = read_csv(seed_dir / "policy_catalog_seed.csv")

    errors.extend(check_unique(assets, "asset_id", "asset_inventory.csv"))
    errors.extend(check_unique(identities, "identity_id", "identity_inventory.csv"))
    errors.extend(check_unique(zones, "network_zone_id", "network_zones.csv"))
    errors.extend(check_unique(business_units, "business_unit_id", "business_units.csv"))
    errors.extend(check_unique(services, "business_service_id", "business_services.csv"))
    errors.extend(check_unique(classifications, "classification_id", "data_classification.csv"))
    errors.extend(check_unique(policies, "policy_id", "policy_catalog_seed.csv"))

    allowed_criticality = {"low", "medium", "high", "critical"}
    allowed_classifications = {"public", "internal", "confidential", "restricted"}
    allowed_exposure = {"internal", "limited", "external", "internet"}
    allowed_sources = {"dataset_anchored_synthetic"}

    for index, asset in enumerate(assets, start=2):
        for field in ["observed_agent_name", "logical_asset_name", "business_unit", "business_service", "asset_criticality", "asset_role", "data_classification", "context_source"]:
            if not asset.get(field):
                errors.append(f"asset_inventory.csv row {index} missing {field}")
        if asset.get("asset_criticality") not in allowed_criticality:
            errors.append(f"asset_inventory.csv row {index} has invalid asset_criticality: {asset.get('asset_criticality')}")
        if asset.get("data_classification") not in allowed_classifications:
            errors.append(f"asset_inventory.csv row {index} has invalid data_classification: {asset.get('data_classification')}")
        if asset.get("exposure_level") not in allowed_exposure:
            errors.append(f"asset_inventory.csv row {index} has invalid exposure_level: {asset.get('exposure_level')}")
        if asset.get("context_source") not in allowed_sources:
            errors.append(f"asset_inventory.csv row {index} must use dataset_anchored_synthetic context_source")

    for index, identity in enumerate(identities, start=2):
        for field in ["identity_id", "logical_username", "user_department", "user_role", "identity_risk_score", "context_source"]:
            if not identity.get(field):
                errors.append(f"identity_inventory.csv row {index} missing {field}")
        try:
            score = int(identity.get("identity_risk_score", ""))
            if score < 0 or score > 100:
                errors.append(f"identity_inventory.csv row {index} identity_risk_score must be 0-100")
        except ValueError:
            errors.append(f"identity_inventory.csv row {index} identity_risk_score is not an integer")
        if identity.get("context_source") not in allowed_sources:
            errors.append(f"identity_inventory.csv row {index} must use dataset_anchored_synthetic context_source")

    if len({row.get("business_unit") for row in business_units}) < 6:
        errors.append("business_units.csv should contain at least six business units for multi-department context")

    observed_agent_names = {row.get("observed_agent_name") for row in assets if row.get("observed_agent_name")}
    if observed_hosts_path and observed_hosts_path.exists():
        observed_hosts = read_csv(observed_hosts_path)
        required_agents = {row.get("agent_name") for row in observed_hosts if row.get("agent_name")}
    else:
        required_agents = {"safesoc-lnx-01", "safesoc-win-01", "safesoc-wazuh-01"}
    missing_agents = sorted(required_agents - observed_agent_names)
    if missing_agents:
        errors.append(f"asset_inventory.csv does not cover observed agents: {', '.join(missing_agents)}")

    wazuh_assets = [asset for asset in assets if asset.get("observed_agent_name") == "safesoc-wazuh-01"]
    if not any(asset.get("asset_criticality") == "critical" and asset.get("crown_jewel") == "true" for asset in wazuh_assets):
        errors.append("safesoc-wazuh-01 must have at least one critical crown-jewel security infrastructure asset")

    errors.extend(check_forbidden_terms(seed_dir))
    return errors


def validate_mapping_rule_package(mapping_rules_path: Path, seed_dir: Path) -> list[str]:
    errors, _summary = validate_mapping_rules(mapping_rules_path, seed_dir)
    return errors
