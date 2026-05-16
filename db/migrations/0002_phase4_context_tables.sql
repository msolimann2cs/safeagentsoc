CREATE SCHEMA IF NOT EXISTS safeagentsoc_runtime;

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_import_batches (
    context_import_batch_id TEXT PRIMARY KEY,
    context_source TEXT NOT NULL,
    imported_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    imported_by TEXT,
    replace_existing BOOLEAN NOT NULL DEFAULT false,
    source_manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
    row_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
    file_hashes JSONB NOT NULL DEFAULT '{}'::jsonb,
    validation_status TEXT NOT NULL CHECK (validation_status IN ('passed', 'failed')),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_business_units (
    business_unit_id TEXT PRIMARY KEY,
    business_unit TEXT NOT NULL UNIQUE,
    executive_owner TEXT,
    business_unit_tier TEXT,
    regulatory_scope TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    description TEXT,
    context_source TEXT NOT NULL,
    raw_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_business_services (
    business_service_id TEXT PRIMARY KEY,
    business_service TEXT NOT NULL UNIQUE,
    business_unit TEXT NOT NULL,
    service_owner TEXT,
    service_tier TEXT,
    service_criticality TEXT CHECK (service_criticality IN ('low', 'medium', 'high', 'critical')),
    data_classification TEXT,
    recovery_time_objective_hours INTEGER,
    recovery_point_objective_hours INTEGER,
    regulatory_scope TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    upstream_dependencies TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    downstream_dependencies TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    context_source TEXT NOT NULL,
    raw_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_data_classifications (
    classification_id TEXT PRIMARY KEY,
    data_classification TEXT NOT NULL UNIQUE,
    sensitivity_rank INTEGER NOT NULL CHECK (sensitivity_rank BETWEEN 0 AND 100),
    confidentiality_impact TEXT,
    integrity_impact TEXT,
    availability_impact TEXT,
    regulatory_scope TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    handling_requirements TEXT,
    context_source TEXT NOT NULL,
    raw_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_network_zones (
    network_zone_id TEXT PRIMARY KEY,
    network_zone TEXT NOT NULL UNIQUE,
    subnet CIDR,
    site TEXT,
    environment TEXT,
    cloud_region TEXT,
    vpc_or_vlan TEXT,
    trust_level TEXT NOT NULL CHECK (trust_level IN ('low', 'medium', 'high', 'critical', 'unknown')),
    ingress_egress_direction TEXT,
    trusted_boundary_crossing BOOLEAN,
    known_admin_network BOOLEAN,
    known_scanner_network BOOLEAN,
    description TEXT,
    raw_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_assets (
    asset_id TEXT PRIMARY KEY,
    observed_hostname TEXT,
    observed_agent_name TEXT,
    observed_ip INET,
    logical_asset_name TEXT NOT NULL,
    asset_owner TEXT,
    business_unit TEXT NOT NULL,
    business_service TEXT NOT NULL,
    asset_criticality TEXT NOT NULL CHECK (asset_criticality IN ('low', 'medium', 'high', 'critical')),
    environment TEXT,
    asset_role TEXT NOT NULL,
    exposure_level TEXT CHECK (exposure_level IN ('internal', 'limited', 'external', 'internet')),
    internet_facing BOOLEAN,
    crown_jewel BOOLEAN,
    data_classification TEXT NOT NULL,
    site TEXT,
    cloud_region TEXT,
    network_zone_id TEXT REFERENCES safeagentsoc_runtime.context_network_zones(network_zone_id),
    network_zone TEXT,
    service_tier TEXT,
    recovery_time_objective_hours INTEGER,
    regulatory_scope TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    monitoring_priority TEXT,
    represented_by_observed_host TEXT,
    tags TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    observed_in_dataset BOOLEAN NOT NULL DEFAULT true,
    context_source TEXT NOT NULL,
    context_rationale TEXT,
    raw_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_identities (
    identity_id TEXT PRIMARY KEY,
    observed_username TEXT,
    logical_username TEXT NOT NULL,
    user_department TEXT,
    user_role TEXT,
    identity_type TEXT,
    identity_status TEXT,
    privileged_account BOOLEAN,
    service_account BOOLEAN,
    privileged_scope TEXT,
    data_access_level TEXT,
    identity_risk_score INTEGER CHECK (identity_risk_score BETWEEN 0 AND 100),
    mfa_status TEXT,
    recent_identity_alerts TEXT,
    account_age_days INTEGER,
    manager_or_owner TEXT,
    normal_assets TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    normal_login_hours TEXT,
    tags TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    observed_in_dataset BOOLEAN NOT NULL DEFAULT true,
    context_source TEXT NOT NULL,
    context_rationale TEXT,
    raw_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_policy_catalog (
    policy_id TEXT PRIMARY KEY,
    policy_name TEXT NOT NULL,
    control_family TEXT,
    evidence_requirements TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    escalation_rules TEXT,
    response_constraints TEXT,
    approval_requirements TEXT,
    audit_logging_requirements TEXT,
    relevant_asset_roles TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    relevant_business_units TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    context_source TEXT NOT NULL,
    raw_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_mapping_rules (
    mapping_id TEXT PRIMARY KEY,
    priority INTEGER NOT NULL,
    mapping_type TEXT NOT NULL CHECK (mapping_type IN ('exact_identity', 'behavioral', 'agent_fallback', 'generic_unknown_fallback')),
    rule_scope TEXT NOT NULL CHECK (rule_scope IN ('asset_identity', 'asset_only', 'unknown_context')),
    criteria TEXT,
    asset_id TEXT NOT NULL,
    identity_id TEXT,
    identity_applicability_status TEXT CHECK (identity_applicability_status IN ('resolved', 'missing', 'not_applicable', 'unknown')),
    network_zone_id TEXT,
    policy_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    confidence NUMERIC(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    fallback_behavior TEXT NOT NULL CHECK (fallback_behavior IN ('use_matched_context', 'use_agent_default_context', 'return_unknown_context')),
    reason TEXT NOT NULL,
    runtime_allowed_fields TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    runtime_safe BOOLEAN NOT NULL DEFAULT true,
    context_source TEXT NOT NULL,
    raw_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (runtime_safe IS TRUE),
    CHECK (asset_id = '__UNKNOWN__' OR asset_id <> '')
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_enriched_alerts (
    alert_uid TEXT PRIMARY KEY REFERENCES safeagentsoc_runtime.normalized_alerts(alert_uid),
    evidence_id TEXT NOT NULL,
    mapping_id TEXT REFERENCES safeagentsoc_runtime.context_mapping_rules(mapping_id),
    asset_id TEXT,
    identity_id TEXT,
    identity_applicability_status TEXT CHECK (identity_applicability_status IN ('resolved', 'missing', 'not_applicable', 'unknown')),
    network_zone_id TEXT,
    business_unit TEXT,
    business_service TEXT,
    business_risk_score NUMERIC(5,2),
    business_risk_label TEXT CHECK (business_risk_label IN ('low', 'medium', 'high', 'critical')),
    analyst_priority_score NUMERIC(5,2),
    analyst_priority_label TEXT CHECK (analyst_priority_label IN ('low', 'medium', 'high', 'critical')),
    urgent_priority_gate_passed BOOLEAN NOT NULL DEFAULT false,
    risk_confidence NUMERIC(5,4),
    context_confidence NUMERIC(5,4),
    missing_context_fields TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    context_enriched_alert JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE safeagentsoc_runtime.context_enriched_alerts
    ADD COLUMN IF NOT EXISTS business_risk_score NUMERIC(5,2),
    ADD COLUMN IF NOT EXISTS business_risk_label TEXT CHECK (business_risk_label IN ('low', 'medium', 'high', 'critical')),
    ADD COLUMN IF NOT EXISTS analyst_priority_score NUMERIC(5,2),
    ADD COLUMN IF NOT EXISTS analyst_priority_label TEXT CHECK (analyst_priority_label IN ('low', 'medium', 'high', 'critical')),
    ADD COLUMN IF NOT EXISTS urgent_priority_gate_passed BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS risk_confidence NUMERIC(5,4),
    ADD COLUMN IF NOT EXISTS identity_applicability_status TEXT CHECK (identity_applicability_status IN ('resolved', 'missing', 'not_applicable', 'unknown'));

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_missing_context_events (
    missing_context_event_id TEXT PRIMARY KEY,
    alert_uid TEXT REFERENCES safeagentsoc_runtime.normalized_alerts(alert_uid),
    missing_field TEXT NOT NULL,
    missing_reason TEXT,
    mapping_id TEXT,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_graph_nodes (
    node_id TEXT PRIMARY KEY,
    node_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    display_name TEXT,
    properties JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.context_graph_edges (
    edge_id TEXT PRIMARY KEY,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_import_batch_id TEXT REFERENCES safeagentsoc_runtime.context_import_batches(context_import_batch_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_context_assets_observed_agent ON safeagentsoc_runtime.context_assets(observed_agent_name);
CREATE INDEX IF NOT EXISTS idx_context_assets_business_unit ON safeagentsoc_runtime.context_assets(business_unit);
CREATE INDEX IF NOT EXISTS idx_context_assets_business_service ON safeagentsoc_runtime.context_assets(business_service);
CREATE INDEX IF NOT EXISTS idx_context_assets_criticality ON safeagentsoc_runtime.context_assets(asset_criticality);
CREATE INDEX IF NOT EXISTS idx_context_identities_observed_username ON safeagentsoc_runtime.context_identities(observed_username);
CREATE INDEX IF NOT EXISTS idx_context_identities_privileged ON safeagentsoc_runtime.context_identities(privileged_account);
CREATE INDEX IF NOT EXISTS idx_context_mapping_rules_priority ON safeagentsoc_runtime.context_mapping_rules(priority DESC, mapping_id);
CREATE INDEX IF NOT EXISTS idx_context_enriched_alerts_asset ON safeagentsoc_runtime.context_enriched_alerts(asset_id);
CREATE INDEX IF NOT EXISTS idx_context_enriched_alerts_business_unit ON safeagentsoc_runtime.context_enriched_alerts(business_unit);
CREATE INDEX IF NOT EXISTS idx_context_enriched_alerts_identity_applicability ON safeagentsoc_runtime.context_enriched_alerts(identity_applicability_status);
CREATE INDEX IF NOT EXISTS idx_context_enriched_alerts_risk_label ON safeagentsoc_runtime.context_enriched_alerts(business_risk_label);
CREATE INDEX IF NOT EXISTS idx_context_enriched_alerts_risk_score ON safeagentsoc_runtime.context_enriched_alerts(business_risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_context_enriched_alerts_analyst_priority_label ON safeagentsoc_runtime.context_enriched_alerts(analyst_priority_label);
CREATE INDEX IF NOT EXISTS idx_context_enriched_alerts_analyst_priority_score ON safeagentsoc_runtime.context_enriched_alerts(analyst_priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_context_graph_edges_source ON safeagentsoc_runtime.context_graph_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_context_graph_edges_target ON safeagentsoc_runtime.context_graph_edges(target_node_id);
