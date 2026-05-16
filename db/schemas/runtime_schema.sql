CREATE SCHEMA IF NOT EXISTS safeagentsoc_runtime;

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.normalization_batches (
    ingestion_batch_id TEXT PRIMARY KEY,
    source_system TEXT NOT NULL,
    source_adapter TEXT NOT NULL,
    source_file_name TEXT,
    source_file_sha256 TEXT,
    normalizer_version TEXT NOT NULL,
    uid_strategy_version TEXT NOT NULL,
    started_at_utc TIMESTAMPTZ,
    completed_at_utc TIMESTAMPTZ,
    parsed_alert_count INTEGER NOT NULL DEFAULT 0,
    normalized_alert_count INTEGER NOT NULL DEFAULT 0,
    warning_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.raw_alerts (
    alert_uid TEXT PRIMARY KEY,
    ingestion_batch_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.normalization_batches(ingestion_batch_id),
    source_system TEXT NOT NULL,
    source_adapter TEXT NOT NULL,
    source_event_id TEXT,
    raw_alert_sha256 TEXT NOT NULL,
    raw_file_sha256 TEXT NOT NULL,
    raw_file_name TEXT NOT NULL,
    raw_line_number INTEGER NOT NULL CHECK (raw_line_number >= 1),
    event_time_utc TIMESTAMPTZ,
    raw_alert JSONB NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (raw_file_sha256, raw_line_number)
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.evidence_references (
    evidence_id TEXT PRIMARY KEY,
    alert_uid TEXT NOT NULL REFERENCES safeagentsoc_runtime.raw_alerts(alert_uid),
    raw_alert_sha256 TEXT NOT NULL,
    raw_file_sha256 TEXT NOT NULL,
    raw_file_name TEXT NOT NULL,
    raw_line_number INTEGER NOT NULL CHECK (raw_line_number >= 1),
    ingestion_batch_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.normalization_batches(ingestion_batch_id),
    source_system TEXT NOT NULL,
    source_adapter TEXT NOT NULL,
    evidence_confidence TEXT NOT NULL CHECK (evidence_confidence IN ('high', 'medium', 'low', 'unknown')),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (alert_uid, raw_alert_sha256)
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.normalized_alerts (
    alert_uid TEXT PRIMARY KEY REFERENCES safeagentsoc_runtime.raw_alerts(alert_uid),
    evidence_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.evidence_references(evidence_id),
    ingestion_batch_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.normalization_batches(ingestion_batch_id),
    schema_version TEXT NOT NULL,
    source_system TEXT NOT NULL,
    source_adapter TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_event_id TEXT,
    source_location TEXT,
    event_time_utc TIMESTAMPTZ NOT NULL,
    normalized_at_utc TIMESTAMPTZ,
    hostname TEXT,
    agent_id TEXT,
    agent_name TEXT,
    agent_ip INET,
    platform TEXT NOT NULL,
    rule_id TEXT,
    rule_level INTEGER,
    rule_description TEXT,
    decoder_name TEXT,
    event_kind TEXT NOT NULL,
    event_category TEXT NOT NULL,
    event_action TEXT NOT NULL,
    event_outcome TEXT NOT NULL,
    severity_normalized TEXT NOT NULL,
    severity_score NUMERIC(5,2),
    mitre_technique_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    mitre_tactics TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    scenario_id TEXT,
    campaign_id TEXT,
    run_id TEXT,
    execution_mode TEXT,
    benchmark_link_available BOOLEAN NOT NULL DEFAULT false,
    normalization_status TEXT NOT NULL,
    normalized_alert JSONB NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (source_type IN ('siem', 'xdr', 'edr', 'ids', 'log_source', 'unknown')),
    CHECK (severity_normalized IN ('low', 'medium', 'high', 'critical', 'unknown')),
    CHECK (normalization_status IN ('success', 'partial', 'failed'))
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.normalization_warnings (
    warning_id TEXT PRIMARY KEY,
    alert_uid TEXT REFERENCES safeagentsoc_runtime.raw_alerts(alert_uid),
    raw_reference_id TEXT,
    warning_type TEXT NOT NULL,
    field_path TEXT,
    warning_message TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.normalization_errors (
    error_id TEXT PRIMARY KEY,
    alert_uid TEXT REFERENCES safeagentsoc_runtime.raw_alerts(alert_uid),
    raw_reference_id TEXT,
    error_type TEXT NOT NULL,
    field_path TEXT,
    error_message TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.mitre_techniques (
    technique_id TEXT PRIMARY KEY,
    technique_name TEXT,
    tactic TEXT,
    mapping_source TEXT,
    first_seen_alert_uid TEXT REFERENCES safeagentsoc_runtime.raw_alerts(alert_uid),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.rule_reference (
    source_system TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_level INTEGER,
    rule_description TEXT,
    rule_groups TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    decoder_name TEXT,
    first_seen_at_utc TIMESTAMPTZ,
    alert_count INTEGER NOT NULL DEFAULT 0,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source_system, rule_id)
);
