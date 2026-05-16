CREATE OR REPLACE VIEW safeagentsoc_runtime.v_alerts_runtime AS
SELECT
    alert_uid,
    evidence_id,
    ingestion_batch_id,
    source_system,
    source_adapter,
    event_time_utc,
    hostname,
    agent_id,
    agent_name,
    agent_ip,
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
    normalization_status,
    benchmark_link_available
FROM safeagentsoc_runtime.normalized_alerts;

CREATE OR REPLACE VIEW safeagentsoc_runtime.v_evidence_runtime AS
SELECT
    evidence_id,
    alert_uid,
    raw_alert_sha256,
    raw_file_sha256,
    raw_file_name,
    raw_line_number,
    ingestion_batch_id,
    source_system,
    source_adapter,
    evidence_confidence
FROM safeagentsoc_runtime.evidence_references;

CREATE OR REPLACE VIEW safeagentsoc_runtime.v_normalization_metrics AS
SELECT
    ingestion_batch_id,
    COUNT(*) AS normalized_alert_count,
    COUNT(*) FILTER (WHERE normalization_status = 'success') AS success_count,
    COUNT(*) FILTER (WHERE normalization_status = 'partial') AS partial_count,
    COUNT(*) FILTER (WHERE normalization_status = 'failed') AS failed_count,
    COUNT(*) FILTER (WHERE cardinality(mitre_technique_ids) > 0 OR cardinality(mitre_tactics) > 0) AS mitre_mapped_count,
    COUNT(*) FILTER (WHERE evidence_id IS NOT NULL) AS evidence_linked_count
FROM safeagentsoc_runtime.normalized_alerts
GROUP BY ingestion_batch_id;

CREATE OR REPLACE VIEW safeagentsoc_runtime.v_rule_summary AS
SELECT
    source_system,
    rule_id,
    MAX(rule_level) AS rule_level,
    MAX(rule_description) AS rule_description,
    COUNT(*) AS alert_count,
    COUNT(DISTINCT agent_name) AS distinct_agent_count,
    MIN(event_time_utc) AS first_seen_utc,
    MAX(event_time_utc) AS last_seen_utc
FROM safeagentsoc_runtime.normalized_alerts
GROUP BY source_system, rule_id;
