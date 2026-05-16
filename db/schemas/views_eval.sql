CREATE OR REPLACE VIEW safeagentsoc_eval.v_label_linkage_metrics AS
SELECT
    labels.loaded_batch_id,
    COUNT(*) AS label_count,
    COUNT(runtime.alert_uid) AS labels_linked_to_runtime_alerts,
    COUNT(*) - COUNT(runtime.alert_uid) AS labels_without_runtime_alerts
FROM safeagentsoc_eval.ground_truth_labels AS labels
LEFT JOIN safeagentsoc_runtime.normalized_alerts AS runtime
    ON runtime.alert_uid = labels.alert_uid
GROUP BY labels.loaded_batch_id;

CREATE OR REPLACE VIEW safeagentsoc_eval.v_casebook_linkage_metrics AS
SELECT
    links.loaded_batch_id,
    COUNT(DISTINCT links.case_id) AS linked_case_count,
    COUNT(*) AS gold_alert_case_link_count,
    COUNT(runtime.alert_uid) AS gold_links_with_runtime_alerts,
    COUNT(*) - COUNT(runtime.alert_uid) AS gold_links_without_runtime_alerts
FROM safeagentsoc_eval.alert_case_links_gold AS links
LEFT JOIN safeagentsoc_runtime.normalized_alerts AS runtime
    ON runtime.alert_uid = links.alert_uid
GROUP BY links.loaded_batch_id;

CREATE OR REPLACE VIEW safeagentsoc_eval.v_evaluation_alerts_joined AS
SELECT
    runtime.alert_uid,
    runtime.event_time_utc,
    runtime.agent_name,
    runtime.platform,
    runtime.rule_id,
    runtime.event_category,
    runtime.severity_normalized,
    labels.label,
    labels.event_role,
    labels.confidence,
    labels.scenario_id,
    labels.campaign_id,
    labels.run_id,
    labels.case_id
FROM safeagentsoc_runtime.normalized_alerts AS runtime
JOIN safeagentsoc_eval.ground_truth_labels AS labels
    ON labels.alert_uid = runtime.alert_uid;
