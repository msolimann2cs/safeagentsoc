# Evaluation Query Cookbook

Sprint 10 query-output generation was skipped by request. This cookbook preserves evaluation query patterns for later execution.

Evaluation queries may use both:

- `safeagentsoc_runtime`
- `safeagentsoc_eval`

These queries must not be used by runtime AI endpoints.

## Label Linkage Metrics

```sql
SELECT *
FROM safeagentsoc_eval.v_label_linkage_metrics;
```

## Casebook Linkage Metrics

```sql
SELECT *
FROM safeagentsoc_eval.v_casebook_linkage_metrics;
```

## Alerts From Atomic Red Team Runs

```sql
SELECT l.alert_uid, l.run_id, l.label, l.event_role, r.event_time_utc, r.rule_id, r.rule_description
FROM safeagentsoc_eval.ground_truth_labels l
JOIN safeagentsoc_runtime.v_alerts_runtime r
  ON l.alert_uid = r.alert_uid
WHERE l.tool ILIKE '%Atomic%';
```

## Caldera-Linked Alerts

```sql
SELECT l.alert_uid, l.run_id, l.caldera_operation_id, l.caldera_ability_id, r.rule_id, r.rule_description
FROM safeagentsoc_eval.ground_truth_labels l
JOIN safeagentsoc_runtime.v_alerts_runtime r
  ON l.alert_uid = r.alert_uid
WHERE l.execution_mode = 'caldera';
```

## Casebook Cases By Execution Mode

```sql
SELECT execution_mode, COUNT(*) AS case_count
FROM safeagentsoc_eval.casebook_cases
GROUP BY execution_mode
ORDER BY case_count DESC;
```

## Trigger Alerts By Case

```sql
SELECT case_id, COUNT(*) AS trigger_alert_count
FROM safeagentsoc_eval.ground_truth_labels
WHERE event_role = 'trigger'
GROUP BY case_id
ORDER BY case_id;
```

## Duplicate Candidates By Case

```sql
SELECT case_id, duplicate_alert_count, suppression_candidate_count, compression_potential
FROM safeagentsoc_eval.alert_fatigue_baseline
ORDER BY duplicate_alert_count DESC;
```

## Detection Gap Register

```sql
SELECT *
FROM safeagentsoc_eval.detection_gap_register
ORDER BY loaded_batch_id;
```

## Evaluation Scores

```sql
SELECT *
FROM safeagentsoc_eval.evaluation_scores
ORDER BY created_at_utc DESC;
```

