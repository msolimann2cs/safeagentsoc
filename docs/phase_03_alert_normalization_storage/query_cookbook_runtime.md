# Runtime Query Cookbook

Sprint 10 query-output generation was skipped by request. This cookbook preserves the runtime query patterns for future execution.

Runtime queries must use only `safeagentsoc_runtime`.

## Find High-Severity Linux Alerts

```sql
SELECT alert_uid, event_time_utc, agent_name, rule_id, rule_description, severity_normalized
FROM safeagentsoc_runtime.v_alerts_runtime
WHERE platform = 'linux'
  AND severity_normalized IN ('high', 'critical')
ORDER BY event_time_utc DESC;
```

## Find Alerts For One Host

```sql
SELECT *
FROM safeagentsoc_runtime.v_alerts_runtime
WHERE agent_name = 'safesoc-lnx-01'
ORDER BY event_time_utc DESC;
```

## Find Alerts Mapped To T1057

```sql
SELECT alert_uid, event_time_utc, agent_name, rule_id, rule_description
FROM safeagentsoc_runtime.v_alerts_runtime
WHERE 'T1057' = ANY(mitre_technique_ids);
```

## Find Authentication Activity

```sql
SELECT alert_uid, event_time_utc, agent_name, rule_id, event_action, event_outcome
FROM safeagentsoc_runtime.v_alerts_runtime
WHERE event_category = 'authentication';
```

## Top Noisy Rules

```sql
SELECT rule_id, rule_description, COUNT(*) AS alert_count
FROM safeagentsoc_runtime.v_alerts_runtime
GROUP BY rule_id, rule_description
ORDER BY alert_count DESC
LIMIT 20;
```

## Alerts Missing MITRE Mappings

```sql
SELECT alert_uid, event_time_utc, agent_name, rule_id, rule_description
FROM safeagentsoc_runtime.v_alerts_runtime
WHERE cardinality(mitre_technique_ids) = 0;
```

## Alerts By Event Category

```sql
SELECT event_category, COUNT(*) AS alert_count
FROM safeagentsoc_runtime.v_alerts_runtime
GROUP BY event_category
ORDER BY alert_count DESC;
```

## Alerts By Normalized Severity

```sql
SELECT severity_normalized, COUNT(*) AS alert_count
FROM safeagentsoc_runtime.v_alerts_runtime
GROUP BY severity_normalized
ORDER BY alert_count DESC;
```

## Alerts With Normalization Warnings

```sql
SELECT a.alert_uid, a.event_time_utc, a.agent_name, w.warning_type, w.field_path, w.warning_message
FROM safeagentsoc_runtime.v_alerts_runtime a
JOIN safeagentsoc_runtime.normalization_warnings w
  ON a.alert_uid = w.alert_uid
ORDER BY a.event_time_utc DESC;
```

## Reconstruct Evidence For One Alert

```sql
SELECT *
FROM safeagentsoc_runtime.v_evidence_runtime
WHERE alert_uid = '<alert_uid>';
```

## Count Alerts Per Endpoint

```sql
SELECT agent_name, COUNT(*) AS alert_count
FROM safeagentsoc_runtime.v_alerts_runtime
GROUP BY agent_name
ORDER BY alert_count DESC;
```

## Count Alerts Per Rule Level

```sql
SELECT rule_level, COUNT(*) AS alert_count
FROM safeagentsoc_runtime.v_alerts_runtime
GROUP BY rule_level
ORDER BY rule_level;
```

## Count Alerts Per Decoder

```sql
SELECT decoder_name, COUNT(*) AS alert_count
FROM safeagentsoc_runtime.v_alerts_runtime
GROUP BY decoder_name
ORDER BY alert_count DESC;
```

