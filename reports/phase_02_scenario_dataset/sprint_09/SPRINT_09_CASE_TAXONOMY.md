# Sprint 9 Case Taxonomy

## Case Types

| Case Type | Meaning |
|---|---|
| run_case | One investigation case per run_id |
| campaign_case | One investigation case per campaign_id |
| scenario_case | Aggregated view of all alerts for a scenario_id |
| technique_case | Sub-case grouped by run_id and MITRE technique |
| background_noise_case | Raw or sampled background telemetry not directly tied to a scenario |

## Metrics

| Metric | Meaning |
|---|---|
| raw_alert_count | Total alert rows included in the case |
| unique_rule_count | Number of unique Wazuh rule IDs |
| trigger_alert_count | Primary evidence alerts |
| supporting_alert_count | Contextual evidence alerts |
| duplicate_alert_count | Repeated alerts with same investigative meaning |
| noise_alert_count | Noise, unrelated, or low-value alerts |
| duplicate_ratio | duplicate_alert_count / raw_alert_count |
| meaningful_alert_count | trigger_alert_count + supporting_alert_count |
| suppression_candidate_count | duplicate_alert_count + noise_alert_count |
| compression_potential | suppression_candidate_count / raw_alert_count |
| analyst_expected_conclusion | What a SOC analyst should conclude from the case |

## Case Quality Rules

1. Every case must have a case_id.
2. Every case must have a run_id, campaign_id, scenario_id, or background identifier.
3. Every case must include alert-fatigue metrics.
4. Every case must have a clear analyst_expected_conclusion.
5. Duplicate and noise counts must be separated from meaningful trigger/supporting alerts.
6. Casebook totals are case-level benchmark references, not raw alert deduplication totals.
7. Campaign cases may overlap with run cases because campaigns summarize multiple related activities.
