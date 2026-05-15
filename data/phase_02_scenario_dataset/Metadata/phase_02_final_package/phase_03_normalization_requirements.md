# Phase 3 Normalization Requirements from Sprint 9

## Purpose

Sprint 9 converted alert-level labels into case-level investigation records and alert-fatigue baselines. Phase 3 should use these requirements to design the SafeAgentSOC normalization and triage pipeline.

## Required Case Inputs

SafeAgentSOC should ingest:

- raw_alert_count
- unique_rule_count
- trigger_alert_count
- supporting_alert_count
- duplicate_alert_count
- noise_alert_count
- duplicate_ratio
- compression_potential
- mitre_techniques
- execution_mode
- tool
- case_summary
- analyst_expected_conclusion

## Required Normalization Tasks

1. Normalize repeated alerts into one case-level finding.
2. Preserve trigger alerts as primary evidence.
3. Preserve supporting alerts as context.
4. Suppress or collapse duplicate alerts.
5. Separate unrelated background telemetry from attack-like behavior.
6. Group campaign-level alerts into multi-stage narratives.
7. Provide analyst-facing conclusions.
8. Track whether a case came from manual, Atomic Red Team, Caldera, benign/noise, or simulated-only execution.

## Required Evaluation Metrics

| Metric | Purpose |
|---|---|
| alert_reduction_ratio | Measures alert compression |
| duplicate_suppression_rate | Measures duplicate reduction |
| trigger_preservation_rate | Measures whether important alerts remain visible |
| case_summary_quality | Measures usefulness of generated case summaries |
| analyst_expected_conclusion_match | Measures whether SafeAgentSOC reaches the intended conclusion |

## Phase 3 Benchmarking Idea

For each Sprint 9 case:

1. Give SafeAgentSOC the raw alerts for the case.
2. Ask it to summarize the case.
3. Ask it to classify the case as benign, noise, attack-like, failed attack-like, simulated-only, or unrelated.
4. Ask it to identify trigger, supporting, duplicate, and noise alerts.
5. Compare the output against the Sprint 9 casebook and Sprint 8 labels.

## Key Design Constraint

SafeAgentSOC must reduce alert fatigue without hiding primary trigger evidence.
