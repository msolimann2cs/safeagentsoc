# Runtime and Evaluation Boundary

## Purpose

This document defines the strict boundary between data SafeAgentSOC may use at runtime and data used only for evaluation.

## Runtime Data

Runtime data is available to the SafeAgentSOC operational pipeline.

Allowed runtime data:

- raw alerts
- normalized alerts
- rule metadata
- MITRE mappings
- evidence references
- normalization warnings
- normalization errors
- future asset/user context
- future policy catalog
- future runtime case outputs

## Evaluation-Only Data

Evaluation-only data is hidden answer-key data.

Evaluation-only data includes:

- ground_truth_labels.csv
- casebook.csv
- alert_fatigue_baseline.csv
- scenario_run_log_frozen.csv
- detection_gap_register.csv
- expected analyst conclusions
- gold alert-to-case links
- true positive/false positive labels

## Critical Rule

Runtime modules and AI modules must not query evaluation-only data.

## Why This Matters

If the runtime pipeline can see the answer key, then later evaluation metrics become invalid.

## Allowed Runtime Linkage

Runtime objects may contain:

```text
scenario_id
campaign_id
run_id
benchmark_link_available
```

Runtime objects must not contain:

```text
label
event_role
expected_conclusion
gold_case_id
casebook_answer
true_positive
false_positive
```

## Evaluation Linkage

Evaluation scripts may join runtime data to evaluation data by `alert_uid`.

This join is allowed only during benchmarking.
