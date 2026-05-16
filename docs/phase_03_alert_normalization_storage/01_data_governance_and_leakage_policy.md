# Phase 3 Data Governance and Leakage Policy

## Purpose

This document defines how SafeAgentSOC separates runtime data from evaluation-only data to prevent ground-truth leakage.

## Runtime Data

Runtime data is data the SafeAgentSOC system is allowed to use during normal operation.

Allowed runtime data:

- Raw alerts
- Normalized alerts
- Evidence references
- MITRE mappings
- Rule metadata
- Asset/user context in later phases
- Policy catalog in later phases
- Case outputs in later phases

## Evaluation-Only Data

Evaluation data is hidden answer-key data used only for benchmarking.

Evaluation-only data:

- ground_truth_labels.csv
- casebook.csv
- scenario_run_log_frozen.csv
- detection_gap_register.csv
- alert_fatigue_baseline.csv
- expected conclusions
- gold alert-to-case links

## Critical Rule

The runtime system and AI modules must not query ground-truth labels, expected conclusions, casebook answers, or evaluation-only tables.

## Database Separation

Runtime tables will live under:

```text
safeagentsoc_runtime
```

Evaluation tables will live under:

```text
safeagentsoc_eval
```

## API Separation

Runtime API endpoints may expose only runtime data.

Evaluator endpoints, if created, must be separated, protected, and documented as not available to the AI/runtime pipeline.

## Git Safety

Private files must not be committed:

- raw alerts
- full labels
- casebook details
- run logs
- detection gaps
- evidence vault data

## Public Artifacts

Safe to commit:

- documentation
- sanitized examples
- source code
- database schemas
- reports without raw private data

## Private Artifacts

Do not commit:

- `06_data/`
- `07_evidence/`
- raw Wazuh exports
- ground truth labels
- casebook files
- run logs
- detection gap registers
