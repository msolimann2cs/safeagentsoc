# Phase 3 Database Design

## Purpose

The Phase 3 database separates runtime SOC data from evaluation-only benchmark data.

This protects the SafeAgentSOC runtime and future AI modules from ground-truth leakage while still allowing separate evaluator scripts to measure correctness.

## Logical Schemas

| Schema | Purpose |
|---|---|
| `safeagentsoc_runtime` | Runtime-safe alerts, evidence, normalization batches, warnings, errors, rules, MITRE references |
| `safeagentsoc_eval` | Ground-truth labels, casebook data, gold alert-case links, scenario logs, detection gaps, baseline comparison data |

## Runtime Tables

| Table | Purpose |
|---|---|
| `safeagentsoc_runtime.normalization_batches` | Batch metadata and manifest summary |
| `safeagentsoc_runtime.raw_alerts` | Raw alert storage with raw line hashes and source line numbers |
| `safeagentsoc_runtime.evidence_references` | Evidence Vault v0 references |
| `safeagentsoc_runtime.normalized_alerts` | Canonical normalized alert records |
| `safeagentsoc_runtime.normalization_warnings` | Non-fatal normalization warnings |
| `safeagentsoc_runtime.normalization_errors` | Failed or blocked normalization events |
| `safeagentsoc_runtime.mitre_techniques` | Runtime MITRE reference table |
| `safeagentsoc_runtime.rule_reference` | Runtime rule metadata summary |

## Raw Alert Hash Behavior

`raw_alert_sha256` is not globally unique because identical Wazuh JSONL lines can appear more than once in the dataset.

The database preserves exact raw position with:

- `alert_uid` as the runtime primary key
- `(raw_file_sha256, raw_line_number)` as the exact source-line uniqueness rule
- `raw_alert_sha256` as a content hash that may repeat when raw lines are identical

## Evaluation-Only Tables

| Table | Purpose |
|---|---|
| `safeagentsoc_eval.ground_truth_labels` | Hidden benchmark labels |
| `safeagentsoc_eval.casebook_cases` | Gold casebook answers and expected conclusions |
| `safeagentsoc_eval.alert_case_links_gold` | Gold alert-to-case links |
| `safeagentsoc_eval.scenario_run_log` | Frozen scenario execution metadata |
| `safeagentsoc_eval.detection_gap_register` | Known detection gaps |
| `safeagentsoc_eval.alert_fatigue_baseline` | Wazuh-only baseline comparison data |
| `safeagentsoc_eval.evaluation_scores` | Evaluation metrics |

## Runtime Views

Runtime API code should query only:

- `safeagentsoc_runtime.v_alerts_runtime`
- `safeagentsoc_runtime.v_evidence_runtime`
- `safeagentsoc_runtime.v_normalization_metrics`
- `safeagentsoc_runtime.v_rule_summary`

These views do not expose labels, event roles, expected conclusions, casebook answers, gold case links, or true-positive/false-positive fields.

## Evaluation Views

Evaluation scripts may query:

- `safeagentsoc_eval.v_label_linkage_metrics`
- `safeagentsoc_eval.v_casebook_linkage_metrics`
- `safeagentsoc_eval.v_evaluation_alerts_joined`

These views are intentionally outside the runtime schema.

## Leakage Rule

Runtime repositories and API endpoints must not query `safeagentsoc_eval`.

The code-level runtime repository guard rejects runtime queries containing evaluation schema names or answer-key terms.

## PostgreSQL Build Order

Apply schema files in this order:

1. `db/schemas/runtime_schema.sql`
2. `db/schemas/eval_schema.sql`
3. `db/schemas/indexes.sql`
4. `db/schemas/views_runtime.sql`
5. `db/schemas/views_eval.sql`

## Sprint 6 Boundary

Sprint 6 defines the PostgreSQL schema and storage repository boundary. It does not load private data yet; historical ingestion starts in Sprint 7.
