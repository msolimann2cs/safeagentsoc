# Sprint 6 Report: Runtime/Evaluation Database Design and PostgreSQL Build

## Sprint Goal

Design the PostgreSQL database layer with strict runtime/evaluation separation.

## Why This Sprint Matters

This sprint prevents ground-truth leakage before the API and future AI modules exist. Runtime data and evaluation-only answer-key data are stored in different logical schemas with separate views and repository access paths.

## Deliverables

- `db/schemas/runtime_schema.sql`
- `db/schemas/eval_schema.sql`
- `db/schemas/indexes.sql`
- `db/schemas/views_runtime.sql`
- `db/schemas/views_eval.sql`
- `src/safeagentsoc/storage/db.py`
- `src/safeagentsoc/storage/repository.py`
- `docs/phase_03_alert_normalization_storage/database_design.md`
- `tests/test_database_schema.py`

## Runtime Schema

Runtime schema name:

```text
safeagentsoc_runtime
```

Runtime tables:

- `normalization_batches`
- `raw_alerts`
- `evidence_references`
- `normalized_alerts`
- `normalization_warnings`
- `normalization_errors`
- `mitre_techniques`
- `rule_reference`

## Runtime Constraint Note

`raw_alert_sha256` is intentionally not unique. Duplicate raw alert lines can exist in historical Wazuh exports, so exact evidence uniqueness is enforced by `(raw_file_sha256, raw_line_number)` and runtime identity is enforced by `alert_uid`.

## Evaluation Schema

Evaluation schema name:

```text
safeagentsoc_eval
```

Evaluation-only tables:

- `ground_truth_labels`
- `casebook_cases`
- `alert_case_links_gold`
- `scenario_run_log`
- `detection_gap_register`
- `alert_fatigue_baseline`
- `evaluation_scores`

## Runtime Views

Runtime-facing views are defined only under `safeagentsoc_runtime`.

They do not expose:

- ground-truth labels
- casebook answers
- expected conclusions
- gold alert-to-case links
- true-positive or false-positive fields

## Storage Code

`RuntimeAlertRepository` includes a query guard that rejects evaluation schema references and answer-key terms in runtime queries.

`EvaluationRepository` is separate and reserved for evaluation scripts.

## Verification

- Python storage files compile successfully.
- Static database boundary tests passed.
- Runtime schema and runtime views do not expose ground-truth, casebook, expected-conclusion, gold-link, true-positive, or false-positive fields.
- Evaluation views are allowed to join `safeagentsoc_runtime` and `safeagentsoc_eval`.
- `psql` was not available in the local shell, so applying the SQL to a live PostgreSQL instance is deferred to the Sprint 7 ingestion environment.

## Sprint 6 Done Criteria

- [ ] PostgreSQL database runs
- [x] Runtime schema exists
- [x] Evaluation schema exists
- [x] Ground-truth tables are separated
- [x] Indexes are defined
- [x] Runtime views do not expose labels
- [x] Database design report exists
- [x] Storage repository boundary exists

## Notes

Sprint 6 defines the PostgreSQL build artifacts and storage boundary. Loading the database with private Phase 3 data is intentionally deferred to Sprint 7.
