# Sprint 7 Report: Historical Ingestion Pipeline and Database Snapshots

## Sprint Goal

Create a repeatable historical ingestion pipeline that loads Phase 3 runtime artifacts into PostgreSQL while keeping evaluation loading separate.

This sprint also adds PostgreSQL snapshot and restore tooling so database states can be backed up and recovered before or after major ingestion steps.

## Why This Sprint Matters

Sprint 7 makes the Phase 3 database reproducible. The runtime layer can be rebuilt from the raw Wazuh JSONL, lineage files, evidence references, normalized alerts, warnings, and errors.

Database snapshots make this safer: before a risky load, create a restore point; after a successful load, create a known-good snapshot.

## Deliverables

- `src/safeagentsoc/cli.py`
- `src/safeagentsoc/ingestion/pipeline.py`
- `src/safeagentsoc/ingestion/eval_loader.py`
- `src/safeagentsoc/storage/snapshots.py`
- `scripts/phase_03_alert_normalization_storage/safeagentsoc_cli.py`
- `scripts/phase_03_alert_normalization_storage/safeagentsoc_menu.py`
- `docs/phase_03_alert_normalization_storage/historical_ingestion_runbook.md`
- `docs/phase_03_alert_normalization_storage/database_snapshot_runbook.md`
- `tests/test_ingestion_pipeline.py`
- `tests/test_snapshots.py`

## Runtime Ingestion Inputs

- raw Wazuh JSONL
- `raw_alert_lineage.csv`
- `evidence_reference.csv`
- `normalized_alerts_v1.jsonl`
- `normalization_warnings.csv`
- `normalization_errors.csv`

## Runtime Tables Loaded

- `safeagentsoc_runtime.normalization_batches`
- `safeagentsoc_runtime.raw_alerts`
- `safeagentsoc_runtime.evidence_references`
- `safeagentsoc_runtime.normalized_alerts`
- `safeagentsoc_runtime.normalization_warnings`
- `safeagentsoc_runtime.normalization_errors`
- `safeagentsoc_runtime.rule_reference`
- `safeagentsoc_runtime.mitre_techniques`

## Evaluation Loading

Evaluation loading is separate and targets only `safeagentsoc_eval`.

Supported loader inputs:

- `ground_truth_labels.csv`
- `casebook.csv`
- `alert_fatigue_baseline.csv`

## Snapshot Support

Snapshot commands wrap PostgreSQL tools:

- `pg_dump`
- `pg_restore`

Recommended private backup location:

```text
09_backups/phase_03_alert_normalization_storage/postgres/
```

Snapshot commands:

- `safeagentsoc backup-db`
- `safeagentsoc list-db-backups`
- `safeagentsoc restore-db`

The interactive menu can be launched with:

```powershell
py scripts\phase_03_alert_normalization_storage\safeagentsoc_menu.py
```

## Verification

- Sprint 7 Python files compile successfully.
- Focused ingestion helper tests passed.
- Focused snapshot path tests passed.
- CLI help works for `ingest-alerts` and `backup-db`.
- Sprint 1 schema package validation still passes.
- Live PostgreSQL ingestion was not executed from the Codex shell because this shell does not expose PostgreSQL CLI tools or a Python PostgreSQL driver.

## Expected Runtime Counts

| Artifact | Expected Count |
|---|---:|
| Raw alerts | 6,893 |
| Normalized alerts | 6,893 |
| Evidence references | 6,893 |
| Normalization warnings | 6,185 |
| Normalization errors | 0 |

## Sprint 7 Done Criteria

- [x] Runtime ingestion pipeline exists
- [x] Evaluation loader exists separately
- [x] CLI entrypoint exists
- [x] Batch summary output path is documented
- [x] Batch QA report output path is documented
- [x] Database snapshot creation exists
- [x] Database snapshot restore exists
- [x] Snapshot runbook exists
- [ ] Runtime ingestion executed against local PostgreSQL
- [ ] Eval loading executed against local PostgreSQL
- [ ] Row counts verified in PostgreSQL
- [ ] Post-ingestion database snapshot created

## Notes

The local Codex shell does not currently expose `psql`, `pg_dump`, `pg_restore`, or a Python PostgreSQL driver. The code and runbooks are ready, but the actual database load should be run from the PostgreSQL-aware PowerShell environment used to verify Sprint 6.

If ingestion fails on `raw_alert_sha256` uniqueness, apply `db/migrations/0001_allow_duplicate_raw_alert_hashes.sql` and rerun with `--replace-batch`. Duplicate raw alert content is valid; exact evidence uniqueness is source file hash plus raw line number.
