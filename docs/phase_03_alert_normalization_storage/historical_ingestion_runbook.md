# Historical Ingestion Runbook

## Purpose

Sprint 7 loads runtime Phase 3 artifacts into PostgreSQL in a repeatable way.

Runtime ingestion uses:

- raw Wazuh JSONL
- raw alert lineage
- evidence references
- normalized alerts
- normalization warnings
- normalization errors

Evaluation loading is separate and uses only `safeagentsoc_eval`.

## Required Python Package

Install a PostgreSQL driver in the Python environment you use to run the CLI:

```powershell
py -m pip install "psycopg[binary]"
```

## Connection String

```powershell
$env:SAFEAGENTSOC_DATABASE_URL = "postgresql://safeagentsoc:safeagentsoc@localhost:5432/safeagentsoc"
```

## Create a Pre-Ingestion Snapshot

```powershell
py scripts\phase_03_alert_normalization_storage\safeagentsoc_cli.py backup-db `
  --output-dir "..\..\09_backups\phase_03_alert_normalization_storage\postgres" `
  --name "before_sprint7_ingestion"
```

## Runtime Ingestion

```powershell
py scripts\phase_03_alert_normalization_storage\safeagentsoc_cli.py ingest-alerts `
  --input "data\phase_02_scenario_dataset\Metadata\sprint_08_ground_truth\raw_alerts_full.jsonl" `
  --lineage "..\..\06_data\phase_03_alert_normalization_storage\lineage\raw_alert_lineage.csv" `
  --evidence "..\..\06_data\phase_03_alert_normalization_storage\lineage\evidence_reference.csv" `
  --normalized "..\..\06_data\phase_03_alert_normalization_storage\normalized\normalized_alerts_v1.jsonl" `
  --warnings "..\..\06_data\phase_03_alert_normalization_storage\normalized\normalization_warnings.csv" `
  --errors "..\..\06_data\phase_03_alert_normalization_storage\normalized\normalization_errors.csv" `
  --batch "phase3_v1" `
  --replace-batch `
  --summary-output "..\..\06_data\phase_03_alert_normalization_storage\batches\phase3_v1\ingestion_summary.csv" `
  --qa-report-output "..\..\06_data\phase_03_alert_normalization_storage\batches\phase3_v1\batch_qa_report.md"
```

## Verify Runtime Counts

```sql
SELECT COUNT(*) FROM safeagentsoc_runtime.raw_alerts WHERE ingestion_batch_id = 'phase3_v1';
SELECT COUNT(*) FROM safeagentsoc_runtime.normalized_alerts WHERE ingestion_batch_id = 'phase3_v1';
SELECT COUNT(*) FROM safeagentsoc_runtime.evidence_references WHERE ingestion_batch_id = 'phase3_v1';
SELECT COUNT(*) FROM safeagentsoc_runtime.normalization_warnings;
SELECT COUNT(*) FROM safeagentsoc_runtime.normalization_errors;
SELECT * FROM safeagentsoc_runtime.v_normalization_metrics;
```

Expected runtime counts:

| Artifact | Expected Count |
|---|---:|
| Raw alerts | 6,893 |
| Normalized alerts | 6,893 |
| Evidence references | 6,893 |
| Normalization warnings | 6,185 |
| Normalization errors | 0 |

## Create a Post-Ingestion Snapshot

```powershell
py scripts\phase_03_alert_normalization_storage\safeagentsoc_cli.py backup-db `
  --output-dir "..\..\09_backups\phase_03_alert_normalization_storage\postgres" `
  --name "after_sprint7_ingestion"
```

## Evaluation Loading

Evaluation loading is intentionally separate:

```powershell
py scripts\phase_03_alert_normalization_storage\safeagentsoc_cli.py load-eval `
  --labels "..\..\06_data\phase_03_alert_normalization_storage\frozen_inputs\ground_truth_labels.csv" `
  --casebook "..\..\06_data\phase_03_alert_normalization_storage\frozen_inputs\casebook.csv" `
  --fatigue "..\..\06_data\phase_03_alert_normalization_storage\frozen_inputs\alert_fatigue_baseline.csv" `
  --batch "phase3_v1" `
  --replace-batch
```

Only run evaluation loading after the private evaluation files are frozen into the expected location.

## Interactive Menu

You can also use the menu tool:

```powershell
py scripts\phase_03_alert_normalization_storage\safeagentsoc_menu.py
```

The menu lets you:

- save a database snapshot
- restore a database snapshot
- run runtime ingestion with the default Phase 3 paths
