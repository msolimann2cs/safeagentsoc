# Database Snapshot Runbook

## Purpose

SafeAgentSOC uses PostgreSQL custom-format dumps as database snapshots.

This gives you restore points before and after risky ingestion steps.

## Snapshot Location

Recommended private backup folder:

```text
09_backups/phase_03_alert_normalization_storage/postgres/
```

Do not commit database dumps.

## Create a Snapshot

From:

```powershell
cd "D:\Seneca\Co op\SafeAgentSOC\05_code\safeagentsoc"
```

Run:

```powershell
py scripts\phase_03_alert_normalization_storage\safeagentsoc_cli.py backup-db `
  --output-dir "..\..\09_backups\phase_03_alert_normalization_storage\postgres" `
  --name "before_sprint7_ingestion"
```

This creates:

```text
before_sprint7_ingestion.dump
before_sprint7_ingestion.manifest.txt
```

## List Snapshots

```powershell
py scripts\phase_03_alert_normalization_storage\safeagentsoc_cli.py list-db-backups `
  --output-dir "..\..\09_backups\phase_03_alert_normalization_storage\postgres"
```

## Restore a Snapshot

Restore replaces database objects contained in the dump.

```powershell
py scripts\phase_03_alert_normalization_storage\safeagentsoc_cli.py restore-db `
  --snapshot "..\..\09_backups\phase_03_alert_normalization_storage\postgres\before_sprint7_ingestion.dump"
```

## Direct PostgreSQL Commands

If you prefer direct PostgreSQL tools:

```powershell
pg_dump --format=custom --verbose --file "..\..\09_backups\phase_03_alert_normalization_storage\postgres\manual_snapshot.dump" $env:SAFEAGENTSOC_DATABASE_URL
```

```powershell
pg_restore --clean --if-exists --verbose --dbname $env:SAFEAGENTSOC_DATABASE_URL "..\..\09_backups\phase_03_alert_normalization_storage\postgres\manual_snapshot.dump"
```

## Recommended Workflow

1. Create a snapshot before ingestion.
2. Run Sprint 7 ingestion.
3. Verify row counts.
4. Create another snapshot after successful ingestion.
5. If anything goes wrong later, restore the known-good snapshot.

## Safety Notes

- Snapshots are private artifacts.
- Snapshots may contain raw alerts, normalized alerts, labels, and casebook data once evaluation loading starts.
- Keep snapshots under `09_backups/`, not inside the git repo.

## Interactive Menu

For a guided workflow:

```powershell
py scripts\phase_03_alert_normalization_storage\safeagentsoc_menu.py
```
