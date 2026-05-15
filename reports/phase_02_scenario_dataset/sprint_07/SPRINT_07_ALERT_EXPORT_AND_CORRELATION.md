# Sprint 7: Alert Export, Operation Correlation, and Raw Dataset Assembly

## Goal

Export raw Wazuh alerts and correlate them with scenario, Atomic, and Caldera metadata.

## Export Scope

- Full raw Wazuh alerts were reconstructed from active and rotated Wazuh JSON alert files under `/var/ossec/logs/alerts/`, including `alerts.json` and compressed `ossec-alerts-*.json.gz` archives.
- Per-agent exports created.
- Per-scenario exports created from correlated run windows.
- Per-run exports created using timestamp windows.
- Per-campaign exports created.
- Sanitized sample dataset created.
- Evidence from `C:\D-Drive\Seneca\Co op\SafeAgentSOC\07_evidence\phase_02_scenario_dataset\screenshots\Phase2` was inventoried and used to derive run windows.

## Inputs

| Input | Path |
|---|---|
| Full raw alerts | `06_data\phase_02_scenario_dataset\sprint_07_raw_exports\full\raw_alerts_full.jsonl` |
| Frozen run log | `06_data\phase_02_scenario_dataset\sprint_07_raw_exports\scenario_run_log_frozen.csv` |
| Atomic test metadata | Phase2 Sprint 5 and Sprint 6 evidence CSVs |
| Caldera operation metadata | Phase2 Sprint 5 and Sprint 6 Caldera CSVs |
| Evidence inventory | `06_data\phase_02_scenario_dataset\sprint_07_raw_exports\evidence_inventory.csv` |

## Outputs

| Output | Path |
|---|---|
| Full raw alerts | `06_data\phase_02_scenario_dataset\sprint_07_raw_exports\full\raw_alerts_full.jsonl` |
| Per-agent exports | `06_data\phase_02_scenario_dataset\sprint_07_raw_exports\per_agent` |
| Per-scenario exports | `06_data\phase_02_scenario_dataset\sprint_07_raw_exports\per_scenario` |
| Per-run exports | `06_data\phase_02_scenario_dataset\sprint_07_raw_exports\per_run` |
| Per-campaign exports | `06_data\phase_02_scenario_dataset\sprint_07_raw_exports\per_campaign` |
| Sanitized sample | `06_data\phase_02_scenario_dataset\sprint_07_raw_exports\sanitized_sample\sanitized_sample_alerts.jsonl` |
| Dataset manifest | `06_data\phase_02_scenario_dataset\sprint_07_raw_exports\dataset_manifest.yaml` |

## Evidence Inventory

| File Type | Count |
|---|---:|
| PNG screenshots | 135 |
| CSV exports/logs | 44 |
| JSON files | 9 |
| JSONL exports | 1 |
| DOCX files | 1 |

## Correlation Method

Alerts were correlated to run IDs using:

1. `RUN_ID=` marker alerts found in Wazuh `full_log`.
2. Scenario run log `start_ts` and `end_ts` windows derived from evidence CSV timestamps.
3. `agent.name` matching the expected host.
4. `campaign_id` inferred from the run log and Caldera evidence folder names.

## Current Counts

| Metric | Count |
|---|---:|
| Full raw alerts | 6,893 |
| Run-marker alerts found | 58 |
| Frozen run log rows | 22 |
| Per-run correlated alert references | 595 |
| Sanitized sample alerts | 100 |

Raw export SHA256:

```text
44EF71B93BBC663FB35DB71F4FF129833BC83D244B8A133E83753FEE7FE0C0BF
```

## Per-Agent Counts

| Agent | Alert Count |
|---|---:|
| safesoc-win-01 | 1,042 |
| safesoc-lnx-01 | 5,338 |
| safesoc-wazuh-01 | 513 |
| unknown | 0 |

## Per-Scenario Counts

| Scenario | Alert Count |
|---|---:|
| S01 | 24 |
| S02 | 39 |
| S03 | 8 |
| S04 | 16 |
| S07 | 60 |
| S08 | 28 |
| S09 | 50 |
| S10 | 132 |
| S11 | 48 |
| S12 | 14 |

## Per-Campaign Counts

| Campaign | Alert Count |
|---|---:|
| C-WIN-01 | 12 |
| C-LNX-01 | 164 |

## Per-Run Counts

| Run ID | Alert Count |
|---|---:|
| S11-MAN-R001 | 16 |
| S11-MAN-R002 | 16 |
| S11-MAN-R003 | 16 |
| S12-MAN-R002 | 14 |
| S02-MAN-R001 | 7 |
| S01-ART-R001 | 24 |
| S02-ART-R001 | 32 |
| S03-ART-R001 | 8 |
| S04-ART-R001 | 16 |
| C-WIN-01-CAL-R001 | 2 |
| C-WIN-01-CAL-R002 | 10 |
| S07-MAN-R001 | 51 |
| S07-MAN-R002 | 9 |
| S08-MAN-R001 | 18 |
| S08-MAN-R002 | 10 |
| S09-MAN-R001 | 13 |
| S09-MAN-R002 | 37 |
| S10-MAN-R001 | 49 |
| S10-MAN-R002 | 83 |
| C-LNX-01-CAL-R001 | 13 |
| C-LNX-01-CAL-R002 | 46 |
| C-LNX-01-CAL-R003 | 105 |

## Known Limitations

- Some alerts may be unrelated background telemetry inside the selected run windows.
- Some run windows may include overlapping benign events.
- Campaign-level windows can overlap with scenario-level windows, so per-run and per-campaign totals are correlation references rather than a deduplicated alert count.
- Some Sprint 4 Windows S05/S06 CSV rows contain `START_TIME` and `END_TIME` placeholders and were retained as evidence metadata but not used for raw JSONL timestamp correlation.
- Sprint 8 will perform alert-level labeling, deduplication, confidence scoring, and QA.
- Raw data is stored locally and should not be committed publicly.

## Evidence Screenshots and Artifacts

Evidence screenshots and exported CSVs are stored under:

```text
C:\D-Drive\Seneca\Co op\SafeAgentSOC\07_evidence\phase_02_scenario_dataset\screenshots\Phase2
```

Sprint 7 generated summary artifacts:

| Artifact | Purpose |
|---|---|
| `sprint_07_counts_summary.txt` | Full raw, per-agent, per-scenario, per-run, and per-campaign counts |
| `run_markers_found.csv` | RUN_ID marker extraction results |
| `per_agent_export_summary.csv` | Per-agent alert counts |
| `per_scenario_export_summary.csv` | Per-scenario alert counts |
| `per_run_export_summary.csv` | Per-run alert counts |
| `per_campaign_export_summary.csv` | Per-campaign alert counts |
| `dataset_manifest.yaml` | Dataset metadata and limitations |

## Completion Status

Sprint 7 is complete for the corrected 6,893-alert raw export. The dataset is ready for Sprint 8 ground-truth labeling and QA.
