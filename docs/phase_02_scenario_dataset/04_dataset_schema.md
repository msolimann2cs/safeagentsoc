# Dataset Schema

## Purpose

This file documents the schemas used for Phase 2 dataset creation.

## Files

| File | Purpose |
|---|---|
| scenario_run_log_template.csv | Template for recording scenario executions |
| ground_truth_labels_template.csv | Template for alert labels |
| mitre_mapping_template.csv | Scenario-to-MITRE mapping |
| dataset_manifest_template.yaml | Dataset metadata |
| raw_wazuh_alert.schema.json | Reference schema for raw Wazuh alerts |
| ground_truth_label.schema.json | JSON schema for labels |
| scenario.schema.json | JSON schema for scenario definitions |

## Important Dataset Rule

Raw Wazuh alerts must not be manually edited. Create labels and processed files separately.

## Local Working Data

Full data is stored outside GitHub:

```text
C:\D-Drive\Seneca\Co op\SafeAgentSOC\06_data\phase_02_scenario_dataset
```

## GitHub Data

Only schemas and small sanitized samples should be committed.

```text
data/schemas
data/samples/phase_02_scenario_dataset
```

