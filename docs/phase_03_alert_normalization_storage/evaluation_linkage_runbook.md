# Evaluation Linkage Runbook

## Purpose

This runbook links Phase 2 evaluation artifacts to Phase 3 normalized alerts without exposing labels to the runtime AI path.

The linkage layer answers questions like:

- Which Phase 3 `alert_uid` corresponds to a Phase 2 `ALERT-*` label ID?
- Which normalized alerts belong to a casebook case?
- Which raw evidence line supports a casebook conclusion?
- Which alerts are candidates for duplicate suppression or fatigue analysis?

## Inputs

- `ground_truth_labels.csv`
- `casebook.csv`
- `casebook_detailed.jsonl`
- `alert_fatigue_baseline.csv`
- `normalized_alerts_v1.jsonl`

## Outputs

Generated under:

```text
06_data/phase_03_alert_normalization_storage/evaluation_linkage/
```

Files:

- `ground_truth_to_normalized_crosswalk.csv`
- `label_normalized_alert_candidates.csv`
- `casebook_to_normalized_alerts.csv`
- `case_linkage_summary.csv`
- `investigation_flow_index.csv`
- `fatigue_case_linkage.csv`
- `linkage_manifest.json`

## Run

From the repo root:

```powershell
py scripts\phase_03_alert_normalization_storage\link_phase2_eval_to_normalized.py `
  --ground-truth "data\phase_02_scenario_dataset\Metadata\sprint_09_casebook\ground_truth_labels.csv" `
  --casebook "data\phase_02_scenario_dataset\Metadata\sprint_09_casebook\casebook.csv" `
  --casebook-detailed "data\phase_02_scenario_dataset\Metadata\sprint_09_casebook\casebook_detailed.jsonl" `
  --fatigue "data\phase_02_scenario_dataset\Metadata\sprint_09_casebook\alert_fatigue_baseline.csv" `
  --normalized "..\..\06_data\phase_03_alert_normalization_storage\normalized\normalized_alerts_v1.jsonl" `
  --output-dir "..\..\06_data\phase_03_alert_normalization_storage\evaluation_linkage"
```

## Matching Strategy

Labels are matched to normalized alerts using:

```text
agent_name + timestamp/source_time_raw + rule_id + rule_description
```

Casebook cases are matched to labels through `run_id`, then expanded to normalized alert candidates.

If a case has no direct label-expanded normalized links, the linker also uses a case-window context match:

```text
case agent_name + case start/end timestamps + case rule_ids
```

Those rows are marked with `link_source = case_window_match`.

## Duplicate Behavior

Some labels match more than one normalized candidate because Wazuh exports may contain alerts with the same visible timestamp, agent, rule ID, and description.

The linkage package preserves all candidates and marks the lowest raw line number as the primary candidate for convenience.

Rows linked through ground truth are marked with:

```text
link_source = ground_truth_label_match
```

Rows linked through the case time window are marked with:

```text
link_source = case_window_match
```

## Boundary Rule

These linkage outputs are evaluation/investigation artifacts. They can be used by evaluation scripts and analyst investigation notebooks, but they must not be used by runtime AI endpoints.
