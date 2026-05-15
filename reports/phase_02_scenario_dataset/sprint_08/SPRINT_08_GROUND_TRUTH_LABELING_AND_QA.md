# Sprint 8: Ground-Truth Labeling and Dataset QA

## Goal

Create a high-quality ground-truth label dataset from the Sprint 7 raw Wazuh export and correlated run windows.

## Inputs

| Input | Path |
|---|---|
| Full raw alerts | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/raw_alerts_full.jsonl` |
| Per-run correlated alerts | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/per_run` |
| Frozen run log | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/scenario_run_log_frozen.csv` |
| Normalized run log | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/scenario_run_log_normalized.csv` |

## Outputs

| Output | Path |
|---|---|
| Ground-truth labels | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/ground_truth_labels.csv` |
| Draft labels | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/ground_truth_labels_draft.csv` |
| Reviewed labels | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/ground_truth_labels_reviewed.csv` |
| Alert UID map | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/alert_uid_map.csv` |
| Label completeness metrics | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/label_completeness_metrics.csv` |
| MITRE coverage matrix | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/mitre_coverage_matrix.csv` |
| Endpoint coverage matrix | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/endpoint_coverage_matrix.csv` |
| Execution-mode comparison matrix | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/execution_mode_comparison_matrix.csv` |
| Dataset QA report | `06_data/phase_02_scenario_dataset/sprint_08_ground_truth/dataset_qa_report.md` |

## Labeling Method

Labels were generated using:

1. Stable alert UIDs based on Wazuh alert fields.
2. Sprint 7 per-run timestamp correlation.
3. RUN_ID marker evidence.
4. Scenario and campaign metadata.
5. ATT&CK mapping from scenario design and Wazuh MITRE fields.
6. Conservative confidence scoring for timestamp-derived labels.

Python is not installed on the host used for this sprint, so the Sprint 8 processing was implemented and executed with Node while Python compatibility wrappers were created under `scripts/phase_02_scenario_dataset/sprint_08`.

## Label Taxonomy

Event roles:

- trigger
- supporting
- duplicate
- noise
- unrelated

Labels:

- benign
- noise
- ambiguous_noise
- attack_like
- attack_like_failed
- simulated_only
- unrelated_background

## QA Summary

| Metric | Value |
|---|---:|
| Total labeled rows | 800 |
| Unique alert UIDs | 631 |
| Duplicate alert UID groups | 121 |
| Draft correlated labels | 595 |
| Background sample labels | 205 |
| Low-confidence rows after cleanup | 0 |

## Label Distribution

| Label | Count |
|---|---:|
| attack_like | 491 |
| unrelated_background | 247 |
| benign | 48 |
| ambiguous_noise | 14 |

## Event Role Distribution

| Event Role | Count |
|---|---:|
| supporting | 289 |
| unrelated | 247 |
| duplicate | 214 |
| trigger | 45 |
| noise | 5 |

## Endpoint Distribution

| Endpoint | Count |
|---|---:|
| safesoc-lnx-01 | 559 |
| safesoc-win-01 | 182 |
| safesoc-wazuh-01 | 59 |

## Execution Mode Distribution

| Execution Mode | Count |
|---|---:|
| manual | 339 |
| background_sample | 205 |
| caldera | 176 |
| atomic_red_team | 80 |

## Cleanup Pass

The first Sprint 8 output was treated as a reviewed draft, then a cleanup pass was completed before finalizing the label set.

Cleanup actions:

- Recovered Caldera operation names, adversary/profile names, adversary IDs, and operation-level ability ID sets from Caldera report JSON evidence.
- Replaced all placeholder Caldera UI values in the final labels.
- Removed all final-label note wording that said draft or manual review recommended.
- Spot-checked the 42 low-confidence rows as unrelated/background rows and retained them with medium confidence.
- Reduced inflated trigger labels from 438 to 45 by limiting trigger roles to primary proof and moving repeated telemetry to supporting or duplicate.
- Added duplicate UID analysis.

Duplicate alert UIDs represent repeated correlation references across overlapping run/campaign windows, not necessarily duplicate raw alerts.

## Validation

Schema validation passed for `800` labeled rows.

```text
SCHEMA VALIDATION PASSED
Rows validated: 800
No Draft wording remains.
No placeholder Caldera UI values remain in the final labels.

Some Caldera UI operation metadata was not recoverable after execution and is marked as `not_recovered` in run-log metadata. Run-level correlation was preserved using timestamp windows, campaign IDs, agent names, and Wazuh alert evidence.
```

## Limitations

- Campaign windows may overlap scenario windows.
- Some labels are derived from timestamp correlation and use conservative confidence scoring.
- Caldera ability IDs are operation-level ability sets from report JSON, not per-alert ability attribution.
- Background samples were included to support unrelated/noise classification.
- Sprint 9 will convert alert-level labels into case-level investigation records and alert-fatigue metrics.

## Completion Status

Sprint 8 is complete. A raw 6,893-alert Wazuh dataset was reduced into a QA-validated 800-row ground-truth label set with stable alert identifiers, scenario/campaign correlation, event-role annotations, MITRE mappings, endpoint coverage, execution-mode coverage, and confidence scoring.
