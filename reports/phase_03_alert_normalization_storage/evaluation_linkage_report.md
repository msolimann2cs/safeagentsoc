# Evaluation Linkage Report

## Goal

Create an easy investigation flow between Phase 2 ground truth, casebook artifacts, fatigue baselines, Phase 3 normalized alerts, and raw evidence lineage.

## Created Linkage Files

- `ground_truth_to_normalized_crosswalk.csv`
- `label_normalized_alert_candidates.csv`
- `casebook_to_normalized_alerts.csv`
- `case_linkage_summary.csv`
- `investigation_flow_index.csv`
- `fatigue_case_linkage.csv`
- `linkage_manifest.json`

## How To Investigate

Start with `investigation_flow_index.csv`.

It gives a single analyst-friendly row shape containing:

- case ID
- run ID
- label ID
- Phase 2 `ALERT-*` ID
- Phase 3 normalized `alert_uid`
- evidence ID
- raw line number
- label and event role
- normalized event category/action/outcome
- MITRE technique IDs
- expected analyst conclusion

## Linkage Results

| Item | Count |
|---|---:|
| Ground-truth labels | 800 |
| Matched ground-truth labels | 800 |
| Unmatched ground-truth labels | 0 |
| Labels with multiple normalized candidates | 232 |
| Casebook cases | 50 |
| Matched casebook cases | 50 |
| Unmatched casebook cases | 0 |
| Label-to-normalized candidate rows | 1,140 |
| Case-to-normalized link rows | 3,039 |
| Investigation flow rows | 3,039 |

## Link Types

`ground_truth_label_match` means a normalized alert matched a Phase 2 label by agent, source timestamp, rule ID, and rule description.

`case_window_match` means a normalized alert matched a case by agent, case time window, and case rule IDs. This preserves useful case context even when the alert was not part of the gold-label answer key.

## Runtime Safety

This linkage package intentionally lives outside runtime normalized alerts. It connects to labels and casebook expected conclusions, so it belongs to evaluation and analyst investigation only.
