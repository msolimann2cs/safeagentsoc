# Sprint 0 Report: Phase 3 Setup, Scope, and Data Governance

## Sprint Goal

Set up Phase 3 as a controlled engineering and research phase with clear folder structure, data boundaries, runtime/evaluation separation, and leakage prevention.

## Completed Work

- Created Phase 3 Git branch.
- Created Phase 3 folder structure.
- Defined public/private artifact rules.
- Created data governance and leakage policy.
- Created input artifact contracts.
- Created draft input manifest.
- Updated `.gitignore` to protect private artifacts.

## Key Design Decisions

### Historical-first, live-compatible later

Phase 3 uses frozen Phase 2 Wazuh JSONL exports as input. Live ingestion is deferred.

### Runtime/evaluation separation

Runtime data and evaluation-only answer-key data are separated from the beginning.

### Wazuh as adapter

Wazuh is treated as the first SIEM adapter, not the permanent core of the product.

## Private Artifacts

The following must not be committed:

- raw_alerts_full.jsonl
- ground_truth_labels.csv
- casebook.csv
- scenario_run_log_frozen.csv
- detection_gap_register.csv
- alert_fatigue_baseline.csv
- 06_data/
- 07_evidence/

## Sprint 0 Done Criteria

- [x] Phase 3 branch exists
- [x] Folder structure exists
- [x] All known Phase 2 inputs are listed
- [x] Runtime vs evaluation separation is documented
- [x] `.gitignore` protects private artifacts
- [x] Sprint 0 report exists

## Sprint 0 Result

Sprint 0 successfully prepared the Phase 3 workspace. The project is now ready for Sprint 1: Canonical Alert Schema and SIEM Adapter.
