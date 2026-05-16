# Sprint 9 Report: QA, Testing, and Leakage Audit

## Sprint Goal

Prove that the Phase 3 telemetry layer is complete enough for later AI use, reproducible from runtime artifacts, and protected from evaluation answer-key leakage.

## Completed Work

- Added a reusable QA/leakage module: `safeagentsoc.evaluation.qa_metrics`.
- Added a Sprint 9 runner: `run_qa_leakage_audit.py`.
- Added required Sprint 9 tests for parser, UID, schema validation, database boundaries, API boundaries, normalization, and leakage scanning.
- Generated private QA artifacts under top-level `06_data`.

## QA Outputs

- `06_data/phase_03_alert_normalization_storage/qa/normalization_metrics.csv`
- `06_data/phase_03_alert_normalization_storage/qa/leakage_audit_report.csv`

## Metrics Captured

| Metric | Result | Status |
|---|---:|---|
| `parse_success_rate` | 100.00% | pass |
| `normalization_success_rate` | 100.00% | pass |
| `required_field_completeness` | 100.00% | pass |
| `timestamp_normalization_rate` | 100.00% | pass |
| `raw_lineage_coverage` | 100.00% | pass |
| `mitre_preservation_rate` | 20.86% | measured |
| `runtime_ground_truth_exposure_count` | 0 | pass |
| `label_linkage_rate` | not available | separate eval load required |
| `casebook_linkage_rate` | not available | separate eval load required |
| `normalization_warning_count` | 6,185 | measured |
| `normalization_error_count` | 0 | pass |

The MITRE preservation rate is a dataset coverage metric, not a failure. It means 1,438 of 6,893 Wazuh alerts carried MITRE IDs or tactics that could be preserved.

## Leakage Audit Scope

The leakage audit scans:

- normalized runtime JSONL output
- runtime PostgreSQL schema
- runtime PostgreSQL views
- runtime API route files

The runtime audit checks for answer-key terms such as:

- `ground_truth`
- `true_positive`
- `false_positive`
- `expected_conclusion`
- `gold_case`
- `casebook_answer`
- `event_role`
- `casebook`
- `answer_key`
- `safeagentsoc_eval`

## Runtime/Evaluation Boundary Result

Runtime artifacts remain label-free. Evaluation linkage metrics are intentionally marked `not_available` until evaluation-only loading is run separately.

## Reproduce

Run the Sprint 9 audit with:

```powershell
py scripts\phase_03_alert_normalization_storage\run_qa_leakage_audit.py
```

Run the Sprint 9 tests with:

```powershell
py -m pytest tests\test_parser.py tests\test_uid.py tests\test_normalizer.py tests\test_schema_validation.py tests\test_database.py tests\test_api.py tests\test_ground_truth_leakage.py
```

## Sprint 9 Done Criteria

- [x] JSONL parse tests exist
- [x] alert UID determinism tests exist
- [x] raw hash and evidence identity behavior is tested
- [x] schema validation tests exist
- [x] timestamp normalization metric is generated
- [x] severity mapping tests exist
- [x] event category mapping tests exist
- [x] MITRE preservation metric is generated
- [x] database boundary tests exist
- [x] API boundary tests exist
- [x] runtime/evaluation separation tests exist
- [x] ground-truth leakage tests exist
- [x] QA metrics CSV exists
- [x] leakage audit CSV exists

## Sprint 9 Result

Sprint 9 adds the verification layer SafeAgentSOC needs before analyst-facing query cookbooks and Phase 4 context enrichment. The project can now prove parse completeness, normalization completeness, raw lineage coverage, MITRE preservation, and absence of runtime answer-key exposure.
