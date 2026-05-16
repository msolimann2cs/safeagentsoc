# Sprint 5 Report: Normalization Engine v1

## Sprint Goal

Convert raw Wazuh alerts into SafeAgentSOC canonical normalized alert objects without using evaluation-only labels or casebook data.

## Why This Sprint Matters

Sprint 5 is the first working SafeAgentSOC Core component. It turns raw Wazuh telemetry plus Sprint 4 evidence lineage into runtime-safe, queryable, evidence-linked normalized alert records.

## Deliverables

- `src/safeagentsoc/normalization/normalizer.py`
- `src/safeagentsoc/normalization/mappings.py`
- `src/safeagentsoc/normalization/severity.py`
- `src/safeagentsoc/normalization/event_taxonomy.py`
- `scripts/phase_03_alert_normalization_storage/run_normalization_engine.py`
- `tests/test_normalizer.py`
- `06_data/phase_03_alert_normalization_storage/normalized/normalized_alerts_v1.jsonl`
- `06_data/phase_03_alert_normalization_storage/normalized/normalization_warnings.csv`
- `06_data/phase_03_alert_normalization_storage/normalized/normalization_errors.csv`

## Transformations Implemented

- timestamp normalization
- agent and host extraction
- platform inference
- Wazuh rule extraction
- decoder extraction
- event category mapping
- event action mapping
- event outcome mapping
- severity normalization
- MITRE extraction
- user extraction
- process extraction
- IP extraction
- file/path extraction
- command-line extraction where available
- raw evidence reference linkage
- normalization warning generation

## Runtime/Evaluation Boundary

The normalizer consumes only:

- raw Wazuh JSONL alerts
- Sprint 4 runtime-safe lineage rows

The normalizer does not consume:

- `ground_truth_labels.csv`
- `casebook.csv`
- expected conclusions
- gold alert-to-case links
- evaluation-only labels

## Run Results

| Metric | Result |
|---|---:|
| Parsed alerts | 6,893 |
| Normalized records generated | 6,893 |
| Normalization error rows | 0 |
| Normalization warning rows | 6,185 |
| Records with evidence references | 6,893 |
| Records preserving MITRE IDs or tactics | 1,438 |
| Runtime forbidden-term exposure count | 0 |

## Normalization Status

| Status | Records |
|---|---:|
| success | 1,270 |
| partial | 5,623 |
| failed | 0 |

## Severity Distribution

| Severity | Records |
|---|---:|
| low | 2,952 |
| medium | 3,393 |
| high | 498 |
| critical | 50 |

## Event Category Distribution

| Category | Records |
|---|---:|
| monitoring_internal | 3,441 |
| system_activity | 1,179 |
| file_activity | 684 |
| authentication | 503 |
| process_execution | 319 |
| persistence | 178 |
| network_activity | 161 |
| privilege_activity | 159 |
| discovery | 155 |
| unknown | 98 |
| collection_or_staging | 16 |

## Warning Breakdown

| Warning Type | Rows |
|---|---:|
| missing_mitre | 5,455 |
| missing_field | 582 |
| unmapped_category | 98 |
| partial_metadata | 50 |

## Verification

- Normalizer focused tests passed with the bundled Python runtime.
- Sprint 5 Python files compile successfully.
- Sprint 1 schema package validation still passes.
- All 6,893 normalized JSONL records include the required top-level normalized alert fields.
- Private normalized outputs remain under top-level `06_data/`.

## Sprint 5 Done Criteria

- [x] Normalization engine exists
- [x] Severity normalization exists
- [x] Event taxonomy mapping exists
- [x] Wazuh mapping helpers exist
- [x] 6,893 normalized records generated
- [x] Normalization errors logged, not hidden
- [x] Normalized severity exists
- [x] Event category/action/outcome fields exist
- [x] MITRE fields preserved where available
- [x] Evidence refs are linked into normalized alerts
- [x] Runtime normalization does not use labels or casebook data

## Notes

The high `missing_mitre` warning count reflects Wazuh rule metadata availability in the raw export, not evaluation labels. The normalizer records those gaps explicitly for later QA.
