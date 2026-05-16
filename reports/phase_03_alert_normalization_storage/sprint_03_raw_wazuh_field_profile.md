# Sprint 3 Report: Raw Wazuh Parser and Field Profiler

## Sprint Goal

Build a Wazuh JSONL parser and empirical field profiler for the Phase 2 raw alert dataset before normalization.

## Why This Sprint Matters

Sprint 3 prevents the normalization engine from being based on assumptions. The profiler records what fields actually appear in the Wazuh export, how often they appear, which fields are missing, which types are observed, and which agents, rules, decoders, MITRE mappings, and timestamps dominate the dataset.

## Inputs

- Source system: Wazuh
- Input format: JSONL
- Target dataset size: 6,893 raw alerts
- Profiled input: `05_code/safeagentsoc/data/phase_02_scenario_dataset/Metadata/sprint_08_ground_truth/raw_alerts_full.jsonl`
- Runtime/evaluation boundary: no ground-truth labels, casebook answers, expected conclusions, or evaluation-only tables are used by this profiler

## Run Results

| Metric | Result |
|---|---:|
| Total JSONL lines | 6,893 |
| Parsed alerts | 6,893 |
| Invalid JSON lines | 0 |
| Blank lines | 0 |
| Unique flattened fields | 359 |
| Valid timestamps | 6,893 |
| Invalid timestamps | 0 |

## Timestamp Range

| Field | Value |
|---|---|
| Earliest event time UTC | 2026-05-13T19:00:45.141000+00:00 |
| Latest event time UTC | 2026-05-15T05:31:16.616000+00:00 |

## Initial Noisy Rule Candidates

| Rule ID | Level | Description | Alerts | Percent |
|---|---:|---|---:|---:|
| 2904 | 7 | Dpkg (Debian Package) half configured. | 688 | 9.98 |
| 550 | 7 | Integrity checksum changed. | 481 | 6.98 |
| 2902 | 7 | New dpkg (Debian Package) installed. | 438 | 6.35 |
| 5501 | 3 | PAM: Login session opened. | 150 | 2.18 |
| 5502 | 3 | PAM: Login session closed. | 140 | 2.03 |

## Verification

The profiler was executed with the bundled Python runtime. Parser/profiler function checks passed, and the Sprint 3 Python files compile successfully.

## Deliverables

- `src/safeagentsoc/adapters/wazuh/jsonl_parser.py`
- `src/safeagentsoc/ingestion/field_profiler.py`
- `scripts/phase_03_alert_normalization_storage/run_wazuh_field_profile.py`
- `06_data/phase_03_alert_normalization_storage/profiles/field_frequency_report.csv`
- `06_data/phase_03_alert_normalization_storage/profiles/missing_field_report.csv`
- `06_data/phase_03_alert_normalization_storage/profiles/field_type_profile.csv`
- `06_data/phase_03_alert_normalization_storage/profiles/agent_distribution.csv`
- `06_data/phase_03_alert_normalization_storage/profiles/rule_distribution.csv`
- `06_data/phase_03_alert_normalization_storage/profiles/decoder_distribution.csv`
- `06_data/phase_03_alert_normalization_storage/profiles/mitre_field_profile.csv`
- `06_data/phase_03_alert_normalization_storage/profiles/timestamp_profile.csv`
- `06_data/phase_03_alert_normalization_storage/profiles/top_noisy_rules.csv`

## Parser Behavior

The parser:

- reads Wazuh JSONL line by line
- preserves raw line number
- counts blank lines
- counts invalid JSON lines
- rejects non-object JSON values
- keeps parsing after invalid lines

## Profiler Behavior

The profiler generates:

- field frequency counts
- missing required field counts
- observed field type counts
- agent distribution
- rule distribution
- decoder distribution
- MITRE ID and tactic coverage
- timestamp validity and range
- top noisy rule candidates

## Sprint 3 Done Criteria

- [x] Wazuh JSONL parser exists
- [x] All 6,893 raw alerts parsed
- [x] Invalid JSON lines are counted
- [x] Invalid JSON line count documented
- [x] Nested field flattener exists
- [x] Field frequency profiler exists
- [x] Missing field profiler exists
- [x] Type profiler exists
- [x] Rule distribution profiler exists
- [x] Agent distribution profiler exists
- [x] Decoder distribution profiler exists
- [x] MITRE field profiler exists
- [x] Timestamp profiler exists
- [x] Top noisy rules identified
- [x] Profile report paths are defined
- [x] Field profile report exists

## Notes

The profiler is historical-first and live-compatible later. It does not build live ingestion and does not query evaluation-only files.
