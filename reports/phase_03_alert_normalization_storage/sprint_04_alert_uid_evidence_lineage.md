# Sprint 4 Report: Alert UID, Evidence Lineage, and Evidence Vault v0

## Sprint Goal

Create stable alert identifiers and trace every parsed raw alert back to raw evidence.

## Why This Sprint Matters

Sprint 4 makes SafeAgentSOC auditable. Later normalization, storage, API, case building, and AI reasoning can point back to the exact raw alert line and file hash that supported a decision.

## Deliverables

- `src/safeagentsoc/evidence/uid.py`
- `src/safeagentsoc/evidence/lineage.py`
- `scripts/phase_03_alert_normalization_storage/generate_evidence_lineage.py`
- `docs/phase_03_alert_normalization_storage/alert_uid_strategy.md`
- `docs/phase_03_alert_normalization_storage/evidence_vault_model.md`
- `06_data/phase_03_alert_normalization_storage/lineage/raw_alert_lineage.csv`
- `06_data/phase_03_alert_normalization_storage/lineage/evidence_reference.csv`
- `06_data/phase_03_alert_normalization_storage/batches/phase3_v1/normalization_batch_manifest.yaml`

## UID Strategy

SafeAgentSOC uses `alert_uid_v1`, a deterministic SHA256-based strategy over runtime-safe fields:

- timestamp
- agent name
- rule ID
- decoder name
- location
- SHA256 of `full_log`, when present

If multiple alerts share the same natural fingerprint, the final UID is disambiguated with the raw JSONL line number.

## Evidence Lineage

Every parsed alert receives:

- `alert_uid`
- `raw_alert_sha256`
- `raw_file_sha256`
- `raw_file_name`
- `raw_line_number`
- `source_system`
- `source_adapter`
- `ingestion_batch_id`
- `ingested_at_utc`
- `normalizer_version`
- `evidence_id`

## Run Results

| Metric | Result |
|---|---:|
| Total JSONL lines | 6,893 |
| Parsed alerts | 6,893 |
| Invalid JSON lines | 0 |
| Blank lines | 0 |
| Unique alert UIDs | 6,893 |
| Raw lineage rows | 6,893 |
| Evidence reference rows | 6,893 |
| Natural duplicate fingerprint groups | 126 |
| Alerts disambiguated by raw line number | 253 |

## Batch Manifest

The `phase3_v1` batch manifest records:

- source system: Wazuh
- source adapter: `wazuh_jsonl_v1`
- normalizer version: `not_normalized_yet`
- UID strategy version: `alert_uid_v1`
- raw file SHA256: `44ef71b93bbc663fb35db71f4ff129833bc83d244b8a133e83753fee7fe0c0bf`
- parsed alert count: 6,893
- unique alert UID count: 6,893

## Runtime/Evaluation Boundary

Sprint 4 does not use labels, casebook answers, expected conclusions, or evaluation-only data.

## Sprint 4 Done Criteria

- [x] Every raw alert gets `alert_uid`
- [x] Every raw alert gets `raw_alert_sha256`
- [x] Every raw alert has `raw_line_number`
- [x] Batch manifest exists
- [x] UID duplicate behavior is documented
- [x] Evidence Vault v0 is documented

## Notes

Lineage generation used the same 6,893-alert raw Wazuh JSONL export profiled in Sprint 3.
