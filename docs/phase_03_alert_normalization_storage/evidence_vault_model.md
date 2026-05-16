# Evidence Vault Model v0

## Purpose

Evidence Vault v0 records enough lineage to prove which raw alert supports each runtime object.

## Core Files

```text
06_data/phase_03_alert_normalization_storage/lineage/raw_alert_lineage.csv
06_data/phase_03_alert_normalization_storage/lineage/evidence_reference.csv
06_data/phase_03_alert_normalization_storage/batches/phase3_v1/normalization_batch_manifest.yaml
```

## Raw Alert Lineage Fields

| Field | Purpose |
|---|---|
| `alert_uid` | Stable SafeAgentSOC alert identifier |
| `evidence_id` | Stable evidence reference identifier |
| `raw_alert_sha256` | SHA256 of the raw JSONL line |
| `raw_file_sha256` | SHA256 of the source JSONL file |
| `raw_file_name` | Source file name |
| `raw_line_number` | One-based line number in the raw JSONL file |
| `source_system` | Source platform, currently Wazuh |
| `source_adapter` | Adapter name, currently `wazuh_jsonl_v1` |
| `ingestion_batch_id` | Batch identifier, currently `phase3_v1` |
| `ingested_at_utc` | Time lineage was generated |
| `normalizer_version` | Normalizer version or placeholder before Sprint 5 |
| `uid_strategy_version` | UID strategy version |
| `natural_alert_fingerprint` | Hash before duplicate line disambiguation |
| `natural_fingerprint_count` | Number of alerts sharing the natural fingerprint |
| `uid_disambiguation` | `none` or `raw_line_number` |

## Evidence Reference Fields

| Field | Purpose |
|---|---|
| `evidence_id` | Evidence reference identifier |
| `alert_uid` | Linked alert UID |
| `raw_alert_sha256` | Raw alert line hash |
| `raw_file_sha256` | Raw file hash |
| `raw_file_name` | Raw source file |
| `raw_line_number` | Raw source line |
| `ingestion_batch_id` | Batch identifier |
| `source_system` | Source system |
| `source_adapter` | Source adapter |
| `evidence_confidence` | Confidence in evidence link |

## Runtime/Evaluation Boundary

Evidence Vault v0 stores runtime-safe lineage only. It does not store ground-truth labels, casebook answers, expected conclusions, or gold alert-to-case links.

Evaluation joins may use `alert_uid`, but those joins belong to evaluation scripts only.
