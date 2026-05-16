# Phase 3 Final Report: Alert Normalization, Evidence Vault, and Storage

## 1. Executive Summary

Phase 3 built the SafeAgentSOC telemetry foundation: a reproducible, evidence-linked, SIEM-agnostic backend layer that converts Phase 2 Wazuh alert exports into canonical normalized alerts while keeping evaluation labels and casebook answers outside the runtime path.

The completed layer supports:

- Raw Wazuh JSONL parsing
- Canonical normalized alerts
- Stable alert UIDs
- Raw evidence lineage
- Evidence Vault v0 files
- Runtime/evaluation schema separation
- PostgreSQL runtime and evaluation schemas
- Historical ingestion CLI
- FastAPI runtime query layer
- QA metrics and leakage audit
- Evaluation linkage between 800 labels, 50 cases, normalized alerts, evidence IDs, and raw line numbers

Phase 3 intentionally does not build live ingestion, LLM reasoning, case compression, context enrichment, graph validation, or GRC response logic. Those belong to later phases.

## 2. Phase 3 Scope

Phase 3 focused on historical-first, live-compatible telemetry infrastructure.

Input:

- 6,893 raw Wazuh alerts
- 800 QA-validated gold-label rows
- 50 investigation cases
- Casebook, fatigue baseline, scenario run metadata, and Phase 2 QA artifacts

Output:

- Canonical runtime alert objects
- Evidence lineage artifacts
- PostgreSQL schemas
- Runtime query API
- QA and leakage proof
- Evaluation-only linkage files
- Phase 4 context enrichment handoff

## 3. Historical-First, Live-Compatible Architecture

Current architecture:

```text
Phase 2 raw Wazuh JSONL
-> Wazuh JSONL parser
-> Evidence lineage generator
-> Normalization engine
-> Runtime files
-> PostgreSQL runtime schema
-> FastAPI runtime API
-> QA and leakage audit
```

Future live architecture:

```text
Live Wazuh alerts
-> same parser interface
-> same normalizer
-> same database schema
-> same runtime API
```

Live ingestion remains deferred. The adapter and normalizer boundaries were designed so live ingestion can reuse the same contract later.

## 4. Runtime vs Evaluation Separation

Runtime artifacts may contain:

- Raw alert fields
- Normalized alert fields
- Evidence IDs
- Raw hashes
- Raw line references
- Rule and MITRE mappings
- Normalization warnings/errors

Runtime artifacts must not contain:

- Ground-truth labels
- Expected conclusions
- Casebook answers
- Event roles
- True-positive or false-positive labels

Evaluation artifacts may contain:

- Ground-truth labels
- Casebook cases
- Expected analyst conclusions
- Alert-to-case links
- Fatigue baseline data
- Evaluation linkage outputs

The runtime/evaluation boundary is enforced through separate files, separate schemas, guarded API routes, and leakage tests.

## 5. Canonical Schema

The canonical runtime object is `normalized_alert`.

Core groups:

- Identity: `alert_uid`, schema version
- Source: source system, adapter, source type
- Time: event, ingest, normalization timestamps
- Host: hostname, agent ID, platform
- Rule and decoder metadata
- Event taxonomy: category, action, outcome
- Severity: SIEM-independent severity bucket and score
- MITRE: technique IDs, names, tactics
- Entities: user, process, network, file
- Scenario context placeholders
- Evidence reference
- Normalization status

The schema is intentionally SIEM-agnostic. Wazuh is the first adapter, not the product boundary.

## 6. Wazuh Adapter

The Wazuh adapter reads JSONL alerts, validates JSON objects, preserves raw lines, and supports nested field flattening for empirical profiling.

Parser result:

| Metric | Value |
|---|---:|
| Total lines | 6,893 |
| Parsed alerts | 6,893 |
| Invalid JSON lines | 0 |
| Blank lines | 0 |

Top agents:

| Agent | Alerts |
|---|---:|
| `safesoc-lnx-01` | 5,337 |
| `safesoc-win-01` | 1,038 |
| `safesoc-wazuh-01` | 513 |

Top decoders:

| Decoder | Alerts |
|---|---:|
| `json` | 2,842 |
| `dpkg-decoder` | 1,155 |
| `sca` | 1,099 |
| `windows_eventchannel` | 488 |
| `syscheck_integrity_changed` | 481 |

## 7. Raw Field Profiling

Sprint 3 generated field, missing-field, type, agent, rule, decoder, MITRE, timestamp, and noisy-rule profiles.

Top rules by alert count:

| Rule ID | Description | Alerts |
|---|---|---:|
| `2904` | Dpkg half configured | 688 |
| `550` | Integrity checksum changed | 481 |
| `2902` | New dpkg package installed | 438 |
| `5501` | PAM login session opened | 150 |
| `5502` | PAM login session closed | 140 |

MITRE coverage preserved where present. 1,438 of 6,893 normalized alerts include MITRE IDs or tactics.

## 8. UID and Evidence Lineage Model

Every parsed alert receives:

- `alert_uid`
- `evidence_id`
- `raw_alert_sha256`
- `raw_file_sha256`
- `raw_file_name`
- `raw_line_number`
- `source_system`
- `source_adapter`
- `ingestion_batch_id`
- `ingested_at_utc`
- UID strategy version

Lineage results:

| Metric | Value |
|---|---:|
| Unique alert UIDs | 6,893 |
| Natural duplicate groups | 126 |
| Alerts disambiguated by raw line | 253 |
| Raw file SHA256 | `44ef71b93bbc663fb35db71f4ff129833bc83d244b8a133e83753fee7fe0c0bf` |

Duplicate behavior is explicit: if stable natural evidence fields collide, raw line number is used as a deterministic disambiguator.

## 9. Evidence Vault v0

Evidence Vault v0 consists of:

- `raw_alert_lineage.csv`
- `evidence_reference.csv`
- `normalization_batch_manifest.yaml`
- Evidence references embedded in normalized alerts

This allows every normalized alert and future AI decision to trace back to raw alert evidence.

## 10. Database Design

The database uses two logical schemas:

- `safeagentsoc_runtime`
- `safeagentsoc_eval`

Runtime tables:

- `raw_alerts`
- `normalized_alerts`
- `evidence_references`
- `normalization_batches`
- `normalization_warnings`
- `normalization_errors`
- `mitre_techniques`
- `rule_reference`

Evaluation tables:

- `ground_truth_labels`
- `casebook_cases`
- `alert_case_links_gold`
- `scenario_run_log`
- `detection_gap_register`
- `alert_fatigue_baseline`
- `evaluation_scores`

Runtime views and repositories reject evaluation-only query terms.

## 11. Ingestion Pipeline

Sprint 7 created a repeatable historical ingestion CLI and database snapshot utilities.

Ingestion result:

| Metric | Value |
|---|---:|
| Parsed alerts | 6,893 |
| Invalid JSON lines | 0 |
| Lineage rows | 6,893 |
| Raw alerts inserted | 6,893 |
| Evidence references inserted | 6,893 |
| Normalized alerts inserted | 6,893 |
| Normalization warnings inserted | 6,185 |
| Normalization errors inserted | 0 |
| Rule reference upserts | 97 |
| MITRE technique upserts | 31 |

Snapshot utilities allow database backup and restore at milestone points.

## 12. API Layer

Sprint 8 created a FastAPI runtime query layer.

Runtime endpoints:

- `GET /health`
- `GET /alerts`
- `GET /alerts/{alert_uid}`
- `GET /evidence/{evidence_id}`
- `GET /rules/{rule_id}`
- `GET /mitre/{technique_id}`
- `GET /metrics/normalization`
- `GET /metrics/runtime-summary`

Evaluation endpoints are separate and disabled by default.

## 13. QA Metrics

Sprint 9 generated QA metrics:

| Metric | Result |
|---|---:|
| Parse success rate | 100.00% |
| Normalization success rate | 100.00% |
| Required field completeness | 100.00% |
| Timestamp normalization rate | 100.00% |
| Raw lineage coverage | 100.00% |
| MITRE preservation rate | 20.86% |
| Runtime ground-truth exposure count | 0 |
| Normalization warnings | 6,185 |
| Normalization errors | 0 |

Warnings are expected where Wazuh alerts lack MITRE metadata, agent IP, or confident taxonomy mappings.

## 14. Leakage Audit

The leakage audit scanned:

- Normalized runtime JSONL
- Runtime SQL schema
- Runtime SQL views
- Runtime API route files

Result:

| Check | Status | Exposure Count |
|---|---|---:|
| Normalized runtime JSONL | pass | 0 |
| Runtime schema | pass | 0 |
| Runtime views | pass | 0 |
| Runtime alerts API | pass | 0 |
| Runtime evidence API | pass | 0 |
| Runtime metrics API | pass | 0 |

Runtime does not expose hidden ground truth.

## 15. Evaluation Linkage and Query Cookbook Status

Sprint 10 was intentionally skipped by user request. Full query-output generation under `query_results/` is therefore deferred.

However, Phase 3 now includes an evaluation linkage package that provides a stronger immediate investigation flow:

| Linkage Item | Count |
|---|---:|
| Ground-truth labels | 800 |
| Matched labels | 800 |
| Unmatched labels | 0 |
| Ambiguous labels | 232 |
| Casebook cases | 50 |
| Matched cases | 50 |
| Unmatched cases | 0 |
| Label-to-normalized candidate rows | 1,140 |
| Investigation flow rows | 3,039 |

The linkage layer connects:

```text
Phase 2 ALERT-* ID
-> Phase 3 alert_uid
-> evidence_id
-> raw_alerts_full.jsonl line number
-> case_id
-> analyst expected conclusion
```

This is evaluation/investigation-only and must not be used by runtime AI endpoints.

## 16. Limitations

- Sprint 10 query-output generation was skipped.
- Live ingestion is not implemented.
- Context enrichment is not implemented.
- Asset criticality, network zone, identity risk, and business service context are placeholders for Phase 4.
- Some labels have multiple normalized candidates because Wazuh alerts can share visible timestamp, agent, rule ID, and description.
- MITRE coverage depends on Wazuh rule metadata and is not inferred beyond preserved source mappings.

## 17. Phase 4 Handoff

Phase 4 should enrich normalized alerts with:

- Asset inventory
- Business criticality
- Network zone
- User and identity context
- Endpoint role
- Ownership and service mapping
- Policy relevance
- Case-building context

The Phase 3 foundation is ready to support those additions because alerts now have stable UIDs, normalized fields, evidence references, runtime database storage, and leakage-safe evaluation linkage.

## Final Status

Phase 3 produced a reproducible, evidence-linked SOC telemetry normalization and storage layer. It transforms raw Wazuh exports into canonical, queryable security objects while preserving lineage, separating runtime data from hidden ground truth, and preparing SafeAgentSOC for context enrichment, case building, AI reasoning, graph validation, and governance-aware response.

