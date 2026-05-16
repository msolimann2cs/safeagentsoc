# Sprint 1 Report: Canonical Alert Schema and SIEM Adapter Contract

## Sprint Goal

Design a canonical alert schema and SIEM adapter contract that allow SafeAgentSOC to normalize Wazuh alerts into evidence-linked runtime objects while preserving strict separation from evaluation-only ground truth.

## Why This Sprint Matters

SafeAgentSOC should not be a Wazuh-only parser.

The internal pipeline must be able to support future SIEM/XDR sources such as Splunk, Sentinel, Elastic, Defender, CrowdStrike, and Google SecOps.

The schema must also support Phase 2 dataset realities:

- 6,893 raw Wazuh alerts
- 800 QA-validated gold-label rows
- 50 investigation cases
- manual, Atomic Red Team, Caldera, benign, noisy, and simulated-only execution modes
- unlabeled background telemetry
- partial or missing Caldera metadata

## Completed Work

### Schemas Created

- normalized_alert.schema.json
- raw_alert_reference.schema.json
- evidence_reference.schema.json
- normalization_warning.schema.json
- normalization_error.schema.json
- siem_adapter_output.schema.json
- runtime_case_reference.schema.json
- evaluation_label_reference.schema.json

### Documentation Created

- normalized_alert_schema.md
- siem_adapter_contract.md
- runtime_evaluation_boundary.md
- event_taxonomy_v1.md
- wazuh_to_canonical_mapping_v1.md
- ocsf_ecs_alignment_notes.md
- schema_decision_record_sprint_01.md

### Validation Created

- validate_schema_package.py
- test_schema_package.py

## Key Design Decisions

### 1. Canonical Runtime Object

SafeAgentSOC uses `normalized_alert` as the internal runtime alert format.

### 2. Wazuh Is an Adapter

Wazuh is the first input adapter, not the product boundary.

### 3. Evidence Is Mandatory

Every normalized alert must link to raw evidence through:

- evidence_id
- raw_alert_sha256
- raw_file_sha256
- raw_file_name
- raw_line_number
- ingestion_batch_id

### 4. Runtime and Evaluation Are Separate

Ground-truth labels, casebook answers, expected conclusions, and gold case assignments are excluded from runtime alerts.

### 5. Evaluation Labels Have Their Own Schema

Evaluation labels are modeled separately through `evaluation_label_reference.schema.json`.

## Runtime-Safe Fields

Runtime alerts may include:

- alert_uid
- source metadata
- timestamp
- host
- rule
- decoder
- event category/action/outcome
- severity
- MITRE mapping
- extracted entities
- scenario/campaign/run references
- benchmark_link_available
- evidence references
- normalization warnings/errors

## Runtime-Forbidden Fields

Runtime alerts must not include:

- true positive label
- false positive label
- expected conclusion
- casebook answer
- gold case assignment
- event_role
- evaluation confidence label

## Sprint 1 Done Criteria

- [x] Canonical normalized alert schema exists
- [x] Raw alert reference schema exists
- [x] Evidence reference schema exists
- [x] Warning and error schemas exist
- [x] SIEM adapter output contract exists
- [x] Runtime case reference schema exists
- [x] Evaluation label schema exists separately
- [x] Runtime/evaluation boundary documented
- [x] Event taxonomy documented
- [x] Wazuh-to-canonical mapping documented
- [x] OCSF/ECS alignment notes documented
- [x] Schema validation script exists
- [x] Schema tests exist

## Sprint 1 Result

Sprint 1 produced a research-grade schema and adapter contract package. The project is now ready for Sprint 3, where the Wazuh JSONL parser and field profiler will test the schema against the real 6,893-alert Phase 2 dataset.
