# Phase 4 Context Enrichment Handoff

## Purpose

Phase 4 should enrich the Phase 3 normalized alert layer with business, asset, identity, network, and policy context.

Phase 3 answers:

```text
What happened, where did it come from, and what evidence proves it?
```

Phase 4 should answer:

```text
How important is this alert in organizational context, and what should an analyst prioritize?
```

## Available Phase 3 Runtime Fields

Normalized alerts provide:

- `alert_uid`
- `evidence_id`
- `source_system`
- `source_adapter`
- `event_time_utc`
- `agent_name`
- `hostname`
- `agent_ip`
- `platform`
- `rule_id`
- `rule_level`
- `rule_description`
- `decoder_name`
- `event_category`
- `event_action`
- `event_outcome`
- `severity_normalized`
- `mitre_technique_ids`
- `mitre_tactics`
- user entity fields
- process entity fields
- network entity fields
- file entity fields
- raw evidence references
- normalization warning/error status

## Asset Context Needed

Phase 4 should add:

- `asset_id`
- `asset_owner`
- `business_unit`
- `business_service`
- `asset_criticality`
- `environment`
- `asset_role`
- `exposure_level`
- `internet_facing`
- `crown_jewel`
- `data_classification`

## User and Identity Context Needed

Phase 4 should add:

- `identity_id`
- `user_department`
- `user_role`
- `privileged_account`
- `service_account`
- `identity_risk_score`
- `mfa_status`
- `recent_identity_alerts`
- `account_age_days`
- `manager_or_owner`

## Network Context Needed

Phase 4 should add:

- `network_zone`
- `subnet`
- `site`
- `cloud_region`
- `vpc_or_vlan`
- `ingress_egress_direction`
- `trusted_boundary_crossing`
- `known_admin_network`
- `known_scanner_network`

## Business Criticality Needed

Phase 4 should create a clear criticality model:

- `low`
- `medium`
- `high`
- `critical`

Recommended drivers:

- Business service importance
- Data sensitivity
- Exposure level
- Identity privilege level
- Known exploitation risk
- Regulatory relevance

## Policy and Governance Context Needed

Later GRC-aware response requires:

- policy catalog IDs
- control family
- evidence requirements
- escalation rules
- response constraints
- approval requirements
- audit logging requirements

## Context Graph Requirements

Phase 4 should prepare for a graph model with nodes:

- Alert
- Evidence
- Host
- User
- Process
- File
- IP address
- MITRE technique
- Rule
- Case
- Asset
- Business service
- Policy/control

Suggested relationships:

- `ALERT_HAS_EVIDENCE`
- `ALERT_ON_HOST`
- `ALERT_INVOLVES_USER`
- `ALERT_INVOLVES_PROCESS`
- `ALERT_MAPS_TO_TECHNIQUE`
- `HOST_SUPPORTS_SERVICE`
- `USER_OWNS_ASSET`
- `CASE_CONTAINS_ALERT`
- `POLICY_RELEVANT_TO_ALERT`

## Runtime/Evaluation Rule

Phase 4 runtime enrichment must not consume:

- ground-truth labels
- casebook expected conclusions
- event roles
- answer-key linkage files

Evaluation scripts may compare enriched runtime output against evaluation artifacts, but runtime services must remain label-free.

## Recommended Phase 4 First Tasks

1. Create asset inventory schema and seed sample SafeAgentSOC lab assets.
2. Create identity context schema for lab users and service accounts.
3. Create network zone mapping for lab IP ranges.
4. Add enrichment module that joins normalized alerts to asset/user/network context.
5. Generate enrichment QA metrics.
6. Document context confidence and missing-context behavior.

