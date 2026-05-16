# Phase 3 Overview: Alert Normalization, Evidence Vault, and Storage

## Purpose

Phase 3 builds the SafeAgentSOC backend foundation for canonical alerts, evidence lineage, runtime/evaluation separation, PostgreSQL storage, and future AI reasoning.

This phase converts Phase 2 Wazuh alert exports into normalized, queryable, evidence-linked security objects.

## Phase 3 Is Not

- A live ingestion system
- An AI reasoning system
- A case builder
- A dashboard phase
- A Splunk or Sentinel integration phase

## Phase 3 Is

- Historical-first alert normalization
- Wazuh JSONL parsing
- Canonical alert schema design
- Evidence lineage tracking
- Runtime/evaluation data separation
- PostgreSQL storage preparation
- FastAPI query foundation
- QA and leakage prevention

## Current Mode

```text
Phase 2 raw Wazuh JSONL
→ parser
→ normalizer
→ database
→ API
→ QA
Future Mode
Live Wazuh alerts
→ same parser interface
→ same normalizer
→ same database
→ same API
```

Live ingestion is intentionally deferred.

Core Design Rules
Historical-first, live-compatible later.
Runtime and evaluation data must be separated.
Every normalized alert must be traceable to raw evidence.
Wazuh is an adapter, not the whole product.
