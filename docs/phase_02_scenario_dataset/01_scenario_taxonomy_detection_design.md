# Scenario Taxonomy and Detection Design

## Purpose

Define the scenario categories, execution layers, label values, event roles, confidence values, detection expectations, and quality gate for Phase 2.

## Execution Layers

| Layer | Name | Execution Mode | Purpose |
|---|---|---|---|
| L0 | Benign baseline | manual | Normal user/admin activity |
| L1 | Noise and false-positive-like activity | manual | Alert fatigue and duplicate suppression evaluation |
| L2 | Manual adversary emulation | manual | Explainable ATT&CK-aligned behavior |
| L3 | Atomic Red Team validation | atomic_red_team | Standardized single-technique ATT&CK validation |
| L4 | MITRE Caldera campaign emulation | caldera | Multi-step adversary-emulation operations |
| L5 | Simulated-only high-risk gaps | simulated_only | Unsafe behaviors documented but not executed |

## Label Values

| Label | Meaning |
|---|---|
| benign | Known normal activity |
| noise | Repeated low-value benign telemetry |
| attack_like | Controlled adversary-emulation behavior |
| ambiguous | Realistic uncertainty |
| false_positive_candidate | Looks suspicious but ground truth is benign |
| simulated_only | High-risk concept documented but not executed |

## Event Roles

| Role | Meaning |
|---|---|
| trigger | Main event representing the scenario |
| supporting | Related context event |
| duplicate | Repeated similar event |
| noise | Low-value event |
| unrelated | Not part of the scenario |

## Simulation Types

| Type | Meaning |
|---|---|
| benign_baseline | Normal admin/user behavior |
| benign_noise | Repeated low-value benign activity |
| manual_adversary_emulation | Manual ATT&CK-like behavior |
| atomic_validation | Atomic Red Team technique validation |
| caldera_campaign | MITRE Caldera operation |
| simulated_only | Not executed; documented only |

## Quality Gate

No scenario or campaign can run until it has:

- Scenario ID or campaign ID
- Run ID
- Host
- Execution mode
- Tool
- Start and end timestamp plan
- Expected local signal
- Expected Wazuh signal
- MITRE mapping or N/A justification
- Safety rating
- Cleanup steps
- Evidence filenames
- Run log row

