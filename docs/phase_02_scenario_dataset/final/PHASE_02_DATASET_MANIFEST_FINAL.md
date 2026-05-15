# SafeAgentSOC Phase 2 Dataset Manifest

## Dataset Name

SafeAgentSOC Phase 2: Scenario Design and Dataset Creation

## Dataset Purpose

This dataset was created to support the design and future evaluation of SafeAgentSOC, an AI-assisted SOC triage system focused on alert reduction, evidence preservation, and analyst-facing case summarization.

## Methodology

Phase 2 used controlled adversary emulation instead of malware execution. The dataset combines:

| Layer | Description |
|---|---|
| L0 | Benign baseline activity |
| L1 | Noise and false-positive-like activity |
| L2 | Manual ATT&CK-aligned adversary emulation |
| L3 | Atomic Red Team validation |
| L4 | MITRE Caldera campaign emulation |
| L5 | Simulated-only high-risk gaps |

## Final Counts

| Metric | Value |
|---|---:|
| Base scenarios | 12 |
| Campaigns | 2 |
| Raw Wazuh alerts | 6,893 |
| Gold-label rows | 800 |
| Unique gold-label alert UIDs | 631 |
| Investigation cases | 50 |
| Total case alert references | 1,549 |
| Average duplicate ratio | 0.2601 |
| Average compression potential | 0.4377 |
| Estimated unlabeled raw pool | 6,174 |

## Endpoint Coverage

| Endpoint | Role |
|---|---|
| safesoc-win-01 | Windows endpoint with Wazuh agent and Sysmon |
| safesoc-lnx-01 | Linux endpoint with Wazuh agent |
| safesoc-wazuh-01 | Wazuh manager/indexer/dashboard |
| safesoc-caldera-01 | MITRE Caldera server |

## Execution Modes

| Execution Mode | Purpose |
|---|---|
| manual | Explainable command-level ground truth |
| atomic_red_team | Standardized ATT&CK technique validation |
| caldera | Campaign-level adversary emulation |
| background_sample | Unrelated/background telemetry sampling |
| simulated_only | High-risk behavior represented safely without destructive execution |

## Dataset Artifacts

| Artifact | Purpose |
|---|---|
| raw_alerts_full.jsonl | Full private raw Wazuh export |
| ground_truth_labels.csv | 800-row gold-label alert dataset |
| casebook.csv | 50 investigation cases |
| alert_fatigue_baseline.csv | Duplicate and compression metrics |
| dataset_qa_report.md | Label QA and coverage report |
| raw_background_pool_summary.md | Profile of remaining unlabeled raw alerts |
| phase_03_normalization_requirements.md | Handoff requirements for SafeAgentSOC pipeline |

## Privacy and Publication

The full raw dataset, full ground-truth labels, and detailed casebook are stored locally. Public GitHub commits should only contain sanitized samples, schemas, methodology reports, QA summaries, and high-level metrics.
