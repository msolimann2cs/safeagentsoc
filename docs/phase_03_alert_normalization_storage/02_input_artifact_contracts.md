# Phase 3 Input Artifact Contracts

## Purpose

This document defines the expected Phase 2 artifacts that Phase 3 will consume.

## Required Inputs From Phase 2

| Artifact | Purpose | Private? | Used By |
|---|---|---:|---|
| raw_alerts_full.jsonl | Raw Wazuh alerts | Yes | Runtime ingestion |
| ground_truth_labels.csv | Benchmark labels | Yes | Evaluation only |
| casebook.csv | Gold case data | Yes | Evaluation only |
| alert_fatigue_baseline.csv | Baseline comparison | Yes | Evaluation only |
| dataset_qa_report.md | Dataset quality summary | Maybe | Documentation/evaluation |
| phase_03_normalization_requirements.md | Requirements for normalization | Maybe | Design |
| scenario_run_log_frozen.csv | Scenario run metadata | Yes | Evaluation only |
| detection_gap_register.csv | Known detection gaps | Yes | Evaluation only, optional |

## Runtime-Allowed Input

Only raw alerts and non-answer-key metadata may enter the runtime pipeline.

## Evaluation-Only Input

Labels, casebook answers, scenario conclusions, and detection gaps must not be used by the runtime pipeline.

## Required Manifest Fields

Each artifact must be tracked with:

- filename
- source path
- destination path
- public/private status
- runtime/evaluation classification
- expected row or line count
- hash, added in Sprint 2
- notes

## Sprint 0 Acceptance

Before Sprint 1 starts, every known Phase 2 artifact must be listed in the manifest.
