# Phase 3 Handoff: SafeAgentSOC Normalization and Triage Pipeline

## Purpose

Phase 2 produced the dataset. Phase 3 should build the SafeAgentSOC pipeline that uses this dataset to evaluate alert reduction, case summarization, and triage correctness.

## Inputs from Phase 2

| Input | Purpose |
|---|---|
| raw_alerts_full.jsonl | Full raw Wazuh alert pool |
| ground_truth_labels.csv | Alert-level gold labels |
| casebook.csv | Case-level SOC benchmark |
| alert_fatigue_baseline.csv | Duplicate and compression metrics |
| phase_03_normalization_requirements.md | Design requirements |

## Phase 3 Pipeline Requirements

SafeAgentSOC should ingest raw alerts, normalize alert fields, group alerts into cases, identify trigger evidence, preserve supporting evidence, collapse duplicate alerts, separate unrelated/noisy telemetry, generate analyst-facing summaries, classify cases, and compare output against Sprint 8 and Sprint 9 ground truth.

## Evaluation Metrics

| Metric | Definition |
|---|---|
| alert_reduction_ratio | Reduced alert count / original alert count |
| duplicate_suppression_rate | Suppressed duplicate count / duplicate count |
| trigger_preservation_rate | Preserved trigger count / trigger count |
| case_classification_accuracy | Correct case label / total cases |
| analyst_expected_conclusion_match | Whether generated conclusion matches casebook |
| summary_completeness | Whether summary includes host, time, technique, evidence, and conclusion |

## Safety Requirement

SafeAgentSOC must reduce alert fatigue without hiding primary trigger evidence.
