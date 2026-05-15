# SafeAgentSOC Phase 2 Public Summary

## Overview

Phase 2 created a controlled SOC dataset for SafeAgentSOC using benign baselines, noisy activity, manual adversary emulation, Atomic Red Team validation, MITRE Caldera campaign operations, and simulated-only high-risk gap documentation.

## Final Results

| Metric | Value |
|---|---:|
| Raw Wazuh alerts | 6,893 |
| Gold-label alerts | 800 |
| Investigation cases | 50 |
| Campaigns | 2 |
| Base scenarios | 12 |
| Average duplicate ratio | 0.2601 |
| Average compression potential | 0.4377 |

## Why This Matters

The dataset provides a benchmark for testing whether SafeAgentSOC can reduce alert fatigue while preserving important evidence. It supports future evaluation of alert grouping, duplicate suppression, case summarization, and analyst-facing triage conclusions.

## Publication Note

Raw alerts and full labels are kept private. Public artifacts include methodology, schemas, QA summaries, sanitized samples, and high-level metrics.
