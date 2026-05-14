# Phase 2 Scenario Coverage Matrix

## Purpose

This matrix evaluates whether the Phase 2 catalog is balanced enough for research-grade dataset creation.

## Coverage by Scenario Type

| Type | Scenarios | Count | Purpose |
|---|---|---:|---|
| Windows attack-like | S01, S02, S03, S04 | 4 | Windows Sysmon, PowerShell, discovery, scheduled task, archive telemetry |
| Linux attack-like | S07, S08, S09, S10 | 4 | SSH, sudo, discovery, cron telemetry |
| Benign | S05, S11 | 2 | Known-benign baseline activity |
| Noise | S06 | 1 | Duplicate/noise generation |
| Ambiguous/noise | S12 | 1 | False-positive-like authentication ambiguity |

## Coverage by Platform

| Platform | Scenarios | Count |
|---|---|---:|
| Windows | S01, S02, S03, S04, S05, S06 | 6 |
| Linux | S07, S08, S09, S10, S11 | 5 |
| Cross-endpoint | S12 | 1 |

## MITRE Coverage

| Tactic | Technique | Scenario |
|---|---|---|
| Execution | T1059.001 PowerShell | S01 |
| Discovery | T1082 System Information Discovery | S02, S09 |
| Discovery | T1033 System Owner/User Discovery | S02, S09 |
| Discovery | T1016 System Network Configuration Discovery | S02, S09 |
| Persistence / Execution | T1053.005 Scheduled Task | S03 |
| Collection | T1560.001 Archive via Utility | S04 |
| Credential Access | T1110.001 Password Guessing | S07 |
| Privilege Escalation | T1548.003 Sudo and Sudo Caching | S08 |
| Persistence / Execution | T1053.003 Cron | S10 |

## Dataset Balance Assessment

| Requirement | Status | Notes |
|---|---|---|
| At least 8 scenarios | Passed | 12 scenarios defined |
| Windows represented | Passed | 6 scenarios |
| Linux represented | Passed | 5 scenarios |
| Benign data included | Passed | S05, S11 |
| Noise data included | Passed | S06, S12 |
| Ambiguous data included | Passed | S12 |
| At least 6 MITRE techniques | Passed | 9 technique mappings |
| High-risk behavior avoided | Passed | No malware, no credential dumping, no destructive tests |

## Research Rationale

This catalog is designed for later evaluation, not only detection triggering. It includes attack-like, benign, noisy, and ambiguous scenarios so SafeAgentSOC can later be evaluated on alert compression, duplicate suppression, case-building quality, MITRE mapping accuracy, hypothesis correctness, and policy-safe response reasoning.

