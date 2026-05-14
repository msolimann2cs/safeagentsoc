# MITRE Mapping Table

## Purpose

This file maps Phase 2 scenarios to MITRE ATT&CK where appropriate.

## Mapping Rule

Do not force MITRE mappings onto purely benign scenarios. Use N/A, benign mimic, or false-positive candidate when the scenario is not adversarial.

## Initial Mapping

| Scenario ID | Scenario | Platform | Type | MITRE Tactic | MITRE Technique ID | Technique Name | Confidence | Notes |
|---|---|---|---|---|---|---|---|---|
| S01 | PowerShell execution | Windows | attack_like | Execution | T1059.001 | PowerShell | High | Benign commands used to simulate suspicious execution telemetry |
| S02 | Windows discovery sequence | Windows | attack_like | Discovery | T1082 / T1033 / T1016 | System/User/Network Discovery | High | Discovery commands only |
| S03 | Scheduled task marker | Windows | attack_like | Persistence / Execution | T1053.005 | Scheduled Task | Medium | Harmless marker task, removed after run |
| S04 | Archive/staging behavior | Windows | attack_like | Collection | T1560.001 | Archive via Utility | Medium | Test files only |
| S05 | Windows normal admin maintenance | Windows | benign | N/A | N/A | N/A | High | Benign admin activity |
| S06 | Windows repeated benign noise | Windows | noise | N/A | N/A | N/A | High | Noise and duplicate suppression candidate |
| S07 | SSH failed login pattern | Linux | attack_like | Credential Access | T1110.001 | Password Guessing | Medium | Fake user failed login only |
| S08 | Sudo auth pattern | Linux | attack_like | Privilege Escalation | T1548.003 | Sudo and Sudo Caching | Medium | Safe sudo authentication events |
| S09 | Linux discovery sequence | Linux | attack_like | Discovery | T1082 / T1033 / T1016 | System/User/Network Discovery | High | Discovery commands only |
| S10 | Cron marker | Linux | attack_like | Persistence / Execution | T1053.003 | Cron | Medium | Harmless marker cron, removed after run |
| S11 | Linux normal admin maintenance | Linux | benign | N/A | N/A | N/A | High | Benign admin activity |
| S12 | Repeated typo/noisy authentication | Cross-endpoint | ambiguous/noise | N/A | N/A | N/A | Medium | False-positive-like authentication noise |

