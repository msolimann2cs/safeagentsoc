# Phase 2 Scenario Catalog

## Purpose

Define the base scenarios used for benign baseline, noise generation, manual adversary emulation, Atomic Red Team validation, and Caldera campaign emulation.

## Base Scenarios

| ID | Type | Platform | Scenario | MITRE | Execution Modes |
|---|---|---|---|---|---|
| S01 | attack_like | Windows | PowerShell execution | T1059.001 | manual, atomic_red_team, caldera |
| S02 | attack_like | Windows | Discovery sequence | T1082, T1033, T1016 | manual, atomic_red_team, caldera |
| S03 | attack_like | Windows | Scheduled task marker | T1053.005 | manual, atomic_red_team, caldera |
| S04 | attack_like | Windows | Archive/staging behavior | T1560.001 | manual, atomic_red_team, caldera |
| S05 | benign | Windows | Normal admin maintenance | N/A | manual |
| S06 | noise | Windows | Repeated benign process noise | N/A | manual |
| S07 | attack_like | Linux | SSH failed login pattern | T1110.001 | manual, atomic_red_team, caldera |
| S08 | attack_like | Linux | Sudo authentication pattern | T1548.003 | manual, atomic_red_team, caldera |
| S09 | attack_like | Linux | Linux discovery sequence | T1082, T1033, T1016 | manual, atomic_red_team, caldera |
| S10 | attack_like | Linux | Cron marker | T1053.003 | manual, atomic_red_team, caldera |
| S11 | benign | Linux | Normal admin maintenance | N/A | manual |
| S12 | ambiguous/noise | Cross-endpoint | Repeated typo/noisy authentication | N/A | manual |

## Scenario Detail Template

Each scenario must include:

- Objective
- Analyst hypothesis
- Wrong inference warning
- MITRE justification or N/A justification
- Expected local signal
- Expected Wazuh signal
- Expected DQL query
- Cleanup
- Evidence filenames

