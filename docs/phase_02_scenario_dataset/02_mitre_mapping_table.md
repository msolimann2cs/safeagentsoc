# Phase 2 MITRE Mapping Table

## Purpose

This table maps Phase 2 scenarios to MITRE ATT&CK Enterprise techniques where appropriate.

The mapping is intentionally conservative. Attack-like scenarios receive MITRE technique mappings. Benign, noisy, and false-positive candidate scenarios use N/A unless there is a clear reason to document them as benign mimics.

## Mapping Rules

1. Do not force MITRE mappings onto purely benign scenarios.
2. Use mapping confidence: high, medium, or low.
3. Use N/A when the scenario is non-adversarial.
4. Use "benign mimic" when a benign scenario resembles a technique but ground truth is not adversarial.
5. Every mapped technique must have an expected observable signal.
6. Every scenario must preserve the difference between telemetry resemblance and confirmed malicious intent.

## Scenario-to-MITRE Mapping

| Scenario ID | Scenario | Platform | Type | Tactic | Technique ID | Technique Name | Confidence | Observable Signal | Notes |
|---|---|---|---|---|---|---|---|---|---|
| S01 | Windows PowerShell execution | Windows | attack_like | Execution | T1059.001 | PowerShell | High | PowerShell process/Sysmon event | Benign commands simulate script execution telemetry |
| S02 | Windows discovery sequence | Windows | attack_like | Discovery | T1082 | System Information Discovery | High | systeminfo/host details | Read-only discovery |
| S02 | Windows discovery sequence | Windows | attack_like | Discovery | T1033 | System Owner/User Discovery | High | whoami/user commands | Read-only discovery |
| S02 | Windows discovery sequence | Windows | attack_like | Discovery | T1016 | System Network Configuration Discovery | High | ipconfig/network config | Read-only discovery |
| S03 | Windows scheduled task marker | Windows | attack_like | Persistence / Execution | T1053.005 | Scheduled Task | Medium | schtasks process/task creation | Harmless marker task, removed after run |
| S04 | Windows archive and staging behavior | Windows | attack_like | Collection | T1560.001 | Archive via Utility | Medium | archive file creation | Test files only no exfiltration |
| S05 | Windows normal admin maintenance | Windows | benign | N/A | N/A | N/A | High | admin command telemetry | Benign, not adversarial |
| S06 | Windows repeated benign noise | Windows | noise | N/A | N/A | N/A | High | repeated benign process telemetry | Used for duplicate suppression evaluation |
| S07 | Linux SSH failed login pattern | Linux | attack_like | Credential Access | T1110.001 | Password Guessing | Medium | failed SSH login | One or two controlled failed attempts only |
| S08 | Linux sudo authentication pattern | Linux | attack_like | Privilege Escalation | T1548.003 | Sudo and Sudo Caching | Medium | sudo/PAM logs | Authentication behavior, not exploitation |
| S09 | Linux discovery sequence | Linux | attack_like | Discovery | T1082 | System Information Discovery | High | uname/host/system details | Read-only discovery |
| S09 | Linux discovery sequence | Linux | attack_like | Discovery | T1033 | System Owner/User Discovery | High | whoami/id | Read-only discovery |
| S09 | Linux discovery sequence | Linux | attack_like | Discovery | T1016 | System Network Configuration Discovery | High | ip a/network details | Read-only discovery |
| S10 | Linux cron marker | Linux | attack_like | Persistence / Execution | T1053.003 | Cron | Medium | crontab/cron logs | Harmless marker cron, removed after run |
| S11 | Linux normal admin maintenance | Linux | benign | N/A | N/A | N/A | High | admin maintenance telemetry | Benign, not adversarial |
| S12 | Repeated typo/noisy authentication | Cross-endpoint | ambiguous/noise | N/A | N/A | N/A | Medium | failed auth then success | False-positive-like noise, not automatically brute force |

## Technique Coverage Summary

| Technique ID | Technique Name | Scenario Coverage |
|---|---|---|
| T1059.001 | PowerShell | S01 |
| T1082 | System Information Discovery | S02, S09 |
| T1033 | System Owner/User Discovery | S02, S09 |
| T1016 | System Network Configuration Discovery | S02, S09 |
| T1053.005 | Scheduled Task | S03 |
| T1560.001 | Archive via Utility | S04 |
| T1110.001 | Password Guessing | S07 |
| T1548.003 | Sudo and Sudo Caching | S08 |
| T1053.003 | Cron | S10 |

## Platform Coverage

| Platform | Attack-like Scenarios | Benign/Noise/Ambiguous Scenarios |
|---|---|---|
| Windows | S01, S02, S03, S04 | S05, S06 |
| Linux | S07, S08, S09, S10 | S11 |
| Cross-endpoint | N/A | S12 |

## Research Notes

This mapping is designed for controlled dataset generation, not for claiming real compromise. A MITRE mapping means the scenario intentionally resembles the observable behavior of a technique. It does not mean the endpoint was actually compromised.

Benign and noisy scenarios are intentionally included because future SafeAgentSOC phases must evaluate false-positive handling, alert compression, duplicate suppression, and analyst-safe reasoning.

