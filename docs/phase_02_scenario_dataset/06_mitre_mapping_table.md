# MITRE Mapping Table

| Scenario/Campaign | Platform | Type | Tactic | Technique ID | Technique Name | Confidence | Notes |
|---|---|---|---|---|---|---|---|
| S01 | Windows | attack_like | Execution | T1059.001 | PowerShell | High | Manual, Atomic, and Caldera-supported |
| S02 | Windows | attack_like | Discovery | T1082 | System Information Discovery | High | Discovery sequence |
| S02 | Windows | attack_like | Discovery | T1033 | System Owner/User Discovery | High | User discovery |
| S02 | Windows | attack_like | Discovery | T1016 | System Network Configuration Discovery | High | Network discovery |
| S03 | Windows | attack_like | Persistence / Execution | T1053.005 | Scheduled Task | Medium | Harmless marker only |
| S04 | Windows | attack_like | Collection | T1560.001 | Archive via Utility | Medium | Synthetic files only |
| S07 | Linux | attack_like | Credential Access | T1110.001 | Password Guessing | Medium | Controlled failed auth only |
| S08 | Linux | attack_like | Privilege Escalation | T1548.003 | Sudo and Sudo Caching | Medium | sudo/PAM telemetry |
| S09 | Linux | attack_like | Discovery | T1082 | System Information Discovery | High | Linux discovery |
| S09 | Linux | attack_like | Discovery | T1033 | System Owner/User Discovery | High | User discovery |
| S09 | Linux | attack_like | Discovery | T1016 | System Network Configuration Discovery | High | Network discovery |
| S10 | Linux | attack_like | Persistence / Execution | T1053.003 | Cron | Medium | Harmless marker only |
| C-WIN-01 | Windows | campaign | Multiple | Multiple | Windows campaign chain | High | PowerShell discovery scheduled task archive |
| C-LNX-01 | Linux | campaign | Multiple | Multiple | Linux campaign chain | High | SSH sudo discovery cron |
| S05/S06/S11/S12 | Mixed | benign/noise | N/A | N/A | N/A | High | Not force-mapped |

