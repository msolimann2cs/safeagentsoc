# Scenario Catalog

## Purpose

This file will define all Phase 2 scenarios before execution. No scenario should be executed until it has an objective, host, commands, expected Wazuh signal, MITRE mapping where appropriate, safety rating, cleanup plan, and evidence filenames.

## Scenario Status Table

| Scenario ID | Name | Type | Platform | MITRE Mapping | Safety | Status |
|---|---|---|---|---|---|---|
| S01 | PowerShell execution | attack_like | Windows | T1059.001 | Low | Draft |
| S02 | Windows discovery sequence | attack_like | Windows | T1082, T1033, T1016 | Low | Draft |
| S03 | Scheduled task marker | attack_like | Windows | T1053.005 | Medium | Draft |
| S04 | Archive/staging behavior | attack_like | Windows | T1560.001 | Low | Draft |
| S05 | Windows normal admin maintenance | benign | Windows | N/A | Low | Draft |
| S06 | Windows repeated benign noise | noise | Windows | N/A | Low | Draft |
| S07 | SSH failed login pattern | attack_like | Linux | T1110.001 | Low | Draft |
| S08 | Sudo auth pattern | attack_like | Linux | T1548.003 | Low | Draft |
| S09 | Linux discovery sequence | attack_like | Linux | T1082, T1033, T1016 | Low | Draft |
| S10 | Cron marker | attack_like | Linux | T1053.003 | Medium | Draft |
| S11 | Linux normal admin maintenance | benign | Linux | N/A | Low | Draft |
| S12 | Repeated typo/noisy authentication | ambiguous/noise | Cross-endpoint | N/A | Low | Draft |

## Scenario Template

### SXX: Scenario Name

| Field | Value |
|---|---|
| Scenario ID | SXX |
| Type | attack_like / benign / noise / ambiguous |
| Platform | Windows / Linux / Cross-endpoint |
| Host | TBD |
| MITRE Tactic | TBD or N/A |
| MITRE Technique | TBD or N/A |
| Safety Rating | Low / Medium / High |
| Expected Wazuh Signal | TBD |
| Cleanup Required | Yes / No |

#### Objective

TBD

#### Commands

```text
TBD
```

#### Expected Wazuh Query

```text
agent.name: "TBD" and TBD
```

#### Evidence Files

- `YYYY-MM-DD_SXX_pre-run_state.png`
- `YYYY-MM-DD_SXX_commands_executed.png`
- `YYYY-MM-DD_SXX_local_log_proof.png`
- `YYYY-MM-DD_SXX_wazuh_results.png`
- `YYYY-MM-DD_SXX_wazuh_event_details.png`

#### Cleanup

TBD

