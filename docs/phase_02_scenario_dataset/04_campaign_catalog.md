# Phase 2 Campaign Catalog

## Purpose

Define the campaign-level adversary-emulation runs used in Phase 2.

Campaigns are the main malicious-simulation layer. They combine multiple scenarios into a realistic sequence.

## C-WIN-01: Windows Foothold-to-Staging Emulation

| Field | Value |
|---|---|
| Campaign ID | C-WIN-01 |
| Target | safesoc-win-01 |
| Execution Modes | manual, atomic_red_team, caldera |
| Primary Tool | MITRE Caldera |
| Ground Truth | emulated_malicious |
| Safety | Medium |

### Chain

| Stage | Scenario | ATT&CK | Purpose |
|---|---|---|---|
| 1 | S01 | T1059.001 | PowerShell execution |
| 2 | S02 | T1082, T1033, T1016 | Host/user/network discovery |
| 3 | S03 | T1053.005 | Scheduled task marker |
| 4 | S04 | T1560.001 | Synthetic file archive/staging |

### Analyst Hypothesis

The Windows endpoint shows a chained suspicious sequence: PowerShell execution, discovery, persistence-like task creation, and file staging.

### Wrong Inference Warning

This does not prove real malware or real data theft. It is controlled adversary emulation inside the lab.

## C-LNX-01: Linux Access-to-Persistence Emulation

| Field | Value |
|---|---|
| Campaign ID | C-LNX-01 |
| Target | safesoc-lnx-01 |
| Execution Modes | manual, atomic_red_team, caldera |
| Primary Tool | MITRE Caldera |
| Ground Truth | emulated_malicious |
| Safety | Medium |

### Chain

| Stage | Scenario | ATT&CK | Purpose |
|---|---|---|---|
| 1 | S07 | T1110.001 | SSH failed login/access probing |
| 2 | S08 | T1548.003 | sudo/PAM authentication activity |
| 3 | S09 | T1082, T1033, T1016 | Linux discovery |
| 4 | S10 | T1053.003 | cron marker |

### Analyst Hypothesis

The Linux endpoint shows authentication probing, sudo activity, discovery, and persistence-like cron behavior.

### Wrong Inference Warning

This does not prove real malware, real credential compromise, or real persistence. It is controlled adversary emulation inside the lab.

