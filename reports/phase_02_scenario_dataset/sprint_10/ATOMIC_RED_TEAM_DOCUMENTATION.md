# Atomic Red Team Documentation

## Purpose

Atomic Red Team was used as the standardized ATT&CK validation layer for Phase 2. Atomic tests helped validate that selected techniques could generate Wazuh-visible telemetry and be compared against manual and Caldera runs.

## Execution Mode

```text
execution_mode = atomic_red_team
```

## Covered Techniques

| Scenario | Platform | Purpose | Example Technique |
|---|---|---|---|
| S01 | Windows | PowerShell execution | T1059.001 |
| S02 | Windows | Discovery validation | T1082, T1033, T1016 |
| S03 | Windows | Scheduled task validation | T1053.005 |
| S04 | Windows | Archive/staging behavior | T1560.001 |
| S09/S10 | Linux | Discovery and persistence-like validation | T1082, T1053.003, T1543.002 |

## Linux Atomic Note

Some Linux Atomic tests required elevation. For example, systemd service creation required `sudo pwsh` and an explicit `PathToAtomicsFolder` value.

## Safety Note

Atomic tests were reviewed before execution. Destructive, credential-exposing, or real exfiltration behaviors were either excluded or represented through simulated-only workflows.

## Evidence

Evidence includes Atomic command screenshots, `Invoke-AtomicTest -ShowDetailsBrief` outputs, Wazuh alert screenshots, and cleanup screenshots.
