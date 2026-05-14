# Phase 2 Execution Runbook

## Purpose

This runbook defines how every scenario must be executed, documented, and captured.

## Golden Rule

Do not run a scenario unless it has:

- Scenario ID
- Run ID
- Start timestamp
- Host
- Commands
- Expected Wazuh signal
- Cleanup steps
- Evidence filenames
- Safety rating

## Run ID Format

Use:

```text
SXX-RYYY
```

Examples:

```text
S01-R001
S01-R002
S07-R001
```

## Standard Execution Process

1. Confirm the relevant VM is running.
2. Confirm Wazuh dashboard is reachable.
3. Set Wazuh time range to Last 15 minutes or Last 1 hour.
4. Add a new row to `scenario_run_log.csv` before commands.
5. Record start timestamp.
6. Take pre-run screenshot.
7. Execute only the commands for that one scenario.
8. Take command execution screenshot.
9. Verify local logs if applicable.
10. Wait 60 to 180 seconds for Wazuh ingestion.
11. Search Wazuh using scenario query.
12. Open event details.
13. Screenshot Wazuh result and event details.
14. Record end timestamp.
15. Record alert count.
16. Run cleanup commands.
17. Record cleanup status.

## Screenshot Naming Pattern

```text
YYYY-MM-DD_SXX_RYYY_description.png
```

Examples:

- `2026-05-13_S01_R001_commands_executed.png`
- `2026-05-13_S01_R001_wazuh_results.png`
- `2026-05-13_S01_R001_wazuh_event_details.png`

## Wazuh Query Examples

Windows endpoint:

```text
agent.name: "safesoc-win-01"
```

Windows Sysmon:

```text
agent.name: "safesoc-win-01" and data.win.system.providerName: "Microsoft-Windows-Sysmon"
```

Linux endpoint:

```text
agent.name: "safesoc-lnx-01"
```

Linux SSH:

```text
agent.name: "safesoc-lnx-01" and ssh
```

Linux sudo:

```text
agent.name: "safesoc-lnx-01" and sudo
```

## Evidence Storage

Screenshots are stored locally outside GitHub:

```text
C:\D-Drive\Seneca\Co op\SafeAgentSOC\07_evidence\phase_02_scenario_dataset\screenshots
```

Raw and exported datasets are stored locally outside GitHub:

```text
C:\D-Drive\Seneca\Co op\SafeAgentSOC\06_data\phase_02_scenario_dataset
```

