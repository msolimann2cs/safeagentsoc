# SafeAgentSOC Event Taxonomy v1

## Purpose

This document defines the first canonical event categories used by SafeAgentSOC.

## Categories

| Category | Meaning | Example |
|---|---|---|
| authentication | Login, logout, auth failures, sudo/PAM activity | failed SSH login |
| process_execution | Process start or suspicious command execution | PowerShell execution |
| privilege_activity | Admin, sudo, privilege use, escalation-like activity | sudo authentication |
| persistence | Scheduled task, cron, service marker | cron marker |
| discovery | System, user, network, process discovery | whoami, hostname |
| collection_or_staging | Archive, compression, staging files | zip archive creation |
| network_activity | Network connection or access event | unusual outbound connection |
| file_activity | File creation, deletion, modification | staged file created |
| system_activity | Service, configuration, system events | service change |
| monitoring_internal | Wazuh/internal monitoring noise | agent keepalive |
| background | Unrelated background telemetry | unrelated audit alert |
| unknown | Could not confidently classify | missing context |

## Outcome Values

| Outcome | Meaning |
|---|---|
| success | Activity completed successfully |
| failure | Activity failed |
| suspicious | Activity is suspicious or security-relevant |
| blocked | Activity was denied, blocked, or failed due to control |
| unknown | Outcome could not be determined |

## Notes

The taxonomy is intentionally small in Sprint 1.

Sprint 3 will profile real Wazuh fields.

Sprint 5 will implement mapping logic.
