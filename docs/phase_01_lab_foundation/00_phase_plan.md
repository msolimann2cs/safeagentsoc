# Phase 1 Plan: Lab Foundation

## Objective

Build the SafeAgentSOC lab foundation by deploying Wazuh, onboarding Windows and Linux endpoints, enabling endpoint telemetry, and proving log ingestion.

## Scope

In scope:
- Wazuh server deployment
- Windows endpoint deployment
- Sysmon installation
- Wazuh agent installation on Windows
- Linux endpoint deployment
- Wazuh agent installation on Linux
- Basic network diagram
- VM inventory
- Log ingestion proof
- Deployment documentation
- Evidence screenshots
- Lab foundation report

Out of scope:
- Alert normalization engine
- FastAPI backend
- PostgreSQL database
- Alert clustering
- MITRE mapping engine
- LLM hypothesis engine
- Attack graph validation
- Risk scoring
- GRC policy engine
- Dashboard
- Atomic Red Team dataset generation

## Sprint Breakdown

| Sprint | Focus | Output |
|---|---|---|
| Sprint 0 | Workspace and documentation setup | Clean repo, folders, templates, evidence system |
| Sprint 1 | Lab architecture and network design | VM inventory and network diagram |
| Sprint 2 | Wazuh server deployment | Wazuh dashboard reachable |
| Sprint 3 | Windows endpoint deployment | Windows agent and Sysmon proof |
| Sprint 4 | Linux endpoint deployment | Linux agent and auth log proof |
| Sprint 5 | Log ingestion proof | Windows/Linux events visible in Wazuh |
| Sprint 6 | Lab foundation report and cleanup | Final report and GitHub cleanup |

## Success Criteria

- Wazuh dashboard is reachable from the host PC.
- Windows endpoint appears as active in Wazuh.
- Linux endpoint appears as active in Wazuh.
- Sysmon is installed on the Windows endpoint.
- At least one Windows login/process/Sysmon event is visible in Wazuh.
- At least one Linux auth/SSH/sudo event is visible in Wazuh.
- Evidence screenshots are saved.
- VM inventory is complete.
- Network diagram is complete.
- Lab foundation report is complete.

## Final Success Sentence

I completed the SafeAgentSOC lab foundation by deploying a Wazuh-based SIEM/XDR environment, onboarding Windows and Linux endpoints, configuring endpoint telemetry, and proving that login, process, Sysmon, SSH, and sudo events are ingested into the SIEM. The phase includes a network diagram, VM inventory, deployment documentation, troubleshooting log, evidence screenshots, and a lab foundation report.
