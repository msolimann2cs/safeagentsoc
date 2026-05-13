# Phase 1 Evidence Log

## Purpose

This file tracks every screenshot, command output, config file, and proof artifact collected during the lab foundation phase.

## Screenshot Naming Convention

Use:

```text
YYYY-MM-DD_component_short-description.png
Examples:

2026-05-12_wazuh01_static-ip.png
2026-05-12_wazuh_dashboard_login.png
2026-05-12_win01_agent-active.png
2026-05-12_lnx01_sudo-event.png
Evidence Table
DateEvidence IDFileTypeWhat it provesRelated deliverable
2026-05-12E-P1-0012026-05-12_phase1_network_diagram.pngScreenshotLab topology and IP plan documentedNetwork diagram
2026-05-12E-P1-002phase_01_lab_network.drawioDiagramEditable lab network diagram createdNetwork diagram
TBDE-P1-003TBDScreenshotWazuh server static IP configuredVM inventory
TBDE-P1-004TBDScreenshotWazuh dashboard reachableWorking Wazuh lab
TBDE-P1-005TBDScreenshotWazuh overview visibleWorking Wazuh lab
TBDE-P1-010TBDScreenshotWindows endpoint activeEndpoint onboarding
TBDE-P1-011TBDScreenshotSysmon installedWindows telemetry
TBDE-P1-012TBDScreenshotWindows event visible in WazuhLog ingestion proof
TBDE-P1-020TBDScreenshotLinux endpoint activeEndpoint onboarding
TBDE-P1-021TBDScreenshotLinux SSH/auth event visible in WazuhLog ingestion proof
TBDE-P1-022TBDScreenshotLinux sudo event visible in WazuhLog ingestion proof
Local Evidence Folder

Local evidence is stored outside GitHub here:

C:\D-Drive\Seneca\Co op\SafeAgentSOC\07_evidence\phase_01_lab_foundation
GitHub Evidence Rule

Only commit sanitized screenshots if needed. Do not commit credentials, secrets, raw huge logs, or sensitive VM exports.
