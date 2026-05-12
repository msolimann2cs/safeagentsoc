# Phase 1 VM Inventory

## Purpose

This file tracks every virtual machine used in the SafeAgentSOC lab foundation.

## VM Inventory

| VM Name | Role | OS | IP Address | CPU | RAM | Disk | Status |
|---|---|---|---:|---:|---:|---:|---|
| safesoc-wazuh-01 | Wazuh SIEM/XDR server | Ubuntu Server | 10.10.10.10 | 4 | 8 GB | 80 to 100 GB | Planned |
| safesoc-win-01 | Windows endpoint | Windows 10/11 | 10.10.10.21 | 2 | 4 GB | 60 GB | Planned |
| safesoc-lnx-01 | Linux endpoint | Ubuntu Server | 10.10.10.31 | 2 | 2 GB | 30 GB | Planned |
| safesoc-sim-01 | Simulation VM | TBD | 10.10.10.41 | 2 | 4 GB | 40 GB | Optional later |

## Naming Rules

- All lab machines start with safesoc.
- Server names use purpose and number.
- Endpoint names use OS or role.
- Do not use generic names like ubuntu, test, windows, or vm1.

## Snapshot Plan

| VM Name | Snapshot Name | When |
|---|---|---|
| safesoc-wazuh-01 | clean-ubuntu-before-wazuh | Before Wazuh install |
| safesoc-wazuh-01 | wazuh-installed-working | After Wazuh dashboard works |
| safesoc-win-01 | clean-windows-before-agent | Before Wazuh agent |
| safesoc-win-01 | win-agent-sysmon-working | After Wazuh + Sysmon works |
| safesoc-lnx-01 | clean-ubuntu-before-agent | Before Wazuh agent |
| safesoc-lnx-01 | linux-agent-working | After Linux logs appear |
