# Phase 1 VM Inventory

## Purpose

This file tracks every virtual machine used in the SafeAgentSOC lab foundation.

## Host Resource Plan

The Wazuh server is allocated the most resources because it runs the Wazuh manager, indexer, and dashboard. Endpoint VMs are allocated fewer resources because they mainly generate logs and send telemetry.

## VM Inventory

| VM Name | Role | OS | IP Address | CPU | RAM | Disk | Status |
|---|---|---|---:|---:|---:|---:|---|
| safesoc-wazuh-01 | Wazuh SIEM/XDR server | Ubuntu Server 24.04 LTS | 10.10.10.10 | 4 vCPU | 8 GB | 100 GB | Planned |
| safesoc-win-01 | Windows endpoint | Windows 10/11 | 10.10.10.21 | 2 vCPU | 4 GB | 60 GB | Planned |
| safesoc-lnx-01 | Linux endpoint | Ubuntu Server 24.04 LTS | 10.10.10.31 | 2 vCPU | 2 GB | 30 GB | Planned |
| safesoc-sim-01 | Simulation VM | Kali Linux or Ubuntu later | 10.10.10.41 | 2 vCPU | 4 GB | 40 GB | Optional later |

## VM Storage Location

VM files are stored outside GitHub:

```text
C:\D-Drive\Seneca\Co op\SafeAgentSOC\SafeAgentSOC-VMs
Naming Rules
All lab machines start with safesoc.
Server names use the role and number.
Endpoint names use the OS or function.
Do not use generic names like ubuntu, windows, test, or vm1.
IP Address Rules
Wazuh/SIEM services use .10 range.
Windows endpoints use .20 range.
Linux endpoints use .30 range.
Simulation or testing machines use .40 range.
Optional server/domain-controller machines use .50 range.
Runtime Plan

If the host has limited RAM, the lab can be operated in pairs:

Mode	VMs Running	Purpose
Windows testing	safesoc-wazuh-01 + safesoc-win-01	Validate Windows and Sysmon telemetry
Linux testing	safesoc-wazuh-01 + safesoc-lnx-01	Validate Linux auth, SSH, and sudo telemetry
Full lab	safesoc-wazuh-01 + safesoc-win-01 + safesoc-lnx-01	Validate multi-endpoint ingestion
Snapshot Plan
VM Name	Snapshot Name	When
safesoc-wazuh-01	clean-ubuntu-before-wazuh	Before Wazuh installation
safesoc-wazuh-01	wazuh-installed-working	After Wazuh dashboard works
safesoc-win-01	clean-windows-before-agent	Before Wazuh agent installation
safesoc-win-01	win-agent-sysmon-working	After Wazuh agent and Sysmon work
safesoc-lnx-01	clean-ubuntu-before-agent	Before Wazuh agent installation
safesoc-lnx-01	linux-agent-working	After Linux logs appear in Wazuh