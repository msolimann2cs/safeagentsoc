# Lab Foundation Report

## 1. Objective

Establish the Month 2 SOC lab foundation for SafeAgentSOC.

## 2. Scope

Deploy a Wazuh server and prepare the lab environment for endpoint onboarding and evidence capture.

## 3. Summary

The lab foundation focused on host folder structure, virtual machine planning, Wazuh server deployment, and documentation discipline.

## 4. Wazuh Server Deployment

The Wazuh server was deployed on the VM `safesoc-wazuh-01` using the official Wazuh all-in-one installation assistant. This deployment installed the Wazuh server, Wazuh indexer, and Wazuh dashboard on a single host.

| Field | Value |
|---|---|
| VM Name | safesoc-wazuh-01 |
| Hostname | safesoc-wazuh-01 |
| IP Address | 10.10.10.10 |
| OS | Ubuntu 24.04 |
| CPU | 4 vCPU |
| RAM | 8 GB |
| Disk | 100 GB |
| Dashboard URL | https://10.10.10.10 |

Before installation, the VM was validated for static IP configuration, default gateway connectivity, internet connectivity, DNS resolution, and sufficient system resources.

The Wazuh dashboard was successfully accessed from the host PC using `https://10.10.10.10`. The generated credentials were stored locally outside GitHub. After installation, Wazuh package repository updates were disabled to avoid accidental upgrades that could break the lab environment.

### Evidence

| Evidence ID | Description |
|---|---|
| E-P1-003 | Wazuh server static IP configured |
| E-P1-004 | Wazuh installation completed |
| E-P1-005 | Wazuh dashboard reachable |
| E-P1-006 | Wazuh dashboard overview visible |
| E-P1-007 | Wazuh services running |

### Snapshot

A VMware snapshot named `wazuh-installed-working` was created after confirming that the dashboard was reachable and credentials were stored safely.

## 5. Windows Endpoint Onboarding

The Windows endpoint `safesoc-win-01` was configured as the first monitored endpoint in the SafeAgentSOC lab. The VM was assigned a static IP address of `10.10.10.21` on the VMware VMnet10 lab network, with the corrected VMware NAT gateway `10.10.10.2`.

The endpoint was validated for connectivity to the Wazuh server at `10.10.10.10`, including dashboard access and agent communication/enrollment ports. The Wazuh agent was installed and enrolled using the Wazuh dashboard deployment instructions. After installation, the Windows endpoint appeared as active in the Wazuh dashboard.

Sysmon was installed on the endpoint to provide detailed Windows telemetry, including process creation events. The Wazuh agent configuration was updated to collect the `Microsoft-Windows-Sysmon/Operational` event channel. Safe test events were generated using benign commands such as launching Notepad, opening Calculator, and running basic PowerShell commands.

### Windows Endpoint Configuration

| Field | Value |
|---|---|
| VM Name | safesoc-win-01 |
| IP Address | 10.10.10.21 |
| Gateway | 10.10.10.2 |
| Wazuh Manager | 10.10.10.10 |
| Wazuh Agent Service | WazuhSvc |
| Sysmon Service | Sysmon64 |
| Sysmon Channel | Microsoft-Windows-Sysmon/Operational |

### Evidence

| Evidence ID | Description |
|---|---|
| E-P1-010 | Windows static IP configured |
| E-P1-011 | Windows endpoint can reach Wazuh |
| E-P1-012 | Wazuh agent installed and running |
| E-P1-013 | Windows endpoint active in Wazuh |
| E-P1-014 | Sysmon installed |
| E-P1-015 | Sysmon local process event generated |
| E-P1-016 | Wazuh received Windows process/Sysmon event |
| E-P1-017 | Wazuh received Windows login/security event |

### Snapshot

A VMware snapshot named `win-agent-sysmon-working` was created after confirming that the Windows endpoint was active in Wazuh and Sysmon was installed.
