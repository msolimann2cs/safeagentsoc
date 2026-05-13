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

## 5. Success Criteria

| Criterion | Status |
|---|---|
| Wazuh dashboard reachable | Complete |

## 6. Next Steps

Proceed to endpoint onboarding and lab evidence capture.

