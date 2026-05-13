# Wazuh Server Deployment

## Objective

Deploy the central Wazuh SIEM/XDR server for the SafeAgentSOC lab.

## VM Details

| Field | Value |
|---|---|
| VM Name | safesoc-wazuh-01 |
| Hostname | safesoc-wazuh-01 |
| Role | Wazuh server, indexer, dashboard |
| OS | Ubuntu 24.04 |
| CPU | 4 vCPU |
| RAM | 8 GB |
| Disk | 100 GB |
| IP Address | 10.10.10.10 |
| Network Mode | VMware VMnet10 NAT |
| Install Date | 2026-05-13 |

## Pre-Install Validation

| Check | Result |
|---|---|
| Static IP configured | Passed |
| Default route configured | Passed |
| Internet connectivity | Passed |
| DNS resolution | Passed |
| Hostname set | Passed |
| VM snapshot before install | Completed |

## Installation Method

Official Wazuh all-in-one quickstart installation assistant.

## Commands Used

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y curl vim net-tools gnupg apt-transport-https lsb-release ca-certificates
cd ~
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

## Dashboard Access

| Field | Value |
|---|---|
| Dashboard URL | https://10.10.10.10 |
| Username | admin |
| Password Storage | Stored locally outside GitHub |

## Service Validation

```bash
sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager
sudo systemctl status wazuh-dashboard --no-pager
sudo ss -tulpn | grep -E '443|1514|1515|55000|9200'
```

## Post-Install Hardening

Wazuh repository updates were disabled after installation to avoid accidental breaking upgrades.

```bash
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

## Evidence

| Evidence ID | Screenshot | What it proves |
|---|---|---|
| E-P1-003 | 2026-05-13_wazuh01_static-ip.png | Static IP and route configured |
| E-P1-004 | 2026-05-13_wazuh01_connectivity.png | Internet and DNS connectivity working |
| E-P1-005 | 2026-05-13_wazuh_services-running.png | Core Wazuh services active |
| E-P1-006 | 2026-05-13_wazuh_ports-listening.png | Wazuh ports listening |
| E-P1-007 | 2026-05-13_wazuh_dashboard_login.png | Dashboard reachable from host PC |
| E-P1-008 | 2026-05-13_wazuh_dashboard_overview.png | Dashboard login successful |

## Snapshots

| Snapshot | Description |
|---|---|
| clean-ubuntu-before-wazuh | Ubuntu installed and static IP configured before Wazuh installation |
| wazuh-installed-working | Wazuh installed and dashboard accessible |

## Issues Faced

| Issue | Cause | Fix | Status |
|---|---|---|---|
| TBD | TBD | TBD | TBD |

## Status

Complete

